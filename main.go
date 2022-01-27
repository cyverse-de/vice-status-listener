package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"

	"github.com/cyverse-de/configurate"
	"github.com/cyverse-de/messaging"
	"github.com/cyverse-de/vice-status-listener/logging"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

var log = logging.Log.WithFields(logrus.Fields{"package": "main"})

// AnalysisStatusPublisher is the interface for types that need to publish a job
// update.
type AnalysisStatusPublisher interface {
	Fail(jobID, msg string) error
	Success(jobID, msg string) error
	Running(jobID, msg string) error
}

// JSLPublisher is a concrete implementation of AnalysisStatusPublisher that
// posts status updates to the job-status-listener service.
type JSLPublisher struct {
	statusURL string
}

// AnalysisStatus contains the data needed to post a status update to the
// notification-agent service.
type AnalysisStatus struct {
	Host    string
	State   messaging.JobState
	Message string
}

func (j *JSLPublisher) postStatus(jobID, msg string, jobState messaging.JobState) error {
	status := &AnalysisStatus{
		Host:    hostname(),
		State:   jobState,
		Message: msg,
	}

	u, err := url.Parse(j.statusURL)
	if err != nil {
		return errors.Wrapf(
			err,
			"error parsing URL %s for job %s before posting %s status",
			j,
			jobID,
			jobState,
		)
	}
	u.Path = path.Join(jobID, "status")

	js, err := json.Marshal(status)
	if err != nil {
		return errors.Wrapf(
			err,
			"error marshalling JSON for analysis %s before posting %s status",
			jobID,
			jobState,
		)

	}
	response, err := http.Post(u.String(), "application/json", bytes.NewReader(js))
	if err != nil {
		return errors.Wrapf(
			err,
			"error returned posting %s status for job %s to %s",
			jobState,
			jobID,
			u.String(),
		)
	}
	if response.StatusCode < 200 || response.StatusCode > 399 {
		return errors.Wrapf(
			err,
			"error status code %d returned after posting %s status for job %s to %s: %s",
			response.StatusCode,
			jobState,
			jobID,
			u.String(),
			response.Body,
		)
	}
	return nil
}

// Fail sends an analysis failure update with the provided message via the AMQP
// broker. Should be sent once.
func (j *JSLPublisher) Fail(jobID, msg string) error {
	log.Warnf("Sending failure job status update for external-id %s", jobID)

	return j.postStatus(jobID, msg, messaging.FailedState)
}

// Success sends a success update via the AMQP broker. Should be sent once.
func (j *JSLPublisher) Success(jobID, msg string) error {
	log.Warnf("Sending success job status update for external-id %s", jobID)

	return j.postStatus(jobID, msg, messaging.SucceededState)
}

// Running sends an analysis running status update with the provided message via the
// AMQP broker. May be sent multiple times, preferably with different messages.
func (j *JSLPublisher) Running(jobID, msg string) error {
	log.Warnf("Sending running job status update for external-id %s", jobID)
	return j.postStatus(jobID, msg, messaging.RunningState)
}

type Internal struct {
	ViceNamespace   string
	statusPublisher AnalysisStatusPublisher
	clientset       kubernetes.Interface
}

// MonitorVICEEvents fires up a goroutine that forwards events from the cluster
// to the status receiving service (probably job-status-listener). This function
// blocks and does not return.
func (i *Internal) MonitorVICEEvents() {
	for {
		log.Debug("beginning to monitor k8s events")
		set := labels.Set(map[string]string{
			"app-type": "interactive",
		})
		factory := informers.NewSharedInformerFactoryWithOptions(
			i.clientset,
			0,
			informers.WithNamespace(i.ViceNamespace),
			informers.WithTweakListOptions(func(listoptions *v1.ListOptions) {
				listoptions.LabelSelector = set.AsSelector().String()
			}),
		)

		deploymentInformer := factory.Apps().V1().Deployments().Informer()
		deploymentInformerStop := make(chan struct{})
		// no-op, defer doesn't work in infinite loop
		// defer close(deploymentInformerStop)

		deploymentInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				log.Debug("add a deployment")
				var err error

				depObj, ok := obj.(v1.Object)
				if !ok {
					log.Error(errors.New("unexpected type deployment object"))
					return
				}

				labels := depObj.GetLabels()

				jobID, ok := labels["external-id"]
				if !ok {
					log.Error(errors.New("deployment is missing external-id label"))
					return
				}

				log.Infof("processing deployment addition for job %s", jobID)

				analysisName, ok := labels["analysis-name"]
				if !ok {
					log.Error(errors.New("deployment is missing analysis-name label"))
					return
				}

				if err = i.statusPublisher.Running(
					jobID,
					fmt.Sprintf("deployment %s has started for analysis %s", depObj.GetName(), analysisName),
				); err != nil {
					log.Error(err)
				}
			},

			DeleteFunc: func(obj interface{}) {
				log.Debug("delete a deployment")
				var err error

				depObj, ok := obj.(v1.Object)
				if !ok {
					log.Error(errors.New("unexpected type deployment object"))
					return
				}

				labels := depObj.GetLabels()

				jobID, ok := labels["external-id"]
				if !ok {
					log.Error(errors.New("deployment is missing external-id label"))
					return
				}

				log.Infof("processing deployment deletion for job %s", jobID)

				analysisName, ok := labels["analysis-name"]
				if !ok {
					log.Error(errors.New("deployment is missing analysis-name label"))
					return
				}

				if err = i.statusPublisher.Success(
					jobID,
					fmt.Sprintf("deployment %s has been deleted for analysis %s", depObj.GetName(), analysisName),
				); err != nil {
					log.Error(err)
				}
			},

			UpdateFunc: func(oldObj, newObj interface{}) {
				log.Debug("update a deployment")
				var err error

				depObj, ok := newObj.(*appsv1.Deployment)
				if !ok {
					log.Error(errors.New("unexpected type deployment object"))
					return
				}

				jobID, ok := depObj.Labels["external-id"]
				if !ok {
					log.Error(errors.New("deployment is missing external-id label"))
					return
				}

				log.Infof("processing deployment change for job %s", jobID)

				if err = i.eventDeploymentModified(depObj, jobID); err != nil {
					log.Error(err)
				}
			},
		})

		deploymentInformer.Run(deploymentInformerStop)
	}
}

// eventDeploymentModified handles emitting job status updates when the pod for the
// VICE analysis generates a modified event from k8s.
func (i *Internal) eventDeploymentModified(deployment *appsv1.Deployment, jobID string) error {
	var err error

	analysisName := deployment.Labels["analysis-name"]

	if deployment.DeletionTimestamp != nil {
		// Pod was deleted at some point, don't do anything now.
		return nil
	}

	err = i.statusPublisher.Running(
		jobID,
		fmt.Sprintf(
			"deployment %s for analysis %s summary: \n replicas: %d ready replicas: %d \n available replicas: %d \n unavailable replicas: %d",
			deployment.Name,
			analysisName,
			deployment.Status.Replicas,
			deployment.Status.ReadyReplicas,
			deployment.Status.AvailableReplicas,
			deployment.Status.UnavailableReplicas,
		),
	)

	return err
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		log.Errorf("Couldn't get the hostname: %s", err.Error())
		return ""
	}
	return h
}

func main() {
	var (
		err        error
		kubeconfig *string
		cfg        *viper.Viper

		configPath    = flag.String("config", "/etc/iplant/de/jobservices.yml", "Full path to the configuration file")
		namespace     = flag.String("namespace", "default", "The namespace scope this process operates on for non-VICE calls")
		viceNamespace = flag.String("vice-namespace", "vice-apps", "The namepsace that VICE apps are launched within")
		listenPort    = flag.Int("port", 60000, "The port the service listens on for requests")
		logLevel      = flag.String("log-level", "info", "One of trace, debug, info, warn, error, fatal, or panic.")
	)

	// if cluster is set, then
	if cluster := os.Getenv("CLUSTER"); cluster != "" {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	} else {
		// If the home directory exists, then assume that the kube config will be read
		// from ~/.kube/config.
		if home := os.Getenv("HOME"); home != "" {
			kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
		} else {
			// If the home directory doesn't exist, then allow the user to specify a path.
			kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
		}
	}

	flag.Parse()
	logging.SetupLogging(*logLevel)

	log.Infof("config path is %s", *configPath)

	cfg, err = configurate.Init(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	log.Infof("done reading configuration from %s", *configPath)

	// Print error and exit if *kubeconfig is not empty and doesn't actually
	// exist. If *kubeconfig is blank, then the app may be running inside the
	// cluster, so let things proceed.
	if *kubeconfig != "" {
		_, err = os.Stat(*kubeconfig)
		if err != nil {
			if os.IsNotExist(err) {
				log.Fatalf("config %s does not exist", *kubeconfig)
			}
			log.Fatal(errors.Wrapf(err, "error stat'ing the kubeconfig %s", *kubeconfig))
		}
	}

	log.Printf("namespace is set to %s\n", *namespace)
	log.Printf("listen port is set to %d\n", *listenPort)
	log.Printf("kubeconfig is set to '%s', and may be blank", *kubeconfig)

	var config *rest.Config
	if *kubeconfig != "" {
		config, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
		if err != nil {
			log.Fatal(errors.Wrapf(err, "error building config from flags using kubeconfig %s", *kubeconfig))
		}
	} else {
		// If the home directory doesn't exist and the user doesn't specify a path,
		// then assume that we're running inside a cluster.
		config, err = rest.InClusterConfig()
		if err != nil {
			log.Fatal(errors.Wrapf(err, "error loading the config inside the cluster"))
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatal(errors.Wrap(err, "error creating clientset from config"))
	}

	jobStatusURL := cfg.GetString("vice.job-status.base")
	if jobStatusURL == "" {
		jobStatusURL = "http://job-status-listener"
	}

	jsl := &JSLPublisher{
		statusURL: jobStatusURL,
	}

	internal := &Internal{
		statusPublisher: jsl,
		clientset:       clientset,
		ViceNamespace:   *viceNamespace,
	}

	internal.MonitorVICEEvents()
}
