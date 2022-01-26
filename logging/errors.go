package logging

import (
	"encoding/json"
	"net/http"

	"github.com/labstack/echo/v4"
)

// HTTPErrorHandler is an echo.HTTPErrorHandler for this application.
func HTTPErrorHandler(err error, c echo.Context) {
	code := http.StatusInternalServerError
	var body interface{}

	switch t := err.(type) {
	case ErrorResponse:
		code = http.StatusBadRequest
		body = t
	case *ErrorResponse:
		code = http.StatusBadRequest
		body = t
	case *echo.HTTPError:
		echoErr := t
		code = echoErr.Code
		body = NewErrorResponse(err)
	default:
		body = NewErrorResponse(err)
	}

	c.JSON(code, body) //nolint - lack of return value is required by Echo.
}

// ErrorResponse represents an HTTP response body containing error information. This type implements
// the error interface so that it can be returned as an error from from existing functions.
//
// swagger:response errorResponse
type ErrorResponse struct {
	Message   string                  `json:"message"`
	ErrorCode string                  `json:"error_code,omitempty"`
	Details   *map[string]interface{} `json:"details,omitempty"`
}

// ErrorBytes returns a byte-array representation of an ErrorResponse.
func (e ErrorResponse) ErrorBytes() []byte {
	bytes, err := json.Marshal(e)
	if err != nil {
		Log.Errorf("unable to marshal %+v as JSON", e)
		return make([]byte, 0)
	}
	return bytes
}

// Error returns a string representation of an ErrorResponse.
func (e ErrorResponse) Error() string {
	return string(e.ErrorBytes())
}

// DetailedError responds to an HTTP request with a JSON response body indicating that an error
// occurred and providing some extra details about the error if additional details are available.
func DetailedError(writer http.ResponseWriter, cause error, code int) {
	writer.Header().Set("Content-Type", "application/json")

	// Handle both instances of ErrorResponse and generic errors.
	var errorResponse ErrorResponse
	switch val := cause.(type) {
	case ErrorResponse:
		errorResponse = val
	case error:
		errorResponse = ErrorResponse{Message: val.Error()}
	}

	// Return the response.
	writer.WriteHeader(code)
	_, err := writer.Write(errorResponse.ErrorBytes())
	if err != nil {
		Log.Errorf("unable to write response body for error: %+v", cause)
		return
	}
}

// Error responds to an HTTP request with a JSON response body indicating that an error occurred.
func Error(writer http.ResponseWriter, message string, code int) {
	DetailedError(writer, ErrorResponse{Message: message}, code)
}

// NewErrorResponse constructs an ErrorResponse based on the message passed in, but does not send
// it over the wire. This is to aid in converting to labstack/echo.
func NewErrorResponse(err error) ErrorResponse {
	var errorResponse ErrorResponse
	switch val := err.(type) {
	case ErrorResponse:
		errorResponse = val
	case error:
		errorResponse = ErrorResponse{Message: val.Error()}
	}
	return errorResponse
}
