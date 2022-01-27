FROM golang:1.17 as build-root

WORKDIR /build

COPY go.mod .
COPY go.sum .

COPY . .

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

RUN go install -v ./...

ENTRYPOINT ["vice-status-listener"]

EXPOSE 60000
