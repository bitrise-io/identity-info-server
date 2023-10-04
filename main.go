package main

import (
	"net/http"
	"os"

	log "github.com/sirupsen/logrus"
	"gopkg.in/DataDog/dd-trace-go.v1/contrib/gorilla/mux"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

func main() {
	port := getPort()

	tracer.Start()
	defer tracer.Stop()

	logger := log.New()
	logger.SetFormatter(&log.JSONFormatter{})

	service := Service{Logger: logger}

	router := mux.NewRouter(mux.WithAnalytics(true)).StrictSlash(true)
	router.HandleFunc("/certificate", service.HandleCertificate).Methods("POST")
	router.HandleFunc("/profile", service.HandleProfile).Methods("POST")
	router.HandleFunc("/keystore", service.HandleKeystore).Methods("POST")
	router.HandleFunc("/", service.Index).Methods("GET")

	if err := http.ListenAndServe(":"+port, router); err != nil {
		logger.Errorf("Failed to listen, error: %s", err)
		return
	}
}

func getPort() string {
	if port, ok := os.LookupEnv("PORT"); ok {
		return port
	}

	return "8080"
}
