package main

import (
	"encoding/json"
	"net/http"
	"os"

	"gopkg.in/DataDog/dd-trace-go.v1/contrib/gorilla/mux"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

func main() {
	port := getPort()

	tracer.Start()
	defer tracer.Stop()

	router := mux.NewRouter(mux.WithAnalytics(true)).StrictSlash(true)
	router.HandleFunc("/certificate", handlerCertificate).Methods("POST")
	router.HandleFunc("/profile", handlerProfile).Methods("POST")
	router.HandleFunc("/", index).Methods("GET")

	if err := http.ListenAndServe(":"+port, router); err != nil {
		logCritical("Failed to listen, error: %s", err)
		return
	}
}

func getPort() string {
	if port, ok := os.LookupEnv("PORT"); ok {
		return port
	}

	return "8080"
}

func index(w http.ResponseWriter, r *http.Request) {
	if err := json.NewEncoder(w).Encode(map[string]string{"message": "Welcome!"}); err != nil {
		logCritical("Failed to write response, error: %+v", err)
	}
}
