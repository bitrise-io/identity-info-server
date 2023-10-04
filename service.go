package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"
)

type Service struct {
	Logger *log.Logger
}

func (s Service) Index(w http.ResponseWriter, r *http.Request) {
	if err := json.NewEncoder(w).Encode(map[string]string{"message": "Welcome!"}); err != nil {
		s.Logger.Errorf("Failed to write response, error: %+v", err)
	}
}

func (s Service) errorResponseWithType(w http.ResponseWriter, err error, errorType string) {
	data := fmt.Sprintf(`{"error":"%s", "error_type":"%s"}`, err, errorType)
	w.WriteHeader(http.StatusBadRequest)
	if _, err := w.Write([]byte(data)); err != nil {
		s.Logger.Errorf("Failed to write response, error: %+v\n", err)
	}
}

func (s Service) errorResponse(w http.ResponseWriter, f string, v ...interface{}) {
	w.WriteHeader(http.StatusBadRequest)
	if _, err := w.Write([]byte(fmt.Sprintf(`{"error":"%s"}`, fmt.Sprintf(f, v...)))); err != nil {
		s.Logger.Errorf("Failed to write response, error: %+v\n", err)
	}
}
