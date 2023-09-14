package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// RequestModel ...
type RequestModel struct {
	Data        []byte `json:"data"`
	Password    []byte `json:"key"`
	Alias       []byte `json:"alias"`
	KeyPassword []byte `json:"key_password"`
}

func getRequestModel(r *http.Request) (RequestModel, error) {
	request := RequestModel{}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return RequestModel{}, fmt.Errorf("failed to read request body: %s", err)
	}

	err = json.NewDecoder(bytes.NewReader(body)).Decode(&request)
	if err != nil {
		return RequestModel{}, fmt.Errorf("failed to decode request body (%s): %s", string(body), err)
	}

	if isValidURL(string(request.Data)) {
		response, err := http.Get(strings.TrimSpace(string(request.Data)))
		if err != nil {
			return RequestModel{}, fmt.Errorf("failed to create request for the given URL: %s", err)
		}

		request.Data, err = io.ReadAll(response.Body)
		if err != nil {
			return RequestModel{}, fmt.Errorf("failed to read body: %s", err)
		}

		if response.StatusCode != http.StatusOK {
			return RequestModel{}, fmt.Errorf("failed to download file: %s", string(request.Data))
		}
	}

	return request, nil
}

func errorResponse(w http.ResponseWriter, f string, v ...interface{}) {
	w.WriteHeader(http.StatusBadRequest)
	if _, err := w.Write([]byte(fmt.Sprintf(`{"error":"%s"}`, fmt.Sprintf(f, v...)))); err != nil {
		logCritical("Failed to write response, error: %+v\n", err)
	}
}

func logCritical(f string, v ...interface{}) {
	fmt.Printf("[!] Exception: %s\n", fmt.Sprintf(f, v...))
}

func isValidURL(reqURL string) bool {
	_, err := url.ParseRequestURI(reqURL)
	return err == nil
}
