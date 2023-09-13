package main

import "net/http"

func handleKeystore(w http.ResponseWriter, r *http.Request) {
	data, err := getDataFromResponse(r)
	if err != nil {
		errorResponse(w, "Failed to decrypt request body, error: %s", err)
		return
	}

	keystoreJSON, err := keystoreToJSON(data.Data)
	if err != nil {
		errorResponse(w, "Failed to get profile info, error: %s", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	if _, err = w.Write([]byte(keystoreJSON)); err != nil {
		logCritical("Failed to write response, error: %+v", err)
	}
}

func keystoreToJSON(data []byte) (string, error) {
	return "", nil
}
