package main

import (
	"encoding/json"
	"fmt"
	"github.com/bitrise-io/pkcs12"
	"github.com/bitrise-tools/go-xcode/certificateutil"
	"net/http"
	"strings"
)

func handlerCertificate(w http.ResponseWriter, r *http.Request) {
	data, err := getDataFromResponse(r)
	if err != nil {
		errorResponse(w, "Failed to decrypt request body, error: %s", err)
		return
	}

	certsJSON, err := certificateToJSON(data.Data, data.Key)
	if err != nil {
		if err == pkcs12.ErrIncorrectPassword {
			w.WriteHeader(http.StatusBadRequest)
			if _, err := w.Write([]byte(fmt.Sprintf(`{"error":"%s", "error_type":"invalid_password"}`, err))); err != nil {
				logCritical("Failed to write response, error: %+v\n", err)
			}
			return
		}
		errorResponse(w, "Failed to get certificate info, error: %s", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	if _, err = w.Write([]byte(certsJSON)); err != nil {
		logCritical("Failed to write response, error: %+v", err)
	}
}

func certificateToJSON(p12, key []byte) (string, error) {
	sKey := strings.TrimSuffix(string(key), "\n")
	certs, _, err := pkcs12.DecodeAll(p12, sKey)
	if err != nil {
		return "", err
	}

	certModels := []certificateutil.CertificateInfoModel{}
	for _, cert := range certs {
		certModels = append(certModels, certificateutil.NewCertificateInfo(*cert))
	}

	b, err := json.Marshal(certModels)
	if err != nil {
		return "", err
	}

	return string(b), nil
}
