package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bitrise-io/go-pkcs12"
	"github.com/bitrise-io/go-xcode/certificateutil"
)

// CertificateInfoModel ...
// TODO: verify json field names and omit empty
type CertificateInfoModel struct {
	CommonName      string    `json:"common_name,omitempty"`
	TeamName        string    `json:"team_name,omitempty"`
	TeamID          string    `json:"team_id,omitempty"`
	Serial          string    `json:"serial,omitempty"`
	SHA1Fingerprint string    `json:"sha_1_fingerprint,omitempty"`
	EndDate         time.Time `json:"end_date"`
	StartDate       time.Time `json:"start_date"`
}

func handlerCertificate(w http.ResponseWriter, r *http.Request) {
	data, err := getDataFromResponse(r)
	if err != nil {
		errorResponse(w, "Failed to decrypt request body, error: %s", err)
		return
	}

	certsJSON, err := certificateToJSON(data.Data, string(data.Key))
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

func certificateToJSON(data []byte, password string) (string, error) {
	password = strings.TrimSuffix(password, "\n")
	certs, err := certificateutil.CertificatesFromPKCS12Content(data, password)
	if err != nil {
		return "", err
	}

	certModels := certsToCertModels(certs)

	b, err := json.Marshal(certModels)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func certsToCertModels(certs []certificateutil.CertificateInfoModel) []CertificateInfoModel {
	var certModels []CertificateInfoModel
	for _, cert := range certs {
		certModels = append(certModels, CertificateInfoModel{
			CommonName:      cert.CommonName,
			TeamName:        cert.TeamName,
			TeamID:          cert.TeamID,
			EndDate:         cert.EndDate,
			StartDate:       cert.StartDate,
			Serial:          cert.Serial,
			SHA1Fingerprint: cert.SHA1Fingerprint,
		})
	}
	return certModels
}
