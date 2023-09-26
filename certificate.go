package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/bitrise-io/go-pkcs12"
	"github.com/bitrise-io/go-xcode/certificateutil"
)

// CertificateInfoModel ...
type CertificateInfoModel struct {
	CommonName      string                     `json:"CommonName,omitempty"`
	TeamName        string                     `json:"TeamName,omitempty"`
	TeamID          string                     `json:"TeamID,omitempty"`
	Serial          string                     `json:"Serial,omitempty"`
	EndDate         time.Time                  `json:"EndDate"`
	StartDate       time.Time                  `json:"StartDate"`
	ListingType     CertificateListingType     `json:"ListingType"`
	ListingPlatform CertificateListingPlatform `json:"ListingPlatform"`
}

func handleCertificate(w http.ResponseWriter, r *http.Request) {
	data, err := getRequestModel(r)
	if err != nil {
		errorResponse(w, "Failed to decrypt request body, error: %s", err)
		return
	}

	certsJSON, err := certificateToJSON(data.Data, string(data.Password))
	if err != nil {
		if err == pkcs12.ErrIncorrectPassword {
			errorResponseWithType(w, err, "invalid_password")
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
		certType := certificateType(cert)
		listingType, listingPlatform := certificatesTypeToListingTypes(certType)

		certModels = append(certModels, CertificateInfoModel{
			CommonName:      cert.CommonName,
			TeamName:        cert.TeamName,
			TeamID:          cert.TeamID,
			EndDate:         cert.EndDate,
			StartDate:       cert.StartDate,
			Serial:          cert.Serial,
			ListingType:     listingType,
			ListingPlatform: listingPlatform,
		})
	}
	return certModels
}
