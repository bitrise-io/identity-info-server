package main

import (
	"encoding/json"
	"errors"
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

	// FileSHA256 is the SHA-256 of the uploaded file bytes as lowercase hex.
	// It is null for certificates that are not backed by an uploaded file (e.g. certificates
	// embedded in a provisioning profile).
	FileSHA256 *string `json:"FileSHA256"`
}

// HandleCertificate ...
func (s Service) HandleCertificate(w http.ResponseWriter, r *http.Request) {
	data, err := getRequestModel(r)
	if err != nil {
		s.errorResponse(w, "Failed to decrypt request body, error: %s", err)
		return
	}

	certsJSON, err := s.certificateToJSON(data.Data, string(data.Password))
	if err != nil {
		if errors.Is(err, pkcs12.ErrIncorrectPassword) {
			s.errorResponseWithType(w, err, "invalid_password")
			return
		}
		s.errorResponse(w, "Failed to get certificate info, error: %s", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	if _, err = w.Write([]byte(certsJSON)); err != nil {
		s.Logger.Errorf("Failed to write response, error: %+v", err)
	}
}

func (s Service) certificateToJSON(data []byte, password string) (string, error) {
	password = strings.TrimSuffix(password, "\n")
	certs, err := certificateutil.CertificatesFromPKCS12Content(data, password)
	if err != nil {
		return "", err
	}

	fileSHA256 := sha256Hex(data)
	certModels := s.certsToCertModels(certs, &fileSHA256)
	b, err := json.Marshal(certModels)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// certsToCertModels maps the parsed certificates to response models.
// fileSHA256 is the SHA-256 of the uploaded file the certificates were extracted from; pass nil
// for certificates that do not originate from an uploaded file (e.g. profile-embedded certificates).
func (s Service) certsToCertModels(certs []certificateutil.CertificateInfoModel, fileSHA256 *string) []CertificateInfoModel {
	var certModels []CertificateInfoModel
	for _, cert := range certs {
		listingType := UnknownCertificateListingType
		listingPlatform := UnknownCertificateListingPlatform

		certType, err := certificateType(cert)
		if err != nil {
			s.Logger.Warn(err)
		} else {
			listingType, listingPlatform, err = certificatesTypeToListingTypes(certType)
			if err != nil {
				s.Logger.Warn(err)
			}
		}

		certModels = append(certModels, CertificateInfoModel{
			CommonName:      cert.CommonName,
			TeamName:        cert.TeamName,
			TeamID:          cert.TeamID,
			EndDate:         cert.EndDate,
			StartDate:       cert.StartDate,
			Serial:          cert.Serial,
			ListingType:     listingType,
			ListingPlatform: listingPlatform,
			FileSHA256:      fileSHA256,
		})
	}
	return certModels
}
