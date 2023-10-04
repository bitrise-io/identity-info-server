package main

import (
	"encoding/json"
	"net/http"

	"github.com/bitrise-io/go-android/v2/keystore"
)

// CertificateInformation ...
type CertificateInformation struct {
	FirstAndLastName   string `json:"first_and_last_name,omitempty"`
	OrganizationalUnit string `json:"organizational_unit,omitempty"`
	Organization       string `json:"organization,omitempty"`
	CityOrLocality     string `json:"city_or_locality,omitempty"`
	StateOrProvince    string `json:"state_or_province,omitempty"`
	CountryCode        string `json:"country_code,omitempty"`
	ValidFrom          string `json:"valid_from,omitempty"`
	ValidUntil         string `json:"valid_until,omitempty"`
}

// HandleKeystore ...
func (s Service) HandleKeystore(w http.ResponseWriter, r *http.Request) {
	reqModel, err := getRequestModel(r)
	if err != nil {
		s.errorResponse(w, "Failed to decrypt request body, error: %s", err)
		return
	}

	keystoreJSON, err := keystoreToJSON(reqModel.Data, string(reqModel.Password), string(reqModel.Alias), string(reqModel.KeyPassword))
	if err != nil {
		switch err {
		case keystore.IncorrectKeystorePasswordError:
			s.errorResponseWithType(w, err, "invalid_password")
		case keystore.IncorrectAliasError:
			s.errorResponseWithType(w, err, "invalid_alias")
		case keystore.IncorrectKeyPasswordError:
			s.errorResponseWithType(w, err, "invalid_key_password")
		default:
			s.errorResponse(w, "Failed to get keystore info, error: %s", err)
		}
		return
	}

	w.WriteHeader(http.StatusOK)
	if _, err = w.Write([]byte(keystoreJSON)); err != nil {
		s.Logger.Errorf("Failed to write response, error: %+v", err)
	}
}

func keystoreToJSON(data []byte, password, alias, keyPassword string) (string, error) {
	reader := keystore.NewDefaultReader()
	certInfo, err := reader.ReadCertificateInformation(data, password, alias, keyPassword)
	if err != nil {
		return "", err
	}

	certModel := convertCertificateInformation(certInfo)
	b, err := json.Marshal(certModel)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func convertCertificateInformation(certInfo *keystore.CertificateInformation) CertificateInformation {
	return CertificateInformation{
		FirstAndLastName:   certInfo.FirstAndLastName,
		OrganizationalUnit: certInfo.OrganizationalUnit,
		Organization:       certInfo.Organization,
		CityOrLocality:     certInfo.CityOrLocality,
		StateOrProvince:    certInfo.StateOrProvince,
		CountryCode:        certInfo.CountryCode,
		ValidFrom:          certInfo.ValidFrom,
		ValidUntil:         certInfo.ValidUntil,
	}
}
