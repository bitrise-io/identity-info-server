package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

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

	// CertificateSHA256Fingerprint is the SHA-256 fingerprint of the signing certificate in keytool
	// format: uppercase hex, colon-separated (e.g. "AB:CD:EF:..."). It is null when the fingerprint
	// cannot be determined.
	CertificateSHA256Fingerprint *string `json:"certificate_sha256_fingerprint"`
	// FileSHA256 is the SHA-256 of the uploaded file bytes as lowercase hex.
	FileSHA256 *string `json:"file_sha256"`
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
		switch {
		case errors.Is(err, keystore.InvalidKeystoreFileError):
			s.Logger.Errorf("Invalid keystore file: %s", err)
			s.errorResponseWithType(w, keystore.InvalidKeystoreFileError, "invalid_file")
		case errors.Is(err, keystore.IncorrectKeystorePasswordError):
			s.errorResponseWithType(w, err, "invalid_password")
		case errors.Is(err, keystore.IncorrectAliasError):
			s.errorResponseWithType(w, err, "invalid_alias")
		case errors.Is(err, keystore.IncorrectKeyPasswordError):
			s.errorResponseWithType(w, err, "invalid_key_password")
		default:
			s.Logger.Errorf("Failed to get keystore info, error: %s", err)
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

	// The file SHA-256 is always computable from the uploaded bytes.
	fileSHA256 := sha256Hex(data)
	certModel.FileSHA256 = &fileSHA256

	// The certificate fingerprint is best effort. See keystoreSigningCertificate for why the
	// keystore is decoded a second time here. Decoding already succeeded above, so this should
	// succeed too; if it does not, the fingerprint is left null.
	if cert, err := keystoreSigningCertificate(data, password, alias, keyPassword); err == nil {
		fingerprint := sha256Fingerprint(cert)
		certModel.CertificateSHA256Fingerprint = &fingerprint
	}

	b, err := json.Marshal(certModel)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// keystoreSigningCertificate decodes the keystore and returns the raw signing certificate so its
// SHA-256 fingerprint can be computed.
//
// This is a known, deliberate workaround, flagged in code review:
//
// The fingerprint is a property of the exact certificate that keystore.Reader.ReadCertificateInformation
// already decodes. That method, however, decodes the keystore, parses the *x509.Certificate into a
// keystore.CertificateInformation and then discards the raw certificate, so the caller never gets it
// back. The vendored keystore package exposes no lower-level Reader method that returns the raw
// certificate. The only public way to obtain it is via the Decoder API, which forces us to both
// re-declare the same decoder list that keystore.NewDefaultReader uses internally (there is no
// accessor for a Reader's decoders) and decode the keystore a second time.
//
// The proper fix belongs upstream in go-android: ReadCertificateInformation should also return the
// decoded *x509.Certificate (or the fingerprint), which would let us drop this function and the
// duplicate decode entirely. That change is out of scope here because the dependency is vendored and
// must not be modified in this repository. Until it lands, this pragmatic double-decode keeps the
// fingerprint correct without touching existing keystore error handling.
func keystoreSigningCertificate(data []byte, password, alias, keyPassword string) (*x509.Certificate, error) {
	decoders := []keystore.Decoder{keystore.PKCS12KeystoreDecoder{}, keystore.JKSKeystoreDecoder{}}
	for _, decoder := range decoders {
		if _, cert, err := decoder.Decode(data, password, alias, keyPassword); err == nil && cert != nil {
			return cert, nil
		}
	}
	return nil, fmt.Errorf("could not decode certificate from keystore")
}

// sha256Fingerprint returns the SHA-256 fingerprint of the certificate in keytool format:
// uppercase hex, colon-separated (e.g. "AB:CD:EF:...").
func sha256Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
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
