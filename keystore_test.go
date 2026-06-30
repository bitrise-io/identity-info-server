package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func Test_handleKeystore(t *testing.T) {
	tests := []struct {
		name         string
		w            *httptest.ResponseRecorder
		r            *http.Request
		expectedResp string
	}{
		{
			name:         "Invalid file",
			w:            httptest.NewRecorder(),
			r:            httptest.NewRequest(http.MethodPost, "/keystore", bytes.NewReader(createRequestData(t, "empty_file", "", "", ""))),
			expectedResp: `{"error":"invalid keystore file", "error_type":"invalid_file"}`,
		},
		{
			name:         "Invalid keystore password",
			w:            httptest.NewRecorder(),
			r:            httptest.NewRequest(http.MethodPost, "/keystore", bytes.NewReader(createRequestData(t, "debug.keystore", "", "androiddebugkey", "android"))),
			expectedResp: `{"error":"incorrect keystore password", "error_type":"invalid_password"}`,
		},
		{
			name:         "Invalid alias",
			w:            httptest.NewRecorder(),
			r:            httptest.NewRequest(http.MethodPost, "/keystore", bytes.NewReader(createRequestData(t, "debug.keystore", "android", "", "android"))),
			expectedResp: `{"error":"incorrect key alias", "error_type":"invalid_alias"}`,
		},
		{
			name:         "Invalid key password",
			w:            httptest.NewRecorder(),
			r:            httptest.NewRequest(http.MethodPost, "/keystore", bytes.NewReader(createRequestData(t, "debug.keystore", "android", "androiddebugkey", ""))),
			expectedResp: `{"error":"incorrect key password", "error_type":"invalid_key_password"}`,
		},
		{
			name:         "Valid credentials",
			w:            httptest.NewRecorder(),
			r:            httptest.NewRequest(http.MethodPost, "/keystore", bytes.NewReader(createRequestData(t, "debug.keystore", "android", "androiddebugkey", "android"))),
			expectedResp: `{"first_and_last_name":"Android Debug","organization":"Android","country_code":"US","valid_from":"2022-06-22 09:57:21 +0000 UTC","valid_until":"2052-06-14 09:57:21 +0000 UTC"}`,
		},
		{
			name:         "Keystore with upper case letters in the alias",
			w:            httptest.NewRecorder(),
			r:            httptest.NewRequest(http.MethodPost, "/keystore", bytes.NewReader(createRequestData(t, "upper_case_alias_keystore.pkcs12", "keystore", "MyKey", "keystore"))),
			expectedResp: `{"organization":"Bitrise","valid_from":"2024-01-31 14:08:42 +0000 UTC","valid_until":"2049-01-24 14:08:42 +0000 UTC"}`,
		},
		{
			name:         "Keystore with multiple keys - key0",
			w:            httptest.NewRecorder(),
			r:            httptest.NewRequest(http.MethodPost, "/keystore", bytes.NewReader(createRequestData(t, "multiple_keys_keystore.pkcs12", "storepass", "key0", "keypass0"))),
			expectedResp: `{"organization":"Bitrise","valid_from":"2024-11-18 14:41:36 +0000 UTC","valid_until":"2025-11-18 14:41:36 +0000 UTC"}`,
		},
		{
			name:         "Keystore with multiple keys - key1",
			w:            httptest.NewRecorder(),
			r:            httptest.NewRequest(http.MethodPost, "/keystore", bytes.NewReader(createRequestData(t, "multiple_keys_keystore.pkcs12", "storepass", "key1", "keypass1"))),
			expectedResp: `{"organization":"Bitrise","valid_from":"2024-11-18 14:43:38 +0000 UTC","valid_until":"2025-11-18 14:43:38 +0000 UTC"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Service{Logger: log.New()}
			s.HandleKeystore(tt.w, tt.r)
			resp := tt.w.Result()
			defer func() {
				err := resp.Body.Close()
				require.NoError(t, err)
			}()

			data, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			if resp.StatusCode != http.StatusOK {
				// Error responses are returned verbatim and are unaffected by the new fields.
				require.Equal(t, tt.expectedResp, string(data))
				return
			}

			var got, want CertificateInformation
			require.NoError(t, json.Unmarshal(data, &got))
			require.NoError(t, json.Unmarshal([]byte(tt.expectedResp), &want))

			// The new fields are always present in a successful response.
			require.NotNil(t, got.FileSHA256)
			require.Regexp(t, `^[0-9a-f]{64}$`, *got.FileSHA256)
			require.NotNil(t, got.CertificateSHA256Fingerprint)
			require.Regexp(t, `^([0-9A-F]{2}:){31}[0-9A-F]{2}$`, *got.CertificateSHA256Fingerprint)

			// All previously existing fields must be unchanged. `want` is decoded from the
			// pre-existing expected JSON (which has no new fields), so comparing after clearing
			// the new fields verifies the existing behavior is intact.
			got.FileSHA256 = nil
			got.CertificateSHA256Fingerprint = nil
			require.Equal(t, want, got)
		})
	}
}

func Test_keystoreContentMetadata(t *testing.T) {
	const (
		fileName    = "debug.keystore"
		pass        = "android"
		alias       = "androiddebugkey"
		keyPassword = "android"
	)

	fileBytes, err := os.ReadFile(filepath.Join("testdata", "keystores", fileName))
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/keystore", bytes.NewReader(createRequestData(t, fileName, pass, alias, keyPassword)))
	w := httptest.NewRecorder()

	s := Service{Logger: log.New()}
	s.HandleKeystore(w, r)

	resp := w.Result()
	defer func() {
		require.NoError(t, resp.Body.Close())
	}()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var got CertificateInformation
	require.NoError(t, json.Unmarshal(data, &got))

	// file_sha256 is the lowercase hex SHA-256 of the uploaded file bytes.
	fileSum := sha256.Sum256(fileBytes)
	require.NotNil(t, got.FileSHA256)
	require.Equal(t, hex.EncodeToString(fileSum[:]), *got.FileSHA256)

	// certificate_sha256_fingerprint is the signing cert's SHA-256 in keytool format
	// (uppercase, colon-separated hex).
	cert, err := keystoreSigningCertificate(fileBytes, pass, alias, keyPassword)
	require.NoError(t, err)
	certSum := sha256.Sum256(cert.Raw)
	expectedParts := make([]string, len(certSum))
	for i, b := range certSum {
		expectedParts[i] = fmt.Sprintf("%02X", b)
	}
	require.NotNil(t, got.CertificateSHA256Fingerprint)
	require.Equal(t, strings.Join(expectedParts, ":"), *got.CertificateSHA256Fingerprint)
}

func createRequestData(t *testing.T, testFileName string, pass, alias, keyPass string) []byte {
	pth := filepath.Join("testdata", "keystores", testFileName)
	b, err := os.ReadFile(pth)
	require.NoError(t, err)

	req := RequestModel{
		Data:        b,
		Password:    []byte(pass),
		Alias:       []byte(alias),
		KeyPassword: []byte(keyPass),
	}

	reqBytes, err := json.Marshal(req)
	require.NoError(t, err)

	return reqBytes
}
