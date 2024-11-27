package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
			name: "Invalid file",
			w:    httptest.NewRecorder(),
			r:    httptest.NewRequest(http.MethodPost, "/keystore", bytes.NewReader(createRequestData(t, "empty_file", "", "", ""))),
			expectedResp: `{"error":"Failed to get keystore info, error: failed to decode keystore:
- pkcs12: error reading P12 data: asn1: syntax error: sequence truncated
- unexpected EOF at position 0 while reading magic header"}`,
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
			require.Equal(t, tt.expectedResp, string(data))
		})
	}
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
