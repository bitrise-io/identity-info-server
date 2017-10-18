package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"

	plist "github.com/DHowett/go-plist"
	"github.com/bitrise-io/go-utils/pkcs12"
	"github.com/fullsailor/pkcs7"
	"github.com/gorilla/mux"
)

//
// CONFIG

// Configs ...
type Configs struct {
	Port   string
	Secret string
}

// NewConfig ...
func NewConfig() (*Configs, error) {
	port := os.Getenv("PORT")
	if port == "" {
		return nil, fmt.Errorf("No PORT specified")
	}

	secret := os.Getenv("AES256_SECRET_KEY")
	if secret == "" {
		return nil, fmt.Errorf("No AES256_SECRET_KEY specified")
	}

	if len(secret) != 32 {
		return nil, fmt.Errorf("Invalid AES256_SECRET_KEY length: %d, required: %d", len(secret), 32)
	}

	return &Configs{
		Port:   port,
		Secret: secret,
	}, nil
}

//
// MISC

// RequestModel ...
type RequestModel struct {
	Data []byte `json:"data"`
	Key  []byte `json:"key"`
}

func errorResponse(w http.ResponseWriter, f string, v ...interface{}) {
	w.WriteHeader(http.StatusBadRequest)
	if _, err := w.Write([]byte(fmt.Sprintf(`{"error":"%s"}`, fmt.Sprintf(f, v)))); err != nil {
		logCritical("Failed to write response, error: %+v\n", err)
	}
}

func logCritical(f string, v ...interface{}) {
	fmt.Printf("[!] Exception: %s\n", fmt.Sprintf(f, v))
}

func decryptData(ciphertext, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short %d - %d", len(ciphertext), nonceSize)
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func isValidURL(reqURL string) bool {
	_, err := url.ParseRequestURI(reqURL)
	return (err == nil)
}

func profileToJSON(profile []byte) (string, error) {
	pkcs7, err := pkcs7.Parse(profile)
	if err != nil {
		return "", err
	}

	var intf map[string]interface{}
	dec := plist.NewDecoder(bytes.NewReader(pkcs7.Content))
	if err := dec.Decode(&intf); err != nil {
		return "", err
	}

	if certificatesPlistArray, ok := intf["DeveloperCertificates"]; ok {
		if certificatesArray, ok := certificatesPlistArray.([]interface{}); ok {
			certs := []*x509.Certificate{}
			for _, base64Data := range certificatesArray {
				if certArrayData, ok := base64Data.([]byte); ok {
					cert, err := x509.ParseCertificate(certArrayData)
					if err != nil {
						return "", fmt.Errorf("E2: %s", err)
					}

					certs = append(certs, cert)
				}
			}
			intf["DeveloperCertificates"] = certs
		}
	}

	str, err := json.Marshal(intf)
	if err != nil {
		return "", err
	}

	return string(str), nil
}

func certificateToJSON(p12, key []byte) (string, error) {
	certs, err := pkcs12.DecodeAllCerts(p12, string(key))
	if err != nil {
		return "", err
	}

	b, err := json.Marshal(certs)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func getDecryptedDataFromResponse(r *http.Request, secret []byte) (RequestModel, error) {
	request := RequestModel{}
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		return RequestModel{}, fmt.Errorf("Failed to decode body to JSON, error: %s", err)
	}

	dataDecrypted, err := decryptData(request.Data, secret)
	if err != nil {
		return RequestModel{}, fmt.Errorf("Failed to decrypt body, error: %s", err)
	}
	request.Data = dataDecrypted

	if len(request.Key) != 0 {
		keyDecrypted, err := decryptData(request.Key, secret)
		if err != nil {
			return RequestModel{}, fmt.Errorf("Failed to decrypt body, error: %s", err)
		}
		request.Key = keyDecrypted
	}

	if isValidURL(string(request.Data)) {
		response, err := http.Get(string(request.Data))
		if err != nil {
			return RequestModel{}, fmt.Errorf("Failed to create request for the given URL, error: %s", err)
		}
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return RequestModel{}, fmt.Errorf("Failed to read body, error: %s", err)
		}
		request.Data = body
	}

	return request, nil
}

//
// HANDLERS

func index(w http.ResponseWriter, r *http.Request) {
	if err := json.NewEncoder(w).Encode(map[string]string{"message": "Welcome!"}); err != nil {
		logCritical("Failed to write response, error: %+v", err)
	}
}

func (configs *Configs) handlerCertificate(w http.ResponseWriter, r *http.Request) {
	decryptedData, err := getDecryptedDataFromResponse(r, []byte(configs.Secret))
	if err != nil {
		errorResponse(w, "Failed to decrypt request body, error: %s", err)
		return
	}

	certsJSON, err := certificateToJSON(decryptedData.Data, decryptedData.Key)
	if err != nil {
		errorResponse(w, "Failed to get certificate info, error: %s", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	if _, err = w.Write([]byte(certsJSON)); err != nil {
		logCritical("Failed to write response, error: %+v", err)
	}
}

func (configs *Configs) handlerProfile(w http.ResponseWriter, r *http.Request) {
	decryptedData, err := getDecryptedDataFromResponse(r, []byte(configs.Secret))
	if err != nil {
		errorResponse(w, "Failed to decrypt request body, error: %s", err)
		return
	}

	profJSON, err := profileToJSON(decryptedData.Data)
	if err != nil {
		errorResponse(w, "Failed to get profile info, error: %s", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	if _, err = w.Write([]byte(profJSON)); err != nil {
		fmt.Printf("Failed to write response, error: %+v", err)
	}
}

func main() {
	config, err := NewConfig()
	if err != nil {
		logCritical("Failed to create configs, error: %s", err)
		return
	}

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/certificate", config.handlerCertificate).Methods("POST")
	router.HandleFunc("/profile", config.handlerProfile).Methods("POST")
	router.HandleFunc("/", index).Methods("GET")

	if err := http.ListenAndServe(":"+config.Port, router); err != nil {
		logCritical("Failed to listen, error: %s", err)
		return
	}
}
