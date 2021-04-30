package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/bitrise-io/pkcs12"
	"github.com/bitrise-tools/go-xcode/certificateutil"
	"github.com/bitrise-tools/go-xcode/profileutil"
	"gopkg.in/DataDog/dd-trace-go.v1/contrib/gorilla/mux"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

//
// MISC

// RequestModel ...
type RequestModel struct {
	Data []byte `json:"data"`
	Key  []byte `json:"key"`
}

func errorResponse(w http.ResponseWriter, f string, v ...interface{}) {
	w.WriteHeader(http.StatusBadRequest)
	if _, err := w.Write([]byte(fmt.Sprintf(`{"error":"%s"}`, fmt.Sprintf(f, v...)))); err != nil {
		logCritical("Failed to write response, error: %+v\n", err)
	}
}

func logCritical(f string, v ...interface{}) {
	fmt.Printf("[!] Exception: %s\n", fmt.Sprintf(f, v...))
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
	pkcs7, err := profileutil.ProvisioningProfileFromContent(profile)
	if err != nil {
		return "", err
	}

	profileModel, err := profileutil.NewProvisioningProfileInfo(*pkcs7)
	if err != nil {
		return "", err
	}

	str, err := json.Marshal(profileModel)
	if err != nil {
		return "", err
	}

	return string(str), nil
}

func certificateToJSON(p12, key []byte) (string, error) {
	sKey := strings.TrimSuffix(string(key), "\n")
	certs, err := pkcs12.DecodeAllCerts(p12, "sKey")
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

func getDataFromResponse(r *http.Request) (RequestModel, error) {
	request := RequestModel{}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Printf("Failed to read body, error: %s", err)
	}

	err = json.NewDecoder(bytes.NewReader(body)).Decode(&request)
	if err != nil {
		return RequestModel{}, fmt.Errorf("Failed to decode body to JSON, error: %s, body: %s", err, string(body))
	}

	if isValidURL(string(request.Data)) {
		response, err := http.Get(strings.TrimSpace(string(request.Data)))
		if err != nil {
			return RequestModel{}, fmt.Errorf("Failed to create request for the given URL, error: %s", err)
		}

		request.Data, err = ioutil.ReadAll(response.Body)
		if err != nil {
			return RequestModel{}, fmt.Errorf("Failed to read body, error: %s", err)
		}

		if response.StatusCode != http.StatusOK {
			return RequestModel{}, fmt.Errorf("Failed to download file, error: %s", string(request.Data))
		}
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

func handlerProfile(w http.ResponseWriter, r *http.Request) {
	data, err := getDataFromResponse(r)
	if err != nil {
		errorResponse(w, "Failed to decrypt request body, error: %s", err)
		return
	}

	profJSON, err := profileToJSON(data.Data)
	if err != nil {
		errorResponse(w, "Failed to get profile info, error: %s", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	if _, err = w.Write([]byte(profJSON)); err != nil {
		logCritical("Failed to write response, error: %+v", err)
	}
}

func getPort() string {
	if port, ok := os.LookupEnv("PORT"); ok {
		return port
	}

	return "8080"
}

func main() {
	port := getPort()

	tracer.Start()
	defer tracer.Stop()

	router := mux.NewRouter(mux.WithAnalytics(true)).StrictSlash(true)
	router.HandleFunc("/certificate", handlerCertificate).Methods("POST")
	router.HandleFunc("/profile", handlerProfile).Methods("POST")
	router.HandleFunc("/", index).Methods("GET")

	if err := http.ListenAndServe(":"+port, router); err != nil {
		logCritical("Failed to listen, error: %s", err)
		return
	}
}
