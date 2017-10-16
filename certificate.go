package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/trapacska/certificate-info/pkcs"
)

func getCertsJSON(p12 []byte) (string, error) {
	certs, err := pkcs.DecodeAllCerts(p12, "")
	if err != nil {
		return "", err
	}

	b, err := json.Marshal(certs)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func certFromContent(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		if _, err = w.Write([]byte(fmt.Sprintf(`{"error":"Failed to read body: %s"}`, err))); err != nil {
			fmt.Printf("Failed to write response, error: %s\n", err)
		}
		fmt.Printf("Failed to read body, error: %s\n", err)
		return
	}

	certsJSON, err := getCertsJSON(body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		if _, err = w.Write([]byte(`{"error":"Failed to get certificate info"}`)); err != nil {
			fmt.Printf("Failed to write response, error: %s\n", err)
		}
		fmt.Printf("Failed to get certificate info, error: %s\n", err)
		return
	}
	w.WriteHeader(http.StatusOK)
	if _, err = w.Write([]byte(certsJSON)); err != nil {
		fmt.Printf("Failed to write response, error: %s\n", err)
	}
}

func certFromURL(w http.ResponseWriter, r *http.Request) {
	url, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		if _, err = w.Write([]byte(fmt.Sprintf(`{"error":"Failed to read body: %s"}`, err))); err != nil {
			fmt.Printf("Failed to write response, error: %s\n", err)
		}
		fmt.Printf("Failed to read body, error: %s\n", err)
		return
	}

	response, err := http.Get(string(url))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		if _, err = w.Write([]byte(`{"error":"Failed to create request for the given URL"}`)); err != nil {
			fmt.Printf("Failed to write response, error: %s\n", err)
		}
		return
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		if _, err = w.Write([]byte(fmt.Sprintf(`{"error":"Failed to get data from the given url: %s"}`, err))); err != nil {
			fmt.Printf("Failed to write response, error: %s\n", err)
		}
		fmt.Printf("Failed to get data from the given url, error: %s\n", err)
		return
	}

	certsJSON, err := getCertsJSON(body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		if _, err = w.Write([]byte(`{"error":"Failed to get certificate info"}`)); err != nil {
			fmt.Printf("Failed to write response, error: %s\n", err)
		}
		return
	}
	w.WriteHeader(http.StatusOK)
	if _, err = w.Write([]byte(certsJSON)); err != nil {
		fmt.Printf("Failed to write response, error: %s\n", err)
	}
}
