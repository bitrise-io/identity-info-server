package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/gorilla/mux"
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

func main() {
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/", index).Methods("GET")
	router.HandleFunc("/certificate/url", certFromURL).Methods("POST")
	router.HandleFunc("/certificate", certFromContent).Methods("POST")

	if err := http.ListenAndServe(":"+os.Getenv("PORT"), router); err != nil {
		fmt.Printf("Failed to listen, error: %s\n", err)
	}
}

func index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Welcome!")
}

func certFromContent(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte(fmt.Sprintf(`{"error":"Failed to read body: %s"}`, err)))
		if err != nil {
			fmt.Printf("Failed to write response, error: %s\n", err)
			return
		}
		return
	}

	certsJSON, err := getCertsJSON(body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte(`{"error":"Failed to get certificate info"}`))
		if err != nil {
			fmt.Printf("Failed to write response, error: %s\n", err)
			return
		}
		return
	}
	w.WriteHeader(http.StatusOK)
	_, err = w.Write([]byte(certsJSON))
	if err != nil {
		fmt.Printf("Failed to write response, error: %s\n", err)
		return
	}
}

func certFromURL(w http.ResponseWriter, r *http.Request) {
	url, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte(fmt.Sprintf(`{"error":"Failed to read body: %s"}`, err)))
		if err != nil {
			fmt.Printf("Failed to write response, error: %s\n", err)
			return
		}
		return
	}

	response, err := http.Get(string(url))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte(`{"error":"Failed to create request for the given URL"}`))
		if err != nil {
			fmt.Printf("Failed to write response, error: %s\n", err)
			return
		}
		return
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte(fmt.Sprintf(`{"error":"Failed to get data from the given url: %s"}`, err)))
		if err != nil {
			fmt.Printf("Failed to write response, error: %s\n", err)
			return
		}
		return
	}

	certsJSON, err := getCertsJSON(body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte(`{"error":"Failed to get certificate info"}`))
		if err != nil {
			fmt.Printf("Failed to write response, error: %s\n", err)
			return
		}
		return
	}
	w.WriteHeader(http.StatusOK)
	_, err = w.Write([]byte(certsJSON))
	if err != nil {
		fmt.Printf("Failed to write response, error: %s\n", err)
		return
	}
}
