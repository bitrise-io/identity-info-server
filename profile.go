package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	plist "github.com/DHowett/go-plist"
	"github.com/bitrise-io/go-utils/command"
)

func getProfileJSON(profile []byte) (string, error) {
	cmd := command.New("openssl", "smime", "-inform", "der", "-verify")
	cmd.SetStdin(strings.NewReader(string(profile)))

	var b bytes.Buffer
	cmd.SetStdout(&b)

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("%s - %s", string(b.Bytes()), err)
	}

	var intf interface{}
	dec := plist.NewDecoder(bytes.NewReader(b.Bytes()))

	err = dec.Decode(&intf)
	if err != nil {
		return "", err
	}

	str, err := json.Marshal(intf)
	if err != nil {
		return "", err
	}

	return string(str), nil
}

func profFromContent(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Printf("Failed to read body, error: %s\n", err)
		if _, err = w.Write([]byte(fmt.Sprintf(`{"error":"Failed to read body: %s"}`, err))); err != nil {
			fmt.Printf("Failed to write response, error: %s\n", err)
		}
		return
	}

	profJSON, err := getProfileJSON(body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Printf("Failed to get profile info, error: %s\n", err)
		if _, err = w.Write([]byte(fmt.Sprintf(`{"error":"Failed to get profile info: %s"}`, err))); err != nil {
			fmt.Printf("Failed to write response, error: %s\n", err)
		}
		return
	}

	w.WriteHeader(http.StatusOK)
	if _, err = w.Write([]byte(profJSON)); err != nil {
		fmt.Printf("Failed to write response, error: %s\n", err)
	}
}

func profFromURL(w http.ResponseWriter, r *http.Request) {
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
		fmt.Printf("Failed to create request for the given URL, error: %s\n", err)
		if _, err = w.Write([]byte(`{"error":"Failed to create request for the given URL"}`)); err != nil {
			fmt.Printf("Failed to write response, error: %s\n", err)
		}
		return
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Printf("Failed to read body, error: %s\n", err)
		if _, err = w.Write([]byte(fmt.Sprintf(`{"error":"Failed to read body: %s"}`, err))); err != nil {
			fmt.Printf("Failed to write response, error: %s\n", err)
		}
		return
	}

	profJSON, err := getProfileJSON(body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Printf("Failed to get profile info, error: %s\n", err)
		if _, err = w.Write([]byte(fmt.Sprintf(`{"error":"Failed to get profile info: %s"}`, err))); err != nil {
			fmt.Printf("Failed to write response, error: %s\n", err)
		}
		return
	}

	w.WriteHeader(http.StatusOK)
	if _, err = w.Write([]byte(profJSON)); err != nil {
		fmt.Printf("Failed to write response, error: %s\n", err)
	}
}
