package main

import (
	"encoding/json"
	"net/http"

	"github.com/bitrise-tools/go-xcode/profileutil"
)

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
