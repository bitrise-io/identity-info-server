package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/bitrise-io/go-xcode/exportoptions"
	"github.com/bitrise-io/go-xcode/plistutil"

	"github.com/bitrise-io/go-xcode/profileutil"
)

// ProvisioningProfileInfoModel ...
type ProvisioningProfileInfoModel struct {
	UUID                  string                 `json:"UUID,omitempty"`
	Name                  string                 `json:"Name,omitempty"`
	TeamName              string                 `json:"TeamName,omitempty"`
	TeamID                string                 `json:"TeamID,omitempty"`
	BundleID              string                 `json:"BundleID,omitempty"`
	ExportType            exportoptions.Method   `json:"ExportType,omitempty"`
	ProvisionedDevices    []string               `json:"ProvisionedDevices,omitempty"`
	DeveloperCertificates []CertificateInfoModel `json:"DeveloperCertificates,omitempty"`
	Entitlements          plistutil.PlistData    `json:"Entitlements,omitempty"`
	ExpirationDate        time.Time              `json:"ExpirationDate"`
}

func handleProfile(w http.ResponseWriter, r *http.Request) {
	data, err := getRequestModel(r)
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

func profileToJSON(data []byte) (string, error) {
	pkcs7, err := profileutil.ProvisioningProfileFromContent(data)
	if err != nil {
		return "", err
	}

	profile, err := profileutil.NewProvisioningProfileInfo(*pkcs7)
	if err != nil {
		return "", err
	}

	profileModel := profileToProfileModel(profile)
	b, err := json.Marshal(profileModel)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func profileToProfileModel(profile profileutil.ProvisioningProfileInfoModel) ProvisioningProfileInfoModel {
	return ProvisioningProfileInfoModel{
		UUID:                  profile.UUID,
		Name:                  profile.Name,
		TeamName:              profile.TeamName,
		TeamID:                profile.TeamID,
		BundleID:              profile.BundleID,
		ExportType:            profile.ExportType,
		ProvisionedDevices:    profile.ProvisionedDevices,
		DeveloperCertificates: certsToCertModels(profile.DeveloperCertificates),
		Entitlements:          profile.Entitlements,
		ExpirationDate:        profile.ExpirationDate,
	}
}
