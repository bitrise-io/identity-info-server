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
// TODO: verify json field names and omit empty
type ProvisioningProfileInfoModel struct {
	UUID                  string                  `json:"uuid,omitempty"`
	Name                  string                  `json:"name,omitempty"`
	TeamName              string                  `json:"team_name,omitempty"`
	TeamID                string                  `json:"team_id,omitempty"`
	BundleID              string                  `json:"bundle_id,omitempty"`
	ExportType            exportoptions.Method    `json:"export_type,omitempty"`
	ProvisionedDevices    []string                `json:"provisioned_devices,omitempty"`
	DeveloperCertificates []CertificateInfoModel  `json:"developer_certificates,omitempty"`
	Entitlements          plistutil.PlistData     `json:"entitlements,omitempty"`
	ProvisionsAllDevices  bool                    `json:"provisions_all_devices,omitempty"`
	Type                  profileutil.ProfileType `json:"type,omitempty"`
	CreationDate          time.Time               `json:"creation_date"`
	ExpirationDate        time.Time               `json:"expiration_date"`
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
		ProvisionsAllDevices:  profile.ProvisionsAllDevices,
		Type:                  profile.Type,
		CreationDate:          profile.CreationDate,
		ExpirationDate:        profile.ExpirationDate,
	}
}
