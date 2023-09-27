package main

import (
	"fmt"

	"github.com/bitrise-io/go-xcode/profileutil"
)

// ProfileType ...
type ProfileType string

// ProfileTypes ...
const (
	DevelopmentProfileType ProfileType = "Development"
	AdHocProfileType       ProfileType = "Ad hoc"
	AppStoreProfileType    ProfileType = "App Store"
	DeveloperIDProfileType ProfileType = "Developer ID"
	EnterpriseProfileType  ProfileType = "Enterprise"
	UnknownProfileType     ProfileType = "unknown"
)

// getProfileType returns the type (ProfileType) based on the provided provisioning profile content.
func getProfileType(profile profileutil.ProvisioningProfileInfoModel) (ProfileType, error) {
	/*
		| macOS        | ProvisionedDevices | ProvisionsAllDevices
		|--------------|--------------------|----------------------|
		| Development  | true               | false                |
		| App Store    | false              | false                |
		| Developer ID | false              | true                 |

		---

		| iOS         | ProvisionedDevices | ProvisionsAllDevices | get-task-allow |
		|-------------|--------------------|----------------------|----------------|
		| Development | true               | false                | true           |
		| Ad Hoc      | true               | false                | false          |
		| App Store   | false              | false                | false          |
		| Enterprise  | false              | true                 | false          |
	*/

	hasProvisionedDevices := len(profile.ProvisionedDevices) > 0
	provisionsAllDevices := profile.ProvisionsAllDevices
	isMacOS := profile.Type == profileutil.ProfileTypeMacOs
	isIOS := profile.Type == profileutil.ProfileTypeIos || profile.Type == profileutil.ProfileTypeTvOs

	if isMacOS && !isIOS {
		switch {
		case hasProvisionedDevices && !provisionsAllDevices:
			return DevelopmentProfileType, nil
		case !hasProvisionedDevices && provisionsAllDevices:
			return DeveloperIDProfileType, nil
		case !hasProvisionedDevices && !provisionsAllDevices:
			return AppStoreProfileType, nil
		default:
			return UnknownProfileType, fmt.Errorf("unkown profile type: hasProvisionedDevices: %v, provisionsAllDevices: %v, isMacOS: %v, isIOS: %v", hasProvisionedDevices, provisionsAllDevices, isMacOS, isIOS)
		}
	}

	getTaskAllow, ok := profile.Entitlements.GetBool("get-task-allow")
	if !ok {
		getTaskAllow = false
	}

	switch {
	case hasProvisionedDevices && !provisionsAllDevices && getTaskAllow:
		return DevelopmentProfileType, nil
	case hasProvisionedDevices && !provisionsAllDevices && !getTaskAllow:
		return AdHocProfileType, nil
	case !hasProvisionedDevices && provisionsAllDevices && !getTaskAllow:
		return EnterpriseProfileType, nil
	case !hasProvisionedDevices && !provisionsAllDevices && !getTaskAllow:
		return AppStoreProfileType, nil
	default:
		return UnknownProfileType, fmt.Errorf("unkown profile type: hasProvisionedDevices: %v, provisionsAllDevices: %v, isMacOS: %v, isIOS: %v, getTaskAllow: %v", hasProvisionedDevices, provisionsAllDevices, isMacOS, isIOS, getTaskAllow)
	}
}

// profileTypesToListingTypes maps profile type and platform to the type and platform should be used when listing profiles.
func profileTypesToListingTypes(profileType ProfileType, profilePlatform profileutil.ProfileType) (ProfileListingType, ProfileListingPlatform, error) {
	mappedPlatform := IOSListingPlatform
	if profilePlatform == profileutil.ProfileTypeMacOs {
		mappedPlatform = MacOSListingPlatform
	}

	var mappedType ProfileListingType
	switch profileType {
	case DevelopmentProfileType:
		if profilePlatform == profileutil.ProfileTypeTvOs {
			mappedType = TVOSDevelopmentListingType
		} else {
			mappedType = DevelopmentListingType
		}
	case AdHocProfileType:
		if profilePlatform == profileutil.ProfileTypeTvOs {
			mappedType = TVOSAdHocListingType
		} else {
			mappedType = AdHocListingType
		}
	case AppStoreProfileType:
		if profilePlatform == profileutil.ProfileTypeTvOs {
			mappedType = TVOSDAppStoreListingType
		} else {
			mappedType = AppStoreListingType
		}
	case EnterpriseProfileType:
		if profilePlatform == profileutil.ProfileTypeTvOs {
			mappedType = TVOSEnterpriseListingType
		} else {
			mappedType = EnterpriseListingType
		}
	case DeveloperIDProfileType:
		mappedType = DeveloperIDApplicationListingType
	default:
		return UnknownProfileListingType, mappedPlatform, fmt.Errorf("unkown profile type: %s", profileType)
	}

	return mappedType, mappedPlatform, nil
}
