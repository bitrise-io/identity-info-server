package main

import "github.com/bitrise-io/go-xcode/profileutil"

type ProfileType string

const (
	Development ProfileType = "Development"
	AdHoc       ProfileType = "Ad hoc"
	AppStore    ProfileType = "App Store"
	DeveloperID ProfileType = "Developer ID"
	Enterprise  ProfileType = "Enterprise"
)

// getProfileType returns the type (ProfileType) based on the provided provisioning profile content.
func getProfileType(profile profileutil.ProvisioningProfileInfoModel) ProfileType {
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
			return Development
		case !hasProvisionedDevices && provisionsAllDevices:
			return DeveloperID
		case !hasProvisionedDevices && !provisionsAllDevices:
			return AppStore
		default:
			// TODO: this shouldn't happen
			return Development
		}
	}

	getTaskAllow, ok := profile.Entitlements.GetBool("get-task-allow")
	if !ok {
		getTaskAllow = false
	}

	switch {
	case hasProvisionedDevices && !provisionsAllDevices && getTaskAllow:
		return Development
	case hasProvisionedDevices && !provisionsAllDevices && !getTaskAllow:
		return AdHoc
	case !hasProvisionedDevices && provisionsAllDevices && !getTaskAllow:
		return Enterprise
	case !hasProvisionedDevices && !provisionsAllDevices && !getTaskAllow:
		return AppStore
	default:
		// TODO: this shouldn't happen
		return Development
	}
}

// profileTypesToListingTypes maps profile type and platform to the type and platform should be used when listing profiles.
func profileTypesToListingTypes(profileType ProfileType, profilePlatform profileutil.ProfileType) (ProfileListingType, ProfileListingPlatform) {
	mappedPlatform := IOSListingPlatform
	if profilePlatform == profileutil.ProfileTypeMacOs {
		mappedPlatform = MacOSListingPlatform
	}

	var mappedType ProfileListingType
	switch profileType {
	case Development:
		if profilePlatform == profileutil.ProfileTypeTvOs {
			mappedType = TVOSDevelopmentListingType
		} else {
			mappedType = DevelopmentListingType
		}
	case AdHoc:
		if profilePlatform == profileutil.ProfileTypeTvOs {
			mappedType = TVOSAdHocListingType
		} else {
			mappedType = AdHocListingType
		}
	case AppStore:
		if profilePlatform == profileutil.ProfileTypeTvOs {
			mappedType = TVOSDAppStoreListingType
		} else {
			mappedType = AppStoreListingType
		}
	case Enterprise:
		if profilePlatform == profileutil.ProfileTypeTvOs {
			mappedType = TVOSEnterpriseListingType
		} else {
			mappedType = EnterpriseListingType
		}
	case DeveloperID:
		mappedType = DeveloperIDApplicationListingType
	default:
		// TODO: this shouldn't happen
		if profilePlatform == profileutil.ProfileTypeTvOs {
			mappedType = TVOSDevelopmentListingType
		} else {
			mappedType = DevelopmentListingType
		}
	}

	return mappedType, mappedPlatform
}
