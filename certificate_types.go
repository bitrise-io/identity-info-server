package main

import (
	"strings"

	"github.com/bitrise-io/go-xcode/certificateutil"
)

// CertificateListingType ...
type CertificateListingType string

// CertificateListingTypes ...
const (
	AppleDevelopmentCertificateListingType  CertificateListingType = "Development"
	AppleDistributionCertificateListingType CertificateListingType = "Distribution"

	iPhoneDeveloperCertificateListingType    CertificateListingType = "iOS Development"
	iPhoneDistributionCertificateListingType CertificateListingType = "iOS Distribution"

	MacDeveloperCertificateListingType                      CertificateListingType = "Mac Development"
	ThirdPartyMacDeveloperApplicationCertificateListingType CertificateListingType = "Mac App Distribution"
	ThirdPartyMacDeveloperInstallerCertificateListingType   CertificateListingType = "Mac Installer Distribution"
	DeveloperIDApplicationCertificateListingType            CertificateListingType = "Developer ID Application"
	DeveloperIDInstallerCertificateListingType              CertificateListingType = "Developer ID Installer"
)

// CertificateListingPlatform ...
type CertificateListingPlatform string

// CertificateListingPlatforms ...
const (
	IOSCertificateListingPlatform   CertificateListingPlatform = "iOS"
	MacOSCertificateListingPlatform CertificateListingPlatform = "macOS"
	AllCertificateListingPlatform   CertificateListingPlatform = "all"
)

// CertificateType ...
type CertificateType string

// CertificateType ...
const (
	AppleDevelopment  CertificateType = "Apple Development"
	AppleDistribution CertificateType = "Apple Distribution"

	iPhoneDeveloper    CertificateType = "iPhone Developer"
	iPhoneDistribution CertificateType = "iPhone Distribution"

	MacDeveloper                      CertificateType = "Mac Developer"
	ThirdPartyMacDeveloperApplication CertificateType = "3rd Party Mac Developer Application"
	ThirdPartyMacDeveloperInstaller   CertificateType = "3rd Party Mac Developer Installer"
	DeveloperIDApplication            CertificateType = "Developer ID Application"
	DeveloperIDInstaller              CertificateType = "Developer ID Installer"
)

var knownSoftwareCertificateTypes = map[CertificateType]bool{
	AppleDevelopment:                  true,
	AppleDistribution:                 true,
	iPhoneDeveloper:                   true,
	iPhoneDistribution:                true,
	MacDeveloper:                      true,
	ThirdPartyMacDeveloperApplication: true,
	ThirdPartyMacDeveloperInstaller:   true,
	DeveloperIDApplication:            true,
	DeveloperIDInstaller:              true,
}

func certificateType(cert certificateutil.CertificateInfoModel) CertificateType {
	split := strings.Split(cert.CommonName, ":")
	if len(split) < 2 {
		// TODO: this shouldn't happen
		return ""
	}

	typeFromName := split[0]
	ok := knownSoftwareCertificateTypes[CertificateType(typeFromName)]
	if !ok {
		// TODO: this should mean a Certificate for services (like Pass Type ID Certificate)
		return CertificateType("")
	}

	return CertificateType(typeFromName)
}

func certificatesTypeToListingTypes(certificateType CertificateType) (CertificateListingType, CertificateListingPlatform) {
	switch certificateType {
	case AppleDevelopment:
		return AppleDevelopmentCertificateListingType, AllCertificateListingPlatform
	case AppleDistribution:
		return AppleDistributionCertificateListingType, AllCertificateListingPlatform
	case iPhoneDeveloper:
		return iPhoneDeveloperCertificateListingType, IOSCertificateListingPlatform
	case iPhoneDistribution:
		return iPhoneDistributionCertificateListingType, IOSCertificateListingPlatform
	case MacDeveloper:
		return MacDeveloperCertificateListingType, MacOSCertificateListingPlatform
	case ThirdPartyMacDeveloperApplication:
		return ThirdPartyMacDeveloperApplicationCertificateListingType, MacOSCertificateListingPlatform
	case ThirdPartyMacDeveloperInstaller:
		return ThirdPartyMacDeveloperInstallerCertificateListingType, MacOSCertificateListingPlatform
	case DeveloperIDApplication:
		return DeveloperIDApplicationCertificateListingType, MacOSCertificateListingPlatform
	case DeveloperIDInstaller:
		return DeveloperIDInstallerCertificateListingType, MacOSCertificateListingPlatform
	default:
		// TODO: this shouldn't happen
		return "", ""
	}
}
