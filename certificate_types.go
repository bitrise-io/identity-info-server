package main

import (
	"fmt"
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
	UnknownCertificateListingType                           CertificateListingType = "unknown"
)

// CertificateListingPlatform ...
type CertificateListingPlatform string

// CertificateListingPlatforms ...
const (
	IOSCertificateListingPlatform     CertificateListingPlatform = "iOS"
	MacOSCertificateListingPlatform   CertificateListingPlatform = "macOS"
	AllCertificateListingPlatform     CertificateListingPlatform = "all"
	UnknownCertificateListingPlatform CertificateListingPlatform = "unknown"
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
	UnknownCertificateType            CertificateType = "unknown"
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

func certificateType(cert certificateutil.CertificateInfoModel) (CertificateType, error) {
	split := strings.Split(cert.CommonName, ":")
	if len(split) < 2 {
		return UnknownCertificateType, fmt.Errorf("couldn't parse certificate type from common name: %s", cert.CommonName)
	}

	typeFromName := split[0]
	//ok := knownSoftwareCertificateTypes[CertificateType(typeFromName)]
	//if !ok {
	//	// TODO: this should mean a Certificate for services (like Pass Type ID Certificate)
	//	return typeFromName, nil
	//}

	return CertificateType(typeFromName), nil
}

func certificatesTypeToListingTypes(certificateType CertificateType) (CertificateListingType, CertificateListingPlatform, error) {
	switch certificateType {
	case AppleDevelopment:
		return AppleDevelopmentCertificateListingType, AllCertificateListingPlatform, nil
	case AppleDistribution:
		return AppleDistributionCertificateListingType, AllCertificateListingPlatform, nil
	case iPhoneDeveloper:
		return iPhoneDeveloperCertificateListingType, IOSCertificateListingPlatform, nil
	case iPhoneDistribution:
		return iPhoneDistributionCertificateListingType, IOSCertificateListingPlatform, nil
	case MacDeveloper:
		return MacDeveloperCertificateListingType, MacOSCertificateListingPlatform, nil
	case ThirdPartyMacDeveloperApplication:
		return ThirdPartyMacDeveloperApplicationCertificateListingType, MacOSCertificateListingPlatform, nil
	case ThirdPartyMacDeveloperInstaller:
		return ThirdPartyMacDeveloperInstallerCertificateListingType, MacOSCertificateListingPlatform, nil
	case DeveloperIDApplication:
		return DeveloperIDApplicationCertificateListingType, MacOSCertificateListingPlatform, nil
	case DeveloperIDInstaller:
		return DeveloperIDInstallerCertificateListingType, MacOSCertificateListingPlatform, nil
	default:
		return CertificateListingType(certificateType), UnknownCertificateListingPlatform, fmt.Errorf("unknown certificate type: %s", certificateType)
	}
}
