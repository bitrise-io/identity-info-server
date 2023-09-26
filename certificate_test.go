package main

import (
	"crypto/x509"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bitrise-io/go-xcode/certificateutil"
	"github.com/stretchr/testify/require"
)

// TODO: describe how test data can be generated from P12 certificates.
func Test_certsToCertModels(t *testing.T) {
	tests := []struct {
		name         string
		pth          string
		wantType     CertificateListingType
		wantPlatform CertificateListingPlatform
	}{
		{
			name:         "Apple Development",
			pth:          "Apple_Development.json",
			wantType:     AppleDevelopmentCertificateListingType,
			wantPlatform: AllCertificateListingPlatform,
		},
		{
			name:         "Apple Distribution",
			pth:          "Apple_Distribution.json",
			wantType:     AppleDistributionCertificateListingType,
			wantPlatform: AllCertificateListingPlatform,
		},
		{
			name:         "iOS App Development",
			pth:          "iOS_App_Development.json",
			wantType:     iPhoneDeveloperCertificateListingType,
			wantPlatform: IOSCertificateListingPlatform,
		},
		{
			name:         "iOS Distribution",
			pth:          "iOS_Distribution.json",
			wantType:     iPhoneDistributionCertificateListingType,
			wantPlatform: IOSCertificateListingPlatform,
		},
		{
			name:         "Mac Development",
			pth:          "Mac_Development.json",
			wantType:     MacDeveloperCertificateListingType,
			wantPlatform: MacOSCertificateListingPlatform,
		},
		{
			name:         "Mac App Distribution",
			pth:          "Mac_App_Distribution.json",
			wantType:     ThirdPartyMacDeveloperApplicationCertificateListingType,
			wantPlatform: MacOSCertificateListingPlatform,
		},
		{
			name:         "Mac Installer Distribution",
			pth:          "Mac_Installer_Distribution.json",
			wantType:     ThirdPartyMacDeveloperInstallerCertificateListingType,
			wantPlatform: MacOSCertificateListingPlatform,
		},
		{
			name:         "Developer ID Application",
			pth:          "Developer_ID_Application.json",
			wantType:     DeveloperIDApplicationCertificateListingType,
			wantPlatform: MacOSCertificateListingPlatform,
		},
		{
			name:         "Developer ID Installer",
			pth:          "Developer_ID_Installer.json",
			wantType:     DeveloperIDInstallerCertificateListingType,
			wantPlatform: MacOSCertificateListingPlatform,
		},
		{
			name:         "Apple Push Notification service SSL Sandbox",
			pth:          "Apple_Push_Notification_service_SSL_Sandbox.json",
			wantType:     "",
			wantPlatform: "",
		},
		{
			name:         "Pass Type ID Certificate",
			pth:          "Pass_Type_ID_Certificate.json",
			wantType:     "",
			wantPlatform: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(filepath.Join("testdata", "certificates", tt.pth))
			require.NoError(t, err)

			x509Cert := newCertFromJSON(t, f)
			cert := certificateutil.NewCertificateInfo(*x509Cert, nil)
			certModels := certsToCertModels([]certificateutil.CertificateInfoModel{cert})
			certModel := certModels[0]
			require.Equal(t, tt.wantType, certModel.ListingType)
			require.Equal(t, tt.wantPlatform, certModel.ListingPlatform)
		})
	}
}

type TestIssuer struct {
	CommonName                       string
	Organization, OrganizationalUnit []string
}

type TestCertificate struct {
	Subject             TestIssuer
	NotBefore, NotAfter time.Time
	SerialNumber        *big.Int
	Raw                 []byte
}

func newCertFromJSON(t *testing.T, reader io.Reader) *x509.Certificate {
	b, err := io.ReadAll(reader)
	require.NoError(t, err)

	var testCertificate TestCertificate
	err = json.Unmarshal(b, &testCertificate)
	require.NoError(t, err)

	newCert := x509.Certificate{}
	newCert.Subject.CommonName = testCertificate.Subject.CommonName
	newCert.Subject.Organization = testCertificate.Subject.Organization
	newCert.Subject.OrganizationalUnit = testCertificate.Subject.OrganizationalUnit
	newCert.NotAfter = testCertificate.NotAfter
	newCert.NotBefore = testCertificate.NotBefore
	newCert.SerialNumber = testCertificate.SerialNumber
	newCert.Raw = testCertificate.Raw

	return &newCert
}
