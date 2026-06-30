package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bitrise-io/go-xcode/certificateutil"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func Test_certsToCertModels_contentMetadata(t *testing.T) {
	notAfter := time.Date(2027, 5, 28, 0, 0, 0, 0, time.UTC)
	// Serial bytes 0x0A1B2C3D4E5F6071 must render as uppercase, byte-aligned hex.
	serial := new(big.Int).SetBytes([]byte{0x0A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F, 0x60, 0x71})

	x509Cert := x509.Certificate{
		Subject:      pkix.Name{CommonName: "Apple Development: Test User (ABCDE12345)"},
		NotBefore:    notAfter.Add(-24 * time.Hour),
		NotAfter:     notAfter,
		SerialNumber: serial,
	}
	cert := certificateutil.NewCertificateInfo(x509Cert, nil)

	fileHash := "0123456789abcdef"
	s := Service{Logger: log.New()}
	models := s.certsToCertModels([]certificateutil.CertificateInfoModel{cert}, &fileHash)
	require.Len(t, models, 1)
	model := models[0]

	require.NotNil(t, model.CertificateSerial)
	require.Equal(t, "0A1B2C3D4E5F6071", *model.CertificateSerial)

	require.NotNil(t, model.CertificateExpiryDate)
	require.Equal(t, notAfter, *model.CertificateExpiryDate)

	require.NotNil(t, model.FileSHA256)
	require.Equal(t, fileHash, *model.FileSHA256)

	// The existing decimal Serial field must be preserved alongside the new hex field.
	require.Equal(t, serial.String(), model.Serial)
}

func Test_certsToCertModels_nilFileSHA256(t *testing.T) {
	// Certificates embedded in a profile have no backing uploaded file.
	x509Cert := x509.Certificate{
		Subject:      pkix.Name{CommonName: "Apple Development: Test User (ABCDE12345)"},
		NotAfter:     time.Date(2027, 5, 28, 0, 0, 0, 0, time.UTC),
		SerialNumber: big.NewInt(42),
	}
	cert := certificateutil.NewCertificateInfo(x509Cert, nil)

	s := Service{Logger: log.New()}
	models := s.certsToCertModels([]certificateutil.CertificateInfoModel{cert}, nil)
	require.Len(t, models, 1)

	require.Nil(t, models[0].FileSHA256)
	// Serial and expiry are intrinsic to the certificate and still populated.
	require.NotNil(t, models[0].CertificateSerial)
	require.Equal(t, "2A", *models[0].CertificateSerial)
	require.NotNil(t, models[0].CertificateExpiryDate)
}

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
			wantType:     "Apple Sandbox Push Services",
			wantPlatform: "unknown",
		},
		{
			name:         "Pass Type ID Certificate",
			pth:          "Pass_Type_ID_Certificate.json",
			wantType:     "Pass Type ID",
			wantPlatform: "unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(filepath.Join("testdata", "certificates", tt.pth))
			require.NoError(t, err)

			x509Cert := newCertFromJSON(t, f)
			cert := certificateutil.NewCertificateInfo(*x509Cert, nil)
			s := Service{Logger: log.New()}
			certModels := s.certsToCertModels([]certificateutil.CertificateInfoModel{cert}, nil)
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
