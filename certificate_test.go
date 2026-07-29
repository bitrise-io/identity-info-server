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

func Test_certsToCertModels_fileSHA256(t *testing.T) {
	notAfter := time.Date(2027, 5, 28, 0, 0, 0, 0, time.UTC)
	serial := big.NewInt(42)

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

	require.NotNil(t, model.FileSHA256)
	require.Equal(t, fileHash, *model.FileSHA256)

	// The existing serial and expiry fields are preserved unchanged; consumers derive any
	// alternative representation (e.g. hex serial) from these on the presentation side.
	require.Equal(t, serial.String(), model.Serial)
	require.Equal(t, notAfter, model.EndDate)
}

func Test_certsToCertModels_nilFileSHA256(t *testing.T) {
	// Certificates embedded in a profile have no backing uploaded file, so file_sha256 is null.
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
