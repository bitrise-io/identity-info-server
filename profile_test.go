package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bitrise-io/go-xcode/profileutil"
	"github.com/fullsailor/pkcs7"
	"github.com/stretchr/testify/require"
)

func TestProfileInfoModel(t *testing.T) {
	tests := []struct {
		name         string
		pth          string
		wantType     ProfileListingType
		wantPlatform ProfileListingPlatform
	}{
		{
			name:         "iOS App Development",
			pth:          "iOS_App_Development.plist",
			wantType:     DevelopmentListingType,
			wantPlatform: IOSListingPlatform,
		},
		{
			name:         "iOS App Development with certificates for Xcode 11 and later",
			pth:          "iOS_App_Development_with_new_cert.plist",
			wantType:     DevelopmentListingType,
			wantPlatform: IOSListingPlatform,
		},
		{
			name:         "iOS App Development with Mac devices",
			pth:          "iOS_App_Development_with_Mac.plist",
			wantType:     DevelopmentListingType,
			wantPlatform: IOSListingPlatform,
		},
		{
			name:         "tvOS App Development",
			pth:          "tvOS_App_Development.plist",
			wantType:     TVOSDevelopmentListingType,
			wantPlatform: IOSListingPlatform,
		},
		{
			name:         "macOS App Development type Mac",
			pth:          "macOS_App_Development_type_Mac.plist",
			wantType:     DevelopmentListingType,
			wantPlatform: MacOSListingPlatform,
		},
		{
			name:         "macOS App Development type Mac Catalyst",
			pth:          "macOS_App_Development_type_Mac_Catalyst.plist",
			wantType:     DevelopmentListingType,
			wantPlatform: MacOSListingPlatform,
		},
		{
			name:         "Ad Hoc",
			pth:          "Ad_Hoc.plist",
			wantType:     AdHocListingType,
			wantPlatform: IOSListingPlatform,
		},
		{
			name:         "tvOS Ad Hoc",
			pth:          "tvOS_Ad_Hoc.plist",
			wantType:     TVOSAdHocListingType,
			wantPlatform: IOSListingPlatform,
		},
		{
			name:         "App Store",
			pth:          "App_Store.plist",
			wantType:     AppStoreListingType,
			wantPlatform: IOSListingPlatform,
		},
		{
			name:         "tvOS App Store",
			pth:          "tvOS_App_Store.plist",
			wantType:     TVOSDAppStoreListingType,
			wantPlatform: IOSListingPlatform,
		},
		{
			name:         "Mac App Store type Mac",
			pth:          "Mac_App_Store_type_Mac.plist",
			wantType:     AppStoreListingType,
			wantPlatform: MacOSListingPlatform,
		},
		{
			name:         "Mac App Store type Mac Catalyst",
			pth:          "Mac_App_Store_type_Mac_Catalyst.plist",
			wantType:     AppStoreListingType,
			wantPlatform: MacOSListingPlatform,
		},
		{
			name:         "Developer ID Application",
			pth:          "Developer_ID_Application.plist",
			wantType:     DeveloperIDApplicationListingType,
			wantPlatform: MacOSListingPlatform,
		},
		{
			name:         "DriverKit App Development",
			pth:          "DriverKit_App_Development.plist",
			wantType:     DevelopmentListingType,
			wantPlatform: MacOSListingPlatform,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(filepath.Join("testdata", "plist", tt.pth))
			require.NoError(t, err)

			b, err := io.ReadAll(f)
			require.NoError(t, err)

			pkcs7Profile := pkcs7.PKCS7{}
			pkcs7Profile.Content = b

			profile, err := profileutil.NewProvisioningProfileInfo(pkcs7Profile)
			require.NotNil(t, profile)

			infoModel := profileToProfileModel(profile)
			require.Equal(t, tt.wantType, infoModel.ListingType)
			require.Equal(t, tt.wantPlatform, infoModel.ListingPlatform)
		})
	}
}

func platformToType(platform string) profileutil.ProfileType {
	return profileutil.ProfileType(strings.ToLower(platform))
}
