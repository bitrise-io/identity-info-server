package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/bitrise-io/go-utils/log"
	"github.com/stretchr/testify/require"
)

type TestResponseModel struct {
	Message string `json:"message"`
	Error   string `json:"error"`
}

func TestEndpoints(t *testing.T) {
	config, err := NewConfig()
	require.NoError(t, err)

	//these envs are required for testing only
	testProfilePath := os.Getenv("TEST_PROFILE_PATH")
	testNoPWCertificatePath := os.Getenv("TEST_NO_PW_CERTIFICATE_PATH")
	testCertificatePath := os.Getenv("TEST_CERTIFICATE_PATH")
	testCertificatePassword := os.Getenv("TEST_CERTIFICATE_PASSWORD")
	testProfileURL := os.Getenv("TEST_PROFILE_URL")
	testCertificateURL := os.Getenv("TEST_CERTIFICATE_URL")
	testCertificateURLPassword := os.Getenv("TEST_CERTIFICATE_URL_PASSWORD")

	//start server locally
	go main()
	time.Sleep(5 * time.Second)

	// test endpoints
	t.Log("/")
	{
		resp, err := http.Get("http://localhost:" + config.Port)
		require.NoError(t, err)

		testResp := TestResponseModel{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&testResp))

		require.Empty(t, testResp.Error)
		require.Equal(t, "Welcome!", testResp.Message)
	}

	t.Log("/profile")
	{
		fileData, err := ioutil.ReadFile(testProfilePath)
		require.NoError(t, err)

		encryptedFileData, err := encrypt(fileData, []byte(config.Secret))
		require.NoError(t, err)

		reqModel := RequestModel{
			Key:  []byte{},
			Data: encryptedFileData,
		}
		b := new(bytes.Buffer)
		err = json.NewEncoder(b).Encode(&reqModel)
		require.NoError(t, err)

		req, err := http.NewRequest("POST", "http://localhost:"+config.Port+"/profile", bytes.NewReader(b.Bytes()))
		resp, err := (&http.Client{}).Do(req)
		require.NoError(t, err)

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		require.NoError(t, err)
		fmt.Printf(string(bodyBytes))

		require.Equal(t, 200, resp.StatusCode)
	}

	t.Log("/profile from URL")
	{
		encryptedFileData, err := encrypt([]byte(testProfileURL), []byte(config.Secret))
		require.NoError(t, err)

		reqModel := RequestModel{
			Key:  []byte{},
			Data: encryptedFileData,
		}
		b := new(bytes.Buffer)
		err = json.NewEncoder(b).Encode(&reqModel)
		require.NoError(t, err)

		log.Donef("%s", string(b.Bytes()))
		require.FailNow(t, "ok")

		req, err := http.NewRequest("POST", "http://localhost:"+config.Port+"/profile", bytes.NewReader(b.Bytes()))
		resp, err := (&http.Client{}).Do(req)
		require.NoError(t, err)

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		require.NoError(t, err)
		fmt.Printf(string(bodyBytes))

		require.Equal(t, 200, resp.StatusCode)
	}

	t.Log("/certificate - without password")
	{
		fileData, err := ioutil.ReadFile(testNoPWCertificatePath)
		require.NoError(t, err)

		encryptedFileData, err := encrypt(fileData, []byte(config.Secret))
		require.NoError(t, err)

		reqModel := RequestModel{
			Key:  []byte(""),
			Data: encryptedFileData,
		}
		b := new(bytes.Buffer)
		err = json.NewEncoder(b).Encode(&reqModel)
		require.NoError(t, err)

		req, err := http.NewRequest("POST", "http://localhost:"+config.Port+"/certificate", bytes.NewReader(b.Bytes()))
		resp, err := (&http.Client{}).Do(req)
		require.NoError(t, err)

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		require.NoError(t, err)
		fmt.Printf(string(bodyBytes))

		require.Equal(t, 200, resp.StatusCode)
	}

	t.Log("/certificate - with password from URL")
	{
		encryptedFileData, err := encrypt([]byte(testCertificateURL), []byte(config.Secret))
		require.NoError(t, err)

		encryptedPasswordData, err := encrypt([]byte(testCertificateURLPassword), []byte(config.Secret))
		require.NoError(t, err)

		reqModel := RequestModel{
			Key:  encryptedPasswordData,
			Data: encryptedFileData,
		}
		b := new(bytes.Buffer)
		err = json.NewEncoder(b).Encode(&reqModel)
		require.NoError(t, err)

		req, err := http.NewRequest("POST", "http://localhost:"+config.Port+"/certificate", bytes.NewReader(b.Bytes()))
		resp, err := (&http.Client{}).Do(req)
		require.NoError(t, err)

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		require.NoError(t, err)
		fmt.Printf(string(bodyBytes))

		require.Equal(t, 200, resp.StatusCode)
	}

	t.Log("/certificate - with password")
	{
		fileData, err := ioutil.ReadFile(testCertificatePath)
		require.NoError(t, err)

		encryptedFileData, err := encrypt(fileData, []byte(config.Secret))
		require.NoError(t, err)
		encryptedPW, err := encrypt([]byte(testCertificatePassword), []byte(config.Secret))
		require.NoError(t, err)

		reqModel := RequestModel{
			Key:  encryptedPW,
			Data: encryptedFileData,
		}
		b := new(bytes.Buffer)
		err = json.NewEncoder(b).Encode(&reqModel)
		require.NoError(t, err)

		req, err := http.NewRequest("POST", "http://localhost:"+config.Port+"/certificate", bytes.NewReader(b.Bytes()))
		resp, err := (&http.Client{}).Do(req)
		require.NoError(t, err)

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		require.NoError(t, err)
		fmt.Printf(string(bodyBytes))

		require.Equal(t, 200, resp.StatusCode)
	}

	t.Log("/certificate - with WRONG password")
	{
		fileData, err := ioutil.ReadFile(testCertificatePath)
		require.NoError(t, err)

		encryptedFileData, err := encrypt(fileData, []byte(config.Secret))
		require.NoError(t, err)
		encryptedPW, err := encrypt([]byte("WRONGPW"), []byte(config.Secret))
		require.NoError(t, err)

		reqModel := RequestModel{
			Key:  encryptedPW,
			Data: encryptedFileData,
		}
		b := new(bytes.Buffer)
		err = json.NewEncoder(b).Encode(&reqModel)
		require.NoError(t, err)

		req, err := http.NewRequest("POST", "http://localhost:"+config.Port+"/certificate", bytes.NewReader(b.Bytes()))
		resp, err := (&http.Client{}).Do(req)
		require.NoError(t, err)

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		require.NoError(t, err)
		fmt.Printf(string(bodyBytes))

		require.Equal(t, 400, resp.StatusCode)
	}

	t.Log("/certificate - with UNENCRYPTED password")
	{
		fileData, err := ioutil.ReadFile(testCertificatePath)
		require.NoError(t, err)

		encryptedFileData, err := encrypt(fileData, []byte(config.Secret))
		require.NoError(t, err)

		reqModel := RequestModel{
			Key:  []byte(testCertificatePassword),
			Data: encryptedFileData,
		}
		b := new(bytes.Buffer)
		err = json.NewEncoder(b).Encode(&reqModel)
		require.NoError(t, err)

		req, err := http.NewRequest("POST", "http://localhost:"+config.Port+"/certificate", bytes.NewReader(b.Bytes()))
		resp, err := (&http.Client{}).Do(req)
		require.NoError(t, err)

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		require.NoError(t, err)
		fmt.Printf(string(bodyBytes))

		require.Equal(t, 400, resp.StatusCode)
	}

	t.Log("/certificate - with mismatched encryption password")
	{
		fileData, err := ioutil.ReadFile(testCertificatePath)
		require.NoError(t, err)

		encryptedFileData, err := encrypt(fileData, []byte(config.Secret))
		require.NoError(t, err)
		encryptedPW, err := encrypt([]byte(testCertificatePassword), []byte("wrong6Key-32Characters1234567890"))
		require.NoError(t, err)

		reqModel := RequestModel{
			Key:  encryptedPW,
			Data: encryptedFileData,
		}
		b := new(bytes.Buffer)
		err = json.NewEncoder(b).Encode(&reqModel)
		require.NoError(t, err)

		req, err := http.NewRequest("POST", "http://localhost:"+config.Port+"/certificate", bytes.NewReader(b.Bytes()))
		resp, err := (&http.Client{}).Do(req)
		require.NoError(t, err)

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		require.NoError(t, err)
		fmt.Printf(string(bodyBytes))

		require.Equal(t, 400, resp.StatusCode)
	}
}

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}
