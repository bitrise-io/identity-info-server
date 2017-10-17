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

	"github.com/stretchr/testify/require"
)

type TestResponseModel struct {
	Message string `json:"message"`
	Error   string `json:"error"`
}

func TestEndpoints(t *testing.T) {
	config, err := NewConfig()
	require.NoError(t, err)

	testProfilePath := os.Getenv("TEST_PROFILE_PATH")
	test1CertificatePath := os.Getenv("TEST1_CERTIFICATE_PATH")
	test1CertificatePassword := os.Getenv("TEST1_CERTIFICATE_PASSWORD")
	test2CertificatePath := os.Getenv("TEST2_CERTIFICATE_PATH")
	test2CertificatePassword := os.Getenv("TEST2_CERTIFICATE_PASSWORD")
	testURLProfilePath := os.Getenv("TESTURL_PROFILE_URL")
	testURLCertificatePath := os.Getenv("TESTURL_CERTIFICATE_URL")
	testURLCertificatePassword := os.Getenv("TESTURL_CERTIFICATE_PASSWORD")

	//start server locally
	go main()
	time.Sleep(5 * time.Second)

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
		encryptedFileData, err := encrypt([]byte(testURLProfilePath), []byte(config.Secret))
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

	t.Log("/certificate - without password")
	{
		fileData, err := ioutil.ReadFile(test1CertificatePath)
		require.NoError(t, err)

		encryptedFileData, err := encrypt(fileData, []byte(config.Secret))
		require.NoError(t, err)

		reqModel := RequestModel{
			Key:  []byte(test1CertificatePassword),
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

	t.Log("/certificate - without password from URL")
	{
		encryptedFileData, err := encrypt([]byte(testURLCertificatePath), []byte(config.Secret))
		require.NoError(t, err)

		reqModel := RequestModel{
			Key:  []byte(testURLCertificatePassword),
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
		fileData, err := ioutil.ReadFile(test2CertificatePath)
		require.NoError(t, err)

		encryptedFileData, err := encrypt(fileData, []byte(config.Secret))
		require.NoError(t, err)
		encryptedPW, err := encrypt([]byte(test2CertificatePassword), []byte(config.Secret))
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
		fileData, err := ioutil.ReadFile(test2CertificatePath)
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
		fileData, err := ioutil.ReadFile(test2CertificatePath)
		require.NoError(t, err)

		encryptedFileData, err := encrypt(fileData, []byte(config.Secret))
		require.NoError(t, err)

		reqModel := RequestModel{
			Key:  []byte(test2CertificatePassword),
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
		fileData, err := ioutil.ReadFile(test2CertificatePath)
		require.NoError(t, err)

		encryptedFileData, err := encrypt(fileData, []byte(config.Secret))
		require.NoError(t, err)
		encryptedPW, err := encrypt([]byte(test2CertificatePassword), []byte("wrong6Key-32Characters1234567890"))
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
