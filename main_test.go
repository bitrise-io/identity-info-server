package main

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	testingPort := os.Getenv("PORT")

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
		resp, err := http.Get("http://localhost:" + testingPort)
		require.NoError(t, err)

		testResp := TestResponseModel{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&testResp))

		require.Empty(t, testResp.Error)
		require.Equal(t, "Welcome!", testResp.Message)
	}

	t.Log("/profile from file")
	{
		fileData, err := ioutil.ReadFile(testProfilePath)
		require.NoError(t, err)

		reqModel := RequestModel{
			Key:  []byte{},
			Data: fileData,
		}
		b := new(bytes.Buffer)
		err = json.NewEncoder(b).Encode(&reqModel)
		require.NoError(t, err)

		req, err := http.NewRequest("POST", "http://localhost:"+testingPort+"/profile", bytes.NewReader(b.Bytes()))
		resp, err := (&http.Client{}).Do(req)
		require.NoError(t, err)

		//bodyBytes, err := ioutil.ReadAll(resp.Body)
		require.NoError(t, err)
		//fmt.Printf(string(bodyBytes))

		require.Equal(t, 200, resp.StatusCode)
	}

	t.Log("/profile from URL")
	{
		reqModel := RequestModel{
			Key:  []byte{},
			Data: []byte(testProfileURL),
		}
		b := new(bytes.Buffer)
		err := json.NewEncoder(b).Encode(&reqModel)
		require.NoError(t, err)

		req, err := http.NewRequest("POST", "http://localhost:"+testingPort+"/profile", bytes.NewReader(b.Bytes()))
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

		reqModel := RequestModel{
			Key:  []byte(""),
			Data: fileData,
		}
		b := new(bytes.Buffer)
		err = json.NewEncoder(b).Encode(&reqModel)
		require.NoError(t, err)

		req, err := http.NewRequest("POST", "http://localhost:"+testingPort+"/certificate", bytes.NewReader(b.Bytes()))
		resp, err := (&http.Client{}).Do(req)
		require.NoError(t, err)

		//bodyBytes, err := ioutil.ReadAll(resp.Body)
		require.NoError(t, err)
		//fmt.Printf(string(bodyBytes))

		require.Equal(t, 200, resp.StatusCode)
	}

	t.Log("/certificate - with password from URL")
	{
		reqModel := RequestModel{
			Key:  []byte(testCertificateURLPassword),
			Data: []byte(testCertificateURL),
		}
		b := new(bytes.Buffer)
		err := json.NewEncoder(b).Encode(&reqModel)
		require.NoError(t, err)

		req, err := http.NewRequest("POST", "http://localhost:"+testingPort+"/certificate", bytes.NewReader(b.Bytes()))
		resp, err := (&http.Client{}).Do(req)
		require.NoError(t, err)

		//bodyBytes, err := ioutil.ReadAll(resp.Body)
		require.NoError(t, err)
		//fmt.Printf(string(bodyBytes))

		require.Equal(t, 200, resp.StatusCode)
	}

	t.Log("/certificate - with password")
	{
		fileData, err := ioutil.ReadFile(testCertificatePath)
		require.NoError(t, err)

		reqModel := RequestModel{
			Key:  []byte(testCertificatePassword),
			Data: fileData,
		}
		b := new(bytes.Buffer)
		err = json.NewEncoder(b).Encode(&reqModel)
		require.NoError(t, err)

		req, err := http.NewRequest("POST", "http://localhost:"+testingPort+"/certificate", bytes.NewReader(b.Bytes()))
		resp, err := (&http.Client{}).Do(req)
		require.NoError(t, err)

		//bodyBytes, err := ioutil.ReadAll(resp.Body)
		require.NoError(t, err)
		//fmt.Printf(string(bodyBytes))

		require.Equal(t, 200, resp.StatusCode)
	}

	t.Log("/certificate - with WRONG password")
	{
		fileData, err := ioutil.ReadFile(testCertificatePath)
		require.NoError(t, err)

		reqModel := RequestModel{
			Key:  []byte("WRONGPW"),
			Data: fileData,
		}

		b := new(bytes.Buffer)
		err = json.NewEncoder(b).Encode(&reqModel)
		require.NoError(t, err)

		req, err := http.NewRequest("POST", "http://localhost:"+testingPort+"/certificate", bytes.NewReader(b.Bytes()))
		resp, err := (&http.Client{}).Do(req)
		require.NoError(t, err)

		//bodyBytes, err := ioutil.ReadAll(resp.Body)
		require.NoError(t, err)
		//fmt.Printf(string(bodyBytes))

		require.Equal(t, 400, resp.StatusCode)
	}
}
