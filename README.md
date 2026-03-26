# identity-info

Returns parsed JSON of `*.mobileprovision`, `*.p12`, and Android keystores (JKS and PKCS12).

## Server Configuration

1. Export `PORT` environment variables.

```
export PORT=3000
```

2. Run the server

```
go run main.go
```

## Test Configuration

1. After **Server Configuration** export the following environment variables

```
export TEST_PROFILE_PATH="/path/to/the/profile.mobileprovision"
export TEST_NO_PW_CERTIFICATE_PATH="/path/to/the/password/less/cert.p12"
export TEST_CERTIFICATE_PATH="/path/to/the/cert/with/password.p12"
export TEST_CERTIFICATE_PASSWORD="my_cert_password"
export TEST_PROFILE_URL="http://url/to/the/profile.mobileprovision"
export TEST_CERTIFICATE_URL="http://url/to/the/cert/with/password.p12"
export TEST_CERTIFICATE_URL_PASSWORD="my_cert_password"
```

2. Run the test

```
go test ./...
```

## Usage

### **POST /certificate**

>Request body: both key and data are in base64 format. Leave empty or do not include `key` if no any.
```
{
    "key" : "FGZ...fKvus6/ee=",
    "data" : "5SN...jDHboV/zs="
}
```

>Response body: the parsed certificate in JSON format

For example:

>curl -X POST -d "{\"data\":\"$(base64 /path/to/cert.p12)\",\"key\":\"$(echo 'cert_pass' | base64 -)\"}" http://localhost:$PORT/certificate

>curl -X POST -d "{\"data\":\"$(echo 'http://url.to/the/cert.p12' | base64 -)\",\"key\":\"$(echo 'cert_pass' | base64 -)\"}" http://localhost:$PORT/certificate

### **POST /profile**

>Request body: data is in base64 format.
```
{
    "data" : "5SN...jDHboV/zs="
}
```

>Response body: the parsed profile in JSON format

For example:

>curl -X POST -d "{\"data\":\"$(base64 /path/to/profile.mobileprovision)\"}" http://localhost:$PORT/profile

>curl -X POST -d "{\"data\":\"$(echo 'http://url.to/the/profile.mobileprovision' | base64 -)\"}" http://localhost:$PORT/profile

### **POST /keystore**

Parses an Android keystore file (JKS or PKCS12) and returns certificate details. All request fields are base64-encoded. The `data` field may contain the raw file bytes or a URL to the file.

>Request body:
```json
{
    "data": "<base64-encoded keystore file content or URL>",
    "key": "<base64-encoded keystore password>",
    "alias": "<base64-encoded key alias>",
    "key_password": "<base64-encoded key password>"
}
```

>Response body on success:
```json
{
    "first_and_last_name": "Android Debug",
    "organizational_unit": "Android",
    "organization": "Google",
    "city_or_locality": "Mountain View",
    "state_or_province": "California",
    "country_code": "US",
    "valid_from": "2022-06-22 09:57:21 +0000 UTC",
    "valid_until": "2052-06-14 09:57:21 +0000 UTC"
}
```

Fields with empty values are omitted from the response.

>Response body on error (HTTP 400):
```json
{
    "error": "<error message>",
    "error_type": "<error type>"
}
```

| `error_type` | Meaning |
|---|---|
| `invalid_file` | The file is not a valid JKS or PKCS12 keystore |
| `invalid_password` | The keystore password is incorrect |
| `invalid_alias` | The key alias is incorrect or not found in the keystore |
| `invalid_key_password` | The key password is incorrect |

>curl examples:

>curl -X POST -d "{\"data\":\"$(base64 /path/to/keystore.jks)\",\"key\":\"$(echo 'keystore_pass' | base64 -)\",\"alias\":\"$(echo 'my_alias' | base64 -)\",\"key_password\":\"$(echo 'key_pass' | base64 -)\"}" http://localhost:$PORT/keystore