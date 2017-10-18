# identity-info

Returns parsed JSON of *.mobileprovision and *.p12.

## Server Configuration

1. Export `PORT` and `AES256_SECRET_KEY` environment variables.

```
export PORT=3000
export AES256_SECRET_KEY=AES256key-000000000-32characters
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

>Request body: both key and data are AES-256 encrypted with the key: `AES256_SECRET_KEY` and in base64 format. Leave empty or do not include `key` if no any.
```
{
    "key" : "FGZ...fKvus6/ee=",
    "data" : "5SN...jDHboV/zs="
}
```

>Response body: the parsed certificate in JSON format

### **POST /profile**

>Request body: data is AES-256 encrypted with the key: `AES256_SECRET_KEY` and in base64 format.
```
{
    "data" : "5SN...jDHboV/zs="
}
```

>Response body: the parsed profile in JSON format