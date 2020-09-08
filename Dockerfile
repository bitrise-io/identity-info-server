############################
# STEP 1 build executable binary
############################
FROM golang:alpine AS builder

# Install git (needed for go modules)
# Git is required for fetching the dependencies (git) and certificates
RUN apk update \
     && apk add --no-cache git \
     && apk add --no-cache ca-certificates

WORKDIR /src/analytics
COPY . .

# Using go mod.
# Using go get.
RUN go get -d -v \
    && go mod download \
    && go mod verify

# Build the binary.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '-w -extldflags "-static"' -o /go/bin/identity-info

############################
# STEP 2 build a small image
############################
FROM scratch

COPY --from=builder /go/bin/identity-info /go/bin/identity-info
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Run the binary.
ENTRYPOINT ["/go/bin/identity-info"]