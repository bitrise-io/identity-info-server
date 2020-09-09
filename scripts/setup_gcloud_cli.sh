#!/usr/bin/env bash

if [[ ! -f /usr/local/google-cloud-sdk/bin/gcloud ]]; then
    GCLOUD_INSTALL=google-cloud-sdk-293.0.0-linux-x86_64.tar.gz

    # download binary
    curl -s https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/$GCLOUD_INSTALL -o $GCLOUD_INSTALL

    # extract it
    tar -C /usr/local -xzf $GCLOUD_INSTALL
fi

export PATH=/usr/local/google-cloud-sdk/bin:$PATH

# authenticate with service user
gcloud auth activate-service-account $GCLOUD_USER --key-file=key_auth.json

gcloud config set project $GCLOUD_PROJECT

# authenticate docker
gcloud auth print-access-token | docker login -u oauth2accesstoken --password-stdin https://gcr.io

# add PATH to subsequent steps
envman add --key PATH --value "$PATH"
