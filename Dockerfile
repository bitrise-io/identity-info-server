FROM bitriseio/docker-bitrise-base

# envs
ENV PROJ_NAME=identity-info-server
ENV BITRISE_SOURCE_DIR="$GOPATH/src/github.com/bitrise-io/$PROJ_NAME"

RUN mkdir -p $BITRISE_SOURCE_DIR
WORKDIR $BITRISE_SOURCE_DIR

ADD . .

EXPOSE 3000

CMD go run main.go
