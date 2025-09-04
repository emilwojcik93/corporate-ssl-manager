#!/bin/bash
# Docker Corporate Certificate Wrapper
# Automatically injects Thomson Reuters corporate certificates into Docker containers
# Usage: docker-corp run [docker-options] image [command]

DOCKER_CERT_PATH="$HOME/.docker/ca-bundle.crt"

if [[ "$1" == "run" ]]; then
    shift
    exec /usr/bin/docker run \
        -v "$DOCKER_CERT_PATH:/etc/ssl/certs/ca-certificates.crt:ro" \
        -v "$DOCKER_CERT_PATH:/etc/pki/tls/certs/ca-bundle.crt:ro" \
        -v "$DOCKER_CERT_PATH:/usr/local/share/ca-certificates/corporate.crt:ro" \
        -e SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
        -e CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
        -e REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
        -e NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt \
        "$@"
else
    exec /usr/bin/docker "$@"
fi
