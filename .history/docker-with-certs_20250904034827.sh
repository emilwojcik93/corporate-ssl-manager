#!/bin/bash
# Docker wrapper that automatically mounts corporate certificates
if [[ "$1" == "run" ]]; then
    # Extract the original docker run arguments
    shift
    exec docker run \
        -v "$HOME/.docker/ca-bundle.crt:/etc/ssl/certs/ca-certificates.crt:ro" \
        -v "$HOME/.docker/ca-bundle.crt:/etc/pki/tls/certs/ca-bundle.crt:ro" \
        -e SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
        -e CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
        -e REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
        "$@"
else
    # Pass through other docker commands
    exec docker "$@"
fi
