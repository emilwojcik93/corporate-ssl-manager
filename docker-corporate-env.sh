# Docker Corporate Certificate Environment
# Thomson Reuters SSL Certificate Configuration for Docker

export DOCKER_CERT_PATH="$HOME/.docker/ca-bundle.crt"

# Docker aliases for corporate environment
alias docker-corp='/usr/local/bin/docker-corp'
alias docker-secure='/usr/local/bin/docker-corp'
alias docker-test='docker-corp run --rm curlimages/curl:latest curl -s -o /dev/null -w "Status: %{http_code}\n"'
alias docker-test-google='docker-test https://google.com'
alias docker-test-github='docker-test https://github.com'
alias docker-test-npmjs='docker-test https://registry.npmjs.org'

# Display status
echo "Docker Corporate SSL Environment Loaded"
echo "Use 'docker-corp' for containers with automatic certificate injection"
echo "Quick tests: docker-test-google, docker-test-github, docker-test-npmjs"
