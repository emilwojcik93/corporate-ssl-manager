# Docker Corporate Certificate Environment
# Corporate SSL Certificate Configuration for Docker

# Only load in interactive shells
case $- in
    *i*) ;;
      *) return;;
esac

export DOCKER_CERT_PATH="$HOME/.docker/ca-bundle.crt"

# Docker aliases for corporate environment (only in interactive shells)
alias docker-corp='/usr/local/bin/docker-corp'
alias docker-secure='/usr/local/bin/docker-corp'

# Docker test functions (more reliable than aliases)
docker-test() {
    /usr/local/bin/docker-corp run --rm curlimages/curl:latest curl -s -o /dev/null -w "Status: %{http_code}" "$1" 2>/dev/null || echo "Status: FAIL"
}

docker-test-google() {
    echo -n "google.com: "
    /usr/local/bin/docker-corp run --rm curlimages/curl:latest curl -s -o /dev/null -w "%{http_code}" https://google.com 2>/dev/null || echo "FAIL"
}

docker-test-github() {
    echo -n "github.com: "
    /usr/local/bin/docker-corp run --rm curlimages/curl:latest curl -s -o /dev/null -w "%{http_code}" https://github.com 2>/dev/null || echo "FAIL"
}

docker-test-npmjs() {
    echo -n "npmjs.org: "
    /usr/local/bin/docker-corp run --rm curlimages/curl:latest curl -s -o /dev/null -w "%{http_code}" https://registry.npmjs.org 2>/dev/null || echo "FAIL"
}

# Test all Docker functionality
test-docker-all() {
    echo "Testing Docker Corporate SSL Configuration:"
    echo "========================================="
    docker-test-google
    docker-test-github
    docker-test-npmjs
    echo "========================================="
}

# Display status
echo "Docker Corporate SSL Environment Loaded"
echo "Use 'docker-corp' for containers with automatic certificate injection"
echo "Quick tests: docker-test-google, docker-test-github, docker-test-npmjs"
echo "Full test: test-docker-all"
