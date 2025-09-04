#!/bin/bash
# Test GitHub.com with Docker corporate certificates
echo -n "github.com: "
/usr/local/bin/docker-corp run --rm curlimages/curl:latest curl -s -o /dev/null -w "%{http_code}" https://github.com 2>/dev/null || echo "FAIL"
