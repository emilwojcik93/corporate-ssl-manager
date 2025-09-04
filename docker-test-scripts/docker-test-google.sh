#!/bin/bash
# Test Google.com with Docker corporate certificates
echo -n "google.com: "
/usr/local/bin/docker-corp run --rm curlimages/curl:latest curl -s -o /dev/null -w "%{http_code}" https://google.com 2>/dev/null || echo "FAIL"
