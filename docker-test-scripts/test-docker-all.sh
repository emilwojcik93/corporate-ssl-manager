#!/bin/bash
# Test all Docker corporate SSL functionality
echo "Testing Docker Corporate SSL Configuration:"
echo "========================================="
echo -n "google.com: "
/usr/local/bin/docker-corp run --rm curlimages/curl:latest curl -s -o /dev/null -w "%{http_code}" https://google.com 2>/dev/null || echo "FAIL"
echo -n "github.com: "
/usr/local/bin/docker-corp run --rm curlimages/curl:latest curl -s -o /dev/null -w "%{http_code}" https://github.com 2>/dev/null || echo "FAIL"
echo -n "npmjs.org: "
/usr/local/bin/docker-corp run --rm curlimages/curl:latest curl -s -o /dev/null -w "%{http_code}" https://registry.npmjs.org 2>/dev/null || echo "FAIL"
echo "========================================="
