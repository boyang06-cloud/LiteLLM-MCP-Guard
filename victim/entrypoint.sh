#!/bin/sh

echo "Starting LiteLLM Proxy..."

litellm \
    --config /app/config.yaml \
    --host 0.0.0.0 \
    --port 4000