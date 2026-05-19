#!/bin/bash
set -e
echo "==> Starting Docker containers..."
docker-compose up --build "$@"
