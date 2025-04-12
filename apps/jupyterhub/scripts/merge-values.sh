#!/bin/bash

# Script to merge common values with environment-specific values
ENV_DIR=$1  # e.g., envs/dev
BASE_DIR="base"

# Use yq (YAML processor) to merge the files
yq eval-all 'select(fileIndex == 0) * select(fileIndex == 1)' \
  "${BASE_DIR}/common-values.yaml" "${ENV_DIR}/values.yaml" \
  > "${ENV_DIR}/merged-values.yaml"

echo "Values merged successfully: ${ENV_DIR}/merged-values.yaml"
