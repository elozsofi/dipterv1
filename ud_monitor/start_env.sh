#!/bin/bash

IMAGE_NAME="aitiasga/ebpf-dev:latest"
HOST_PROJ_DIR="/home/zsofi/Dokumentumok/Aitia/aitia/EZsofi/ud_tctap"
CONTAINER_PROJ_DIR="/mnt/userdata"

docker pull $IMAGE_NAME

docker run -it --rm \
  -v ${HOST_PROJ_DIR}:${CONTAINER_PROJ_DIR} \
  $IMAGE_NAME bash