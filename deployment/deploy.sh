#!/bin/bash
current_time=$(date +%s)
docker build --build-arg BUILD_TIME=$current_time -t bpf-image .././
kubectl delete deployment bpf
sed "s/<BUILD_TIME>/$current_time/" deploy.yaml > deploy-updated.yaml
kubectl apply -f deploy-updated.yaml
rm deploy-updated.yaml