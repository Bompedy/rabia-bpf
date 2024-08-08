docker build -t bpf-image .././
kubectl delete deployment bpf
kubectl apply -f .\deploy.yaml