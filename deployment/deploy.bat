@echo off
for /f "delims=" %%i in ('powershell -command "([int][double]::Parse((Get-Date -UFormat %%s)))"') do set current_time=%%i
docker build --build-arg BUILD_TIME=%current_time% -t bpf-image .././
kubectl delete deployment bpf
powershell -Command "(Get-Content deploy.yaml) -replace '<BUILD_TIME>', '%current_time%' | Set-Content deploy-updated.yaml"
kubectl apply -f deploy-updated.yaml
del deploy-updated.yaml