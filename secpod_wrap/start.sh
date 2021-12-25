if [ ! -z "$K8S_TOKEN" ];then
  echo 'Found K8S_TOKEN... using K8S_TOKEN instead of TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)'
  export K8S_TOKEN=$K8S_TOKEN
else
  # Source the service account token from the container directly.
  export K8S_TOKEN="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
fi

export K8S_URL="${KUBERNETES_SERVICE_HOST}"

./secpod_wrap.py store