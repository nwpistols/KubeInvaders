#!/bin/bash+
sed -i '' "s/kubeinvaders_version:.*/kubeinvaders_version: develop<\/p>/g" html5/index.html
docker build . -t 192.168.178.36:5001/luckysideburn/kubeinvaders:develop
docker push 192.168.178.36:5001/luckysideburn/kubeinvaders:develop
ssh root@192.168.58.99 <<'EOL'
  kubectl create namespace kubeinvaders
  export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
  helm upgrade kubeinvaders --set-string target_namespace="namespace1\,namespace2" -n kubeinvaders /vagrant/helm-charts/kubeinvaders/ --set ingress.hostName=kubeinvaders.io --set image.tag=develop -i
  kubectl delete pod --force --grace-period=0 --all -n kubeinvaders
EOL
