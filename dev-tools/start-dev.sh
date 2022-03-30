#!/bin/bash
myregistry="$(ifconfig  en0 | grep 'inet ' | awk '{ print $2 }'):5000"
echo "Found Registry Docker Host: $myregistry"
echo $myregistry > dev-tools/repo
scp dev-tools/repo root@192.168.58.99:/tmp/
/bin/cp dev-tools/registries-template.yaml dev-tools/registries.yaml
echo "Replacing ENDPOINT in dev-tools/registries.yaml"
sed -i '' "s/ENDPOINT/$myregistry/" dev-tools/registries.yaml
cat dev-tools/registries.yaml
sed -i '' "s/kubeinvaders_version:.*/kubeinvaders_version: develop<\/p>/g" html5/index.html
docker build . -t $(ifconfig  en0 | grep 'inet ' | awk '{ print $2 }'):5000/luckysideburn/kubeinvaders:develop
docker push $(ifconfig  en0 | grep 'inet ' | awk '{ print $2 }'):5000/luckysideburn/kubeinvaders:develop
scp dev-tools/registries.yaml root@192.168.58.99:/tmp/
ssh root@192.168.58.99 <<'EOL'
  ls /etc/rancher/k3s/registries.yaml
  if [ $? -eq 0 ];then
    cmp /tmp/registries.yaml /etc/rancher/k3s/registries.yaml || $(/bin/cp /tmp/registries.yaml /etc/rancher/k3s/registries.yaml && systemctl restart k3s)
  else
    /bin/cp /tmp/registries.yaml /etc/rancher/k3s/registries.yaml
  fi
  kubectl create namespace kubeinvaders
  export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
  helm upgrade kubeinvaders --set-string target_namespace="namespace1\,namespace2" -n kubeinvaders /vagrant/helm-charts/kubeinvaders/ --set ingress.hostName=kubeinvaders.io --set image.tag=develop  --set image.repository=$(cat /tmp/repo)/luckysideburn/kubeinvaders -i
  kubectl delete pod --force --grace-period=0 --all -n kubeinvaders
EOL
