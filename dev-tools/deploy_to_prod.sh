sed -i '' "s/kubeinvaders_version:.*/kubeinvaders_version: $1<\/p>/g" html5/index.html
docker build . -t docker.io/luckysideburn/kubeinvaders:$1
docker tag docker.io/luckysideburn/kubeinvaders:$1 docker.io/luckysideburn/kubeinvaders:latest
docker push docker.io/luckysideburn/kubeinvaders:$1
docker push docker.io/luckysideburn/kubeinvaders:latest