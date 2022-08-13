#!/usr/bin/env bash

# 配置邮件服务器
# sudo sed -i "s/user = 'youremailaddress@qq.com'/user = '${1}'/g" ./littleRedCUC/emailway.py
# sudo sed -i "s/password = 'yourserver-password'/password = '${2}'/g" ./littleRedCUC/emailway.py

docker build -t es_python_image  -f Dockerfile .
# docker run --rm -it -v "${PWD}/src:/src" -w /src node:11-alpine npm install
docker-compose -f docker-compose.yml up -d