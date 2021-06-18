FROM ubuntu:20.04

LABEL maintainer="LoRexxar <guoyinqi@xiaomi.com>"

RUN sed -i "s/archive.ubuntu.com/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list && sed -i "s/archive.ubuntu.com/ubuntu/g" /etc/apt/sources.list

RUN apt-get update \
    && apt-get install -y vim inetutils-ping curl ssh zip python3 python3-pip

# Set the locale
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

# python换源
RUN mkdir /root/.pip
RUN /bin/bash -c "echo -e '[global]\nindex-url = https://pypi.tuna.tsinghua.edu.cn/simple' > /root/.pip/pip.conf"
RUN cat /root/.pip/pip.conf

# mysql
RUN apt-get install -y libmysqlclient-dev

# nginx
RUN apt-get install -y nginx

# install
COPY ../ /home/kunlun-m
WORKDIR /home/kunlun-m

RUN python3 -m pip install -r requirements.txt
RUN Kunlun_M/settings.py.bak Kunlun_M/settings.py

RUN python3 kunlun.py init

# nginx config
COPY nginx.conf /etc/nginx/
RUN /etc/init.d/nginx start

RUN mkdir /data && mkdir /data/log && mkdir /data/log/

RUN python3 -m pip install supervisor

RUN supervisord -c /home/kunlun-m/docker/supervisord.conf
RUN supervisorctl -c /home/kunlun-m/docker/supervisord.conf start all

EXPOSE 80