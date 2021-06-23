FROM ubuntu:20.04

LABEL maintainer="LoRexxar <guoyinqi@xiaomi.com>"

RUN sed -i "s/archive.ubuntu.com/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list && sed -i "s/archive.ubuntu.com/ubuntu/g" /etc/apt/sources.list

# Set the locale
ENV DEBIAN_FRONTEND=noninteractive
ENV LANG zh_CN.UTF-8
ENV LC_ALL zh_CN.UTF-8

RUN apt-get update \
    && apt-get install -y vim inetutils-ping curl ssh zip python3 python3-pip gunicorn

# python换源
RUN mkdir /root/.pip
RUN /bin/bash -c "echo -e '[global]\nindex-url = https://pypi.tuna.tsinghua.edu.cn/simple' > /root/.pip/pip.conf"
RUN cat /root/.pip/pip.conf

# mysql
RUN apt-get install -y libmysqlclient-dev

# nginx
RUN apt-get install -y nginx

# install
COPY ./ /home/kunlun-m
WORKDIR /home/kunlun-m

RUN python3 -m pip install -r requirements.txt
RUN cp Kunlun_M/settings.py.bak Kunlun_M/settings.py

RUN python3 kunlun.py init

# nginx config
COPY /docker/nginx.conf /etc/nginx/
RUN mkdir /data && mkdir /data/log
RUN /etc/init.d/nginx start

RUN python3 -m pip install supervisor

COPY /docker/supervisord.conf /etc/
COPY /docker/start.sh /
RUN chmod +x /start.sh
RUN /usr/local/bin/supervisord && /usr/local/bin/supervisorctl start all

ENTRYPOINT ["/start.sh"]

EXPOSE 80