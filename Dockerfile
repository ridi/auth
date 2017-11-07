FROM ridibooks/performance-apache-base:latest
MAINTAINER Kang Ki Tae <kt.kang@ridi.com>

ENV APACHE_DOC_ROOT /var/www/html/web
EXPOSE 80 443
ADD . /var/www/html
