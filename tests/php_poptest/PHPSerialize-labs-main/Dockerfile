FROM php:5.4-apache
COPY . /var/www/html
RUN sed -i 's/Options FollowSymLinks/Options +FollowSymLinks +Indexes/g' /etc/apache2/apache2.conf
RUN echo '<IfModule mime_module>\nAddDefaultCharset UTF-8\n</IfModule>' > /etc/apache2/conf-enabled/default-charset.conf
EXPOSE 80