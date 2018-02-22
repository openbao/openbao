FROM centos:latest
MAINTAINER Jonathan Turner <jt@jtnet.co.uk>

EXPOSE 80 443
ENV LANG C
ENTRYPOINT ["/usr/sbin/httpd", "-DFOREGROUND"]

RUN yum install -y \
  httpd \
  mod_auth_kerb \
  mod_ssl \
  tcpdump krb5-workstation vim \
  && yum update -y && yum clean all

ADD httpd-krb5.conf /etc/httpd/conf.d/
ADD index.html /var/www/html/index.html
ADD krb5.conf /etc/krb5.conf
ADD http.testtab /etc/httpd/
#RUN ln -sf /dev/stdout /var/log/httpd/access_log && \
# ln -sf /dev/stdout /var/log/httpd/ssl_access_log && \
# ln -sf /dev/stdout /var/log/httpd/ssl_request_log && \
# ln -sf /dev/stderr /var/log/httpd/error_log && \
# ln -sf /dev/stderr /var/log/httpd/ssl_error_log


