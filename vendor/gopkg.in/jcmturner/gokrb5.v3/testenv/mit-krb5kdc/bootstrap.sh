#!/bin/bash

rm /etc/localtime
ln -s /usr/share/zoneinfo/Europe/London /etc/localtime
setenforce 0
sed -i "s/SELINUX=enforcing/SELINUX=permissive/g" /etc/sysconfig/selinux

yum update -y && yum clean all
yum install -y tcpdump ntp docker net-tools krb5-workstation vim

systemctl stop firewalld
systemctl disable firewalld
systemctl enable ntpd docker
systemctl start docker
systemctl stop docker

#Some storage issue with docker on centos 7.1 hack
rm -f /etc/sysconfig/docker-storage
rm -rf /var/lib/docker

cat <<EOF >> /etc/sysctl.conf
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF

cp /vagrant/krb5.conf /etc/krb5.conf
cp /vagrant/*.service /etc/systemd/system/
systemctl enable krb5kdc krb5kdc-resdom krb5kdc-latest krb5kdc-older httpd dns


/usr/bin/docker pull jcmturner/gokrb5:http
/usr/bin/docker pull jcmturner/gokrb5:kdc-centos-default
/usr/bin/docker pull jcmturner/gokrb5:kdc-resdom
/usr/bin/docker pull jcmturner/gokrb5:kdc-older
/usr/bin/docker pull jcmturner/gokrb5:kdc-latest
/usr/bin/docker pull jcmturner/gokrb5:dns


reboot

#systemctl start docker krb5kdc krb5kdc-res krb5kdc-latest krb5kdc-older
