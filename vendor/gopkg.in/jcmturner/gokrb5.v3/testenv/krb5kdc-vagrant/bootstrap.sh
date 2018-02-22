#!/bin/bash

rm /etc/localtime
ln -s /usr/share/zoneinfo/Europe/London /etc/localtime
setenforce 0
sed -i "s/SELINUX=enforcing/SELINUX=permissive/g" /etc/sysconfig/selinux

yum update -y && yum clean all
yum install -y tcpdump krb5-server krb5-workstation httpd mod_auth_kerb mod_ssl ntp vim net-tools

systemctl stop firewalld
systemctl disable firewalld
systemctl enable ntpd

cat <<EOF >> /etc/sysctl.conf
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF

echo "10.80.88.89 client.test.gokrb5" >> /etc/hosts


sh /vagrant/kdc-setup.sh

reboot
