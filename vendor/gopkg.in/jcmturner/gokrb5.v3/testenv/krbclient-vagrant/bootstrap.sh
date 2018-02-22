#!/bin/bash

rm /etc/localtime
ln -s /usr/share/zoneinfo/Europe/London /etc/localtime
setenforce 0
sed -i "s/SELINUX=enforcing/SELINUX=permissive/g" /etc/sysconfig/selinux

yum update -y && yum clean all
yum install -y tcpdump krb5-workstation ntp vim

systemctl stop firewalld
systemctl disable firewalld
systemctl enable ntpd

cat <<EOF >> /etc/sysctl.conf
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF

mkdir -p /var/log/kerberos
cp /vagrant/krb5.conf /etc/krb5.conf
echo "10.80.88.88 kdc.test.gokrb5" >> /etc/hosts

reboot
