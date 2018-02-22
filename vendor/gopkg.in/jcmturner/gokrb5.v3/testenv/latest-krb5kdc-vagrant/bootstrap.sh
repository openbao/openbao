#!/bin/bash

rm /etc/localtime
ln -s /usr/share/zoneinfo/Europe/London /etc/localtime
setenforce 0
sed -i "s/SELINUX=enforcing/SELINUX=permissive/g" /etc/sysconfig/selinux

yum update -y && yum clean all
yum install -y tcpdump ntp vim ncurses telnet ncurses-devel tcl net-tools
yum groupinstall "Development Tools" -y

cd /vagrant
tar -xvzf krb5-1.15.1.tar.gz && cd krb5-1.15.1/src && \
./configure && make && make install

ln -s /usr/local/var/krb5kdc /var/kerberos/krb5kdc
cp /vagrant/krb5kdc.service /etc/systemd/system/
systemctl enable krb5kdc

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

