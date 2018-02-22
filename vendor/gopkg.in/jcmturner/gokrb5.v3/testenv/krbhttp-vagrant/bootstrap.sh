#!/bin/bash

rm /etc/localtime
ln -s /usr/share/zoneinfo/Europe/London /etc/localtime
setenforce 0
sed -i "s/SELINUX=enforcing/SELINUX=disabled/g" /etc/sysconfig/selinux

yum update -y
yum install -y \
   httpd \
   mod_auth_kerb \
   mod_ssl \
   ntp \
   krb5-workstation

systemctl stop firewalld
systemctl disable firewalld
systemctl enable ntpd

cat <<EOF >> /etc/sysctl.conf
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF

echo "10.80.88.88 kdc.test.gokrb5" >> /etc/hosts
echo "10.80.88.89 client.test.gokrb5" >> /etc/hosts
echo "10.80.88.90 host.test.gokrb5" >> /etc/hosts

sh /vagrant/krb-setup.sh
mv /vagrant/httpd-krb5.conf /etc/httpd/conf.d/
chcon system_u:object_r:httpd_config_t:s0 /etc/httpd/conf.d/*
chcon system_u:object_r:httpd_config_t:s0 /vagrant/http.testtab
chmod 644 /vagrant/http.testtab
echo "<html>TEST.GOKRB5</html>" > /var/www/html/index.html

systemctl restart httpd
systemctl enable httpd

reboot
