#!/bin/bash


REALM=TEST.GOKRB5
DOMAIN=test.gokrb5
SERVER_HOST=kdc.test.gokrb5

cp /vagrant/krb5.conf /etc/krb5.conf

sed -i "s/__REALM__/${REALM}/g" /etc/krb5.conf
sed -i "s/__DOMAIN__/${DOMAIN}/g" /etc/krb5.conf
sed -i "s/__SERVER_HOST__/${SERVER_HOST}/g" /etc/krb5.conf
