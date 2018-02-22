#!/bin/bash

sed -i "s/<TEST_KDC_ADDR>/${TEST_KDC_ADDR}/g" /var/named/data/db.test.gokrb5

/usr/sbin/named -g -c /etc/named.conf -u bind -4