#!/bin/bash

systemctl start krb5kdc

REALM=TEST.GOKRB5
DOMAIN=test.gokrb5
SERVER_HOST=kdc.test.gokrb5
ADMIN_USERNAME=adminuser
HOST_PRINCIPALS="kdc.test.gokrb5 host.test.gokrb5"

cp /vagrant/krb5.conf /etc/krb5.conf
cp /var/kerberos/krb5kdc/kdc.conf /var/kerberos/krb5kdc/kdc.conf-old
cp /vagrant/kdc.conf /var/kerberos/krb5kdc/kdc.conf
cp /vagrant/kadm5.acl /var/kerberos/krb5kdc/kadm5.acl

sed -i "s/__ADMIN_USER__/${ADMIN_USERNAME}/g" /var/kerberos/krb5kdc/kadm5.acl
sed -i "s/__REALM__/${REALM}/g" /var/kerberos/krb5kdc/kadm5.acl
sed -i "s/__REALM__/${REALM}/g" /var/kerberos/krb5kdc/kdc.conf
sed -i "s/__REALM__/${REALM}/g" /etc/krb5.conf
sed -i "s/__DOMAIN__/${DOMAIN}/g" /etc/krb5.conf
sed -i "s/__SERVER_HOST__/${SERVER_HOST}/g" /etc/krb5.conf

create_entropy() {
   while true
   do
     sleep $(( ( RANDOM % 10 )  + 1 ))
     echo "Generating Entropy... $RANDOM"
   done
}

create_entropy &

  echo "Kerberos initialisation required. Creating database for ${REALM} ..."
  echo "This can take a long time if there is little entropy. A process has been started to create some."
  MASTER_PASSWORD=$(echo $RANDOM$RANDOM$RANDOM | md5sum | awk '{print $1}')
  /usr/local/sbin/kdb5_util create -r ${REALM} -s -P ${MASTER_PASSWORD}
  echo "Kerberos database created."
  /usr/local/sbin/kadmin.local -q "add_principal -randkey ${ADMIN_USERNAME}/admin"
  echo "Kerberos admin user created: ${ADMIN_USERNAME} To update password: sudo /usr/local/sbin/kadmin.local -q \"change_password ${ADMIN_USERNAME}/admin\""

  KEYTAB_DIR="/keytabs"
  mkdir -p $KEYTAB_DIR

  if [ ! -z "${HOST_PRINCIPALS}" ]; then
    for host in ${HOST_PRINCIPALS}
    do
      /usr/local/sbin/kadmin.local -q "add_principal -pw hostpasswordvalue -kvno 1 host/$host"
      echo "Created host principal host/$host"
    done
  fi

  /usr/local/sbin/kadmin.local -q "add_principal -pw spnpasswordvalue -kvno 1 HTTP/host.test.gokrb5"

  /usr/local/sbin/kadmin.local -q "add_principal -pw passwordvalue -kvno 1 testuser1"
  /usr/local/sbin/kadmin.local -q "add_principal +requires_preauth -pw passwordvalue -kvno 1 testuser2"
  /usr/local/sbin/kadmin.local -q "add_principal -pw passwordvalue -kvno 1 testuser3"

  echo "Kerberos initialisation complete"

systemctl restart krb5kdc
