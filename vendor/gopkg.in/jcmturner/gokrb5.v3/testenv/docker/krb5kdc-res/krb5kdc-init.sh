#!/bin/bash

REALM=RESDOM.GOKRB5
DOMAIN=resdom.gokrb5
SERVER_HOST=kdc.resdom.gokrb5
ADMIN_USERNAME=adminuser
HOST_PRINCIPALS="kdc.resdom.gokrb5 host.resdom.gokrb5"
SPNs="HTTP/host.resdom.gokrb5"

create_entropy() {
   while true
   do
     sleep $(( ( RANDOM % 10 )  + 1 ))
     echo "Generating Entropy... $RANDOM"
   done
}

create_entropy &
ENTROPY_PID=$!


  echo "Kerberos initialisation required. Creating database for ${REALM} ..."
  echo "This can take a long time if there is little entropy. A process has been started to create some."
  MASTER_PASSWORD=$(echo $RANDOM$RANDOM$RANDOM | md5sum | awk '{print $1}')
  /usr/sbin/kdb5_util create -r ${REALM} -s -P ${MASTER_PASSWORD}
  kill -9 ${ENTROPY_PID}
  echo "Kerberos database created."
  /usr/sbin/kadmin.local -q "add_principal -randkey ${ADMIN_USERNAME}/admin"
  echo "Kerberos admin user created: ${ADMIN_USERNAME} To update password: sudo /usr/sbin/kadmin.local -q \"change_password ${ADMIN_USERNAME}/admin\""

  KEYTAB_DIR="/keytabs"
  mkdir -p $KEYTAB_DIR

  if [ ! -z "${HOST_PRINCIPALS}" ]; then
    for host in ${HOST_PRINCIPALS}
    do
      /usr/sbin/kadmin.local -q "add_principal -pw hostpasswordvalue -kvno 1 host/$host"
      echo "Created host principal host/$host"
    done
  fi

  /usr/sbin/kadmin.local -q "add_principal -pw spnpasswordvalue -kvno 1 HTTP/host.resdom.gokrb5"

  /usr/sbin/kadmin.local -q "add_principal -pw passwordvalue -kvno 1 testuser1"
  /usr/sbin/kadmin.local -q "add_principal +requires_preauth -pw passwordvalue -kvno 1 testuser2"
  /usr/sbin/kadmin.local -q "add_principal -pw passwordvalue -kvno 1 testuser3"

  # Set up trust
  /usr/sbin/kadmin.local -q "add_principal -requires_preauth -pw trustpasswd -kvno 1 krbtgt/TEST.GOKRB5@RESDOM.GOKRB5"
  /usr/sbin/kadmin.local -q "add_principal -requires_preauth -pw trustpasswd -kvno 1 krbtgt/RESDOM.GOKRB5@TEST.GOKRB5"


  echo "Kerberos initialisation complete"
