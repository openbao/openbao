# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

import kerberos
import requests
import sys

prefix = sys.argv[1]
namespace = sys.argv[2]

host = prefix + ".matrix.lan:8200"
service = "HTTP@{}".format(host)
rc, vc = kerberos.authGSSClientInit(service=service, mech_oid=kerberos.GSS_MECH_OID_SPNEGO)
kerberos.authGSSClientStep(vc, "")
kerberos_token = kerberos.authGSSClientResponse(vc)

r = requests.post("http://{}/v1/{}auth/kerberos/login".format(host, namespace),
                  headers={'Authorization': 'Negotiate ' + kerberos_token})
print('Vault token:', r.json()['auth']['client_token'])