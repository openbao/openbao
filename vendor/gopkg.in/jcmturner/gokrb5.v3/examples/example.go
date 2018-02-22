// +build examples

package main

import (
	"encoding/hex"
	"fmt"
	"gopkg.in/jcmturner/gokrb5.v3/client"
	"gopkg.in/jcmturner/gokrb5.v3/config"
	"gopkg.in/jcmturner/gokrb5.v3/credentials"
	"gopkg.in/jcmturner/gokrb5.v3/keytab"
	"gopkg.in/jcmturner/gokrb5.v3/service"
	"gopkg.in/jcmturner/gokrb5.v3/testdata"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
)

/*
These examples have the following prerequisites:
* Hashicorp Vagrant
* VirtualBox

The test environment relies upon a host only network configured within VirtualBox with a CIDR range of 10.80.0.0/16
If this does not suit your setup then you will need to set the IP addresses for the private_network in the Vagrantfiles to something that suits you.
You will also need to update the IPs referenced in the testdata/test_vectors.go file in the TEST_KRB5CONF constant.

Before running execute the following commands (note that the KDC can take a long time to start up):
cd $GOPATH/src/gopkg.in/jcmturner/gokrb5.v3/testenv/krb5kdc-vagrant && vagrant up
cd $GOPATH/src/gopkg.in/jcmturner/gokrb5.v3/testenv/krbhttp-vagrant && vagrant up
*/
func main() {
	s := httpServer()
	defer s.Close()

	b, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt, _ := keytab.Parse(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	cl := client.NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt)
	cl.WithConfig(c)
	httpRequest(s.URL, cl)

	b, _ = hex.DecodeString(testdata.TESTUSER2_KEYTAB)
	kt, _ = keytab.Parse(b)
	c, _ = config.NewConfigFromString(testdata.TEST_KRB5CONF)
	cl = client.NewClientWithKeytab("testuser2", "TEST.GOKRB5", kt)
	cl.WithConfig(c)
	httpRequest(s.URL, cl)

	//httpRequest("http://host.test.gokrb5/index.html")
}

func httpRequest(url string, cl client.Client) {
	l := log.New(os.Stderr, "GOKRB5 Client: ", log.Ldate|log.Ltime|log.Lshortfile)

	err := cl.Login()
	if err != nil {
		l.Printf("Error on AS_REQ: %v\n", err)
	}
	r, _ := http.NewRequest("GET", url, nil)
	err = cl.SetSPNEGOHeader(r, "HTTP/host.test.gokrb5")
	if err != nil {
		l.Printf("Error setting client SPNEGO header: %v", err)
	}
	httpResp, err := http.DefaultClient.Do(r)
	if err != nil {
		l.Printf("Request error: %v\n", err)
	}
	fmt.Fprintf(os.Stdout, "Response Code: %v\n", httpResp.StatusCode)
	content, _ := ioutil.ReadAll(httpResp.Body)
	fmt.Fprintf(os.Stdout, "Response Body:\n%s\n", content)
}

func httpServer() *httptest.Server {
	l := log.New(os.Stderr, "GOKRB5 Service: ", log.Ldate|log.Ltime|log.Lshortfile)
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt, _ := keytab.Parse(b)
	th := http.HandlerFunc(testAppHandler)
	s := httptest.NewServer(service.SPNEGOKRB5Authenticate(th, kt, "", l))
	return s
}

func testAppHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	fmt.Fprint(w, "<html>\n<p><h1>TEST.GOKRB5 Handler</h1></p>\n")
	if validuser, ok := ctx.Value(service.CTXKey_Authenticated).(bool); ok && validuser {
		if creds, ok := ctx.Value(service.CTXKey_Credentials).(credentials.Credentials); ok {
			fmt.Fprintf(w, "<ul><li>Authenticed user: %s</li>\n", creds.Username)
			fmt.Fprintf(w, "<li>User's realm: %s</li></ul>\n", creds.Realm)
		}

	} else {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Authentication failed")
	}
	fmt.Fprint(w, "</html>")
	return
}
