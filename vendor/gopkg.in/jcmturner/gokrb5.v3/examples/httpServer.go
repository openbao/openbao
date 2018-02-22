// +build examples

package main

import (
	"encoding/hex"
	"fmt"
	"gopkg.in/jcmturner/gokrb5.v3/credentials"
	"gopkg.in/jcmturner/gokrb5.v3/keytab"
	"gopkg.in/jcmturner/gokrb5.v3/service"
	"gopkg.in/jcmturner/gokrb5.v3/testdata"
	"log"
	"net/http"
	"os"
)

func main() {
	// Create logger
	l := log.New(os.Stderr, "GOKRB5 Service: ", log.Ldate|log.Ltime|log.Lshortfile)

	// Load the service's keytab
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt, _ := keytab.Parse(b)

	// Create the application's specific handler
	th := http.HandlerFunc(testAppHandler)

	// Set up handler mappings wrapping in the SPNEGOKRB5Authenticate handler wrapper
	mux := http.NewServeMux()
	mux.Handle("/", service.SPNEGOKRB5Authenticate(th, kt, "", l))

	// Start up the web server
	log.Fatal(http.ListenAndServe(":9080", mux))
}

// Simple application specific handler
func testAppHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	ctx := r.Context()
	fmt.Fprintf(w, "<html>\nTEST.GOKRB5 Handler\nAuthenticed user: %s\nUser's realm: %s\n</html>", ctx.Value(service.CREDENTIALS_CTXKEY).(credentials.Credentials).Username, ctx.Value(service.CREDENTIALS_CTXKEY).(credentials.Credentials).Realm)
	return
}
