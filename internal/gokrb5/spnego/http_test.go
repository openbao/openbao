package spnego

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/client"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/config"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/keytab"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/service"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/test"
	"github.com/hashicorp/vault-plugin-auth-kerberos/internal/gokrb5/test/testdata"
	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/goidentity.v3"
)

func TestSPNEGOKRB5AuthenticateRespectsKeytabPrincipal(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testGSSAPIInit)
	if err != nil {
		t.Fatalf("Error converting hex string test data to bytes: %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString(b)

	configuredKt := keytab.New()
	buf := bytes.NewBuffer(nil)
	logger := log.New(buf, "", 0)
	handler := SPNEGOKRB5Authenticate(nil, configuredKt, service.Logger(logger), service.KeytabPrincipal("expected-principal"))

	header := make(map[string][]string)
	header[HTTPHeaderAuthRequest] = []string{"Negotiate " + b64}
	handler.ServeHTTP(&httptest.ResponseRecorder{}, &http.Request{
		Header:     header,
		RemoteAddr: "127.0.0.1:1234",
	})
	// Note that the resulting log line doesn't state it's looking for "expected-principal" in the keytab.
	fmt.Println(buf.String())
}

func TestClient_SetSPNEGOHeader(t *testing.T) {
	test.Integration(t)
	b, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.TEST_KDC}
	l := log.New(os.Stderr, "SPNEGO Client:", log.LstdFlags)
	cl := client.NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt, c, client.Logger(l))

	err := cl.Login()
	if err != nil {
		t.Fatalf("error on AS_REQ: %v\n", err)
	}
	urls := []string{
		"http://cname.test.gokrb5",
		"http://host.test.gokrb5",
	}
	paths := []string{
		"/modkerb/index.html",
		//"/modgssapi/index.html",
	}
	for _, url := range urls {
		for _, p := range paths {
			r, _ := http.NewRequest("GET", url+p, nil)
			httpResp, err := http.DefaultClient.Do(r)
			if err != nil {
				t.Fatalf("%s request error: %v", url+p, err)
			}
			assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode, "Status code in response to client with no SPNEGO not as expected")

			err = SetSPNEGOHeader(cl, r, "")
			if err != nil {
				t.Fatalf("error setting client SPNEGO header: %v", err)
			}

			httpResp, err = http.DefaultClient.Do(r)
			if err != nil {
				t.Fatalf("%s request error: %v\n", url+p, err)
			}
			assert.Equal(t, http.StatusOK, httpResp.StatusCode, "Status code in response to client SPNEGO request not as expected")
		}
	}
}

func TestSPNEGOHTTPClient(t *testing.T) {
	test.Integration(t)
	b, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.TEST_KDC}
	l := log.New(os.Stderr, "SPNEGO Client:", log.LstdFlags)
	cl := client.NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt, c, client.Logger(l))

	err := cl.Login()
	if err != nil {
		t.Fatalf("error on AS_REQ: %v\n", err)
	}
	urls := []string{
		"http://cname.test.gokrb5",
		"http://host.test.gokrb5",
	}
	// This path issues a redirect which the http client will automatically follow.
	// It should cause a replay issue if the negInit token is sent in the first instance.
	paths := []string{
		"/modgssapi", // This issues a redirect which the http client will automatically follow. Could cause a replay issue
		"/redirect",
	}
	for _, url := range urls {
		for _, p := range paths {
			r, _ := http.NewRequest("GET", url+p, nil)
			httpCl := http.DefaultClient
			httpCl.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				t.Logf("http client redirect: %+v", *req)
				return nil
			}
			spnegoCl := NewClient(cl, httpCl, "")
			httpResp, err := spnegoCl.Do(r)
			if err != nil {
				t.Fatalf("%s request error: %v", url+p, err)
			}
			assert.Equal(t, http.StatusOK, httpResp.StatusCode, "Status code in response to client SPNEGO request not as expected")
		}
	}
}

func TestService_SPNEGOKRB_NoAuthHeader(t *testing.T) {
	s := httpServer()
	defer s.Close()
	r, _ := http.NewRequest("GET", s.URL, nil)
	httpResp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode, "Status code in response to client with no SPNEGO not as expected")
	assert.Equal(t, "Negotiate", httpResp.Header.Get("WWW-Authenticate"), "Negotiation header not set by server.")
}

func TestService_SPNEGOKRB_ValidUser(t *testing.T) {
	test.Integration(t)

	s := httpServer()
	defer s.Close()
	r, _ := http.NewRequest("GET", s.URL, nil)

	cl := getClient()
	err := SetSPNEGOHeader(cl, r, "HTTP/host.test.gokrb5")
	if err != nil {
		t.Fatalf("error setting client's SPNEGO header: %v", err)
	}

	httpResp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusOK, httpResp.StatusCode, "Status code in response to client SPNEGO request not as expected")
}

func TestService_SPNEGOKRB_Replay(t *testing.T) {
	test.Integration(t)

	s := httpServer()
	defer s.Close()
	r1, _ := http.NewRequest("GET", s.URL, nil)

	cl := getClient()
	err := SetSPNEGOHeader(cl, r1, "HTTP/host.test.gokrb5")
	if err != nil {
		t.Fatalf("error setting client's SPNEGO header: %v", err)
	}

	// First request with this ticket should be accepted
	httpResp, err := http.DefaultClient.Do(r1)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusOK, httpResp.StatusCode, "Status code in response to client SPNEGO request not as expected")

	// Use ticket again should be rejected
	httpResp, err = http.DefaultClient.Do(r1)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode, "Status code in response to client with no SPNEGO not as expected. Expected a replay to be detected.")

	// Form a 2nd ticket
	r2, _ := http.NewRequest("GET", s.URL, nil)

	err = SetSPNEGOHeader(cl, r2, "HTTP/host.test.gokrb5")
	if err != nil {
		t.Fatalf("error setting client's SPNEGO header: %v", err)
	}

	// First use of 2nd ticket should be accepted
	httpResp, err = http.DefaultClient.Do(r2)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusOK, httpResp.StatusCode, "Status code in response to client SPNEGO request not as expected")

	// Using the 1st ticket again should still be rejected
	httpResp, err = http.DefaultClient.Do(r1)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode, "Status code in response to client with no SPNEGO not as expected. Expected a replay to be detected.")

	// Using the 2nd again should be rejected as replay
	httpResp, err = http.DefaultClient.Do(r2)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode, "Status code in response to client with no SPNEGO not as expected. Expected a replay to be detected.")
}

func TestService_SPNEGOKRB_ReplayCache_Concurrency(t *testing.T) {
	test.Integration(t)

	s := httpServer()
	defer s.Close()
	r1, _ := http.NewRequest("GET", s.URL, nil)

	cl := getClient()
	err := SetSPNEGOHeader(cl, r1, "HTTP/host.test.gokrb5")
	if err != nil {
		t.Fatalf("error setting client's SPNEGO header: %v", err)
	}

	r2, _ := http.NewRequest("GET", s.URL, nil)

	err = SetSPNEGOHeader(cl, r2, "HTTP/host.test.gokrb5")
	if err != nil {
		t.Fatalf("error setting client's SPNEGO header: %v", err)
	}

	// Concurrent 1st requests should be OK
	var wg sync.WaitGroup
	wg.Add(2)
	go httpGet(r1, &wg)
	go httpGet(r2, &wg)
	wg.Wait()

	// A number of concurrent requests with the same ticket should be rejected due to replay
	var wg2 sync.WaitGroup
	noReq := 10
	wg2.Add(noReq * 2)
	for i := 0; i < noReq; i++ {
		go httpGet(r1, &wg2)
		go httpGet(r2, &wg2)
	}
	wg2.Wait()
}

func TestService_SPNEGOKRB_Upload(t *testing.T) {
	test.Integration(t)

	s := httpServer()
	defer s.Close()

	bodyBuf := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuf)

	fileWriter, err := bodyWriter.CreateFormFile("uploadfile", "testfile.bin")
	if err != nil {
		t.Fatalf("error writing to buffer: %v", err)
	}

	data := make([]byte, 10240)
	rand.Read(data)
	br := bytes.NewReader(data)
	_, err = io.Copy(fileWriter, br)
	if err != nil {
		t.Fatalf("error copying bytes: %v", err)
	}
	bodyWriter.Close()

	r, _ := http.NewRequest("POST", s.URL, bodyBuf)
	r.Header.Set("Content-Type", bodyWriter.FormDataContentType())

	cl := getClient()
	spnegoCl := NewClient(cl, nil, "HTTP/host.test.gokrb5")
	httpResp, err := spnegoCl.Do(r)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	if httpResp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(httpResp.Body)
		bodyString := string(bodyBytes)
		httpResp.Body.Close()
		t.Errorf("unexpected code from http server (%d): %s", httpResp.StatusCode, bodyString)
	}
}

func httpGet(r *http.Request, wg *sync.WaitGroup) {
	defer wg.Done()
	http.DefaultClient.Do(r)
}

func httpServer() *httptest.Server {
	l := log.New(os.Stderr, "GOKRB5 Service Tests: ", log.Ldate|log.Ltime|log.Lshortfile)
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	th := http.HandlerFunc(testAppHandler)
	s := httptest.NewServer(SPNEGOKRB5Authenticate(th, kt, service.Logger(l)))
	return s
}

func testAppHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		maxUploadSize := int64(11240)
		if err := r.ParseMultipartForm(maxUploadSize); err != nil {
			http.Error(w, fmt.Sprintf("cannot parse multipart form: %v", err), http.StatusBadRequest)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
		file, _, err := r.FormFile("uploadfile")
		if err != nil {
			http.Error(w, "INVALID_FILE", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// write out to /dev/null
		_, err = io.Copy(ioutil.Discard, file)
		if err != nil {
			http.Error(w, "WRITE_ERR", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
	ctx := r.Context()
	fmt.Fprintf(w, "<html>\nTEST.GOKRB5 Handler\nAuthenticed user: %s\nUser's realm: %s\n</html>",
		ctx.Value(CTXKeyCredentials).(goidentity.Identity).UserName(),
		ctx.Value(CTXKeyCredentials).(goidentity.Identity).Domain())
	return
}

func getClient() *client.Client {
	b, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	c.LibDefaults.NoAddresses = true
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.TEST_KDC}
	c.Realms[0].KPasswdServer = []string{addr + ":464"}
	cl := client.NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt, c)
	return cl
}
