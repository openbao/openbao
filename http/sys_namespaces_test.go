package http

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/openbao/openbao/helper/benchhelpers"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/vault"
)

func FuzzNamespaceName(f *testing.F) {
	t := benchhelpers.TBtoT(f)
	core, _, token := vault.TestCoreUnsealed(t)
	ln, addr := TestServer(f, core)
	defer ln.Close()
	TestServerAuth(f, addr, token)

	f.Add(".")
	f.Add("..")
	f.Add("/")
	f.Add("foo/bar")
	f.Add("sys")
	f.Add("cubbyhole")
	f.Add("root")
	f.Add("audit")
	f.Add("auth")
	f.Add("identity")
	f.Add("valid")
	f.Add("%")
	f.Add("💪")
	f.Add("大")
	f.Add("foo bar")
	f.Add(string([]byte{0x20, 0x00}))
	f.Add(string([]byte{0xE2, 0x80, 0x80}))

	namesCache := make(map[string]bool)
	namesList := make([]string, 0)

	f.Fuzz(func(t *testing.T, name string) {
		expect := http.StatusOK
		switch {
		// exact values
		case name == "..":
			expect = http.StatusNotFound
		case name == ".":
			expect = http.StatusMethodNotAllowed
		case name == "":
			expect = http.StatusBadRequest
		case name == "sys":
			expect = http.StatusInternalServerError
		case name == "cubbyhole":
			expect = http.StatusInternalServerError
		case name == "root":
			expect = http.StatusInternalServerError
		case name == "audit":
			expect = http.StatusInternalServerError
		case name == "auth":
			expect = http.StatusInternalServerError
		case name == "identity":
			expect = http.StatusInternalServerError

		// 400
		case strings.ContainsFunc(name, not(unicode.IsPrint)):
			expect = http.StatusBadRequest
		case strings.HasSuffix(name, "/"):
			expect = http.StatusBadRequest

		// 500
		case strings.Contains(name, " "):
			expect = http.StatusInternalServerError
		case strings.Contains(name, "/"):
			expect = http.StatusInternalServerError
		case strings.Contains(name, "+*"):
			expect = http.StatusInternalServerError

		// 400 again
		case !utf8.ValidString(name):
			expect = http.StatusBadRequest
		}

		escapedName := url.PathEscape(name)
		canonicalName := namespace.Canonicalize(path.Clean(name))
		if namesCache[canonicalName] {
			return
		}
		namesCache[canonicalName] = true
		namesList = append(namesList, name)

		resp := testHttpPut(t, token, addr+"/v1/sys/namespaces/"+escapedName, nil)
		t.Logf("creating namespace '%s' (%x)", name, name)
		if resp.StatusCode < 300 {
			resp = testHttpGet(t, token, addr+"/v1/sys/namespaces?list=true")
			t.Log("listing namespaces")
			testResponseStatus(t, resp, http.StatusOK)

			resp = testHttpGet(t, token, addr+"/v1/"+escapedName+"/sys/namespaces?list=true")
			t.Logf("listing child namespaces of '%s' (%x)", name, name)
			testResponseStatus(t, resp, http.StatusNotFound)

			resp = testHttpDelete(t, token, addr+"/v1/sys/namespaces/"+escapedName)
			t.Logf("deleting namespace '%s' (%x)", name, name)
			testResponseStatus(t, resp, http.StatusNoContent)
			return
		}

		if resp.StatusCode >= 500 {
			b, _ := io.ReadAll(resp.Body)
			var out struct {
				Errors []string `json:"errors"`
			}
			json.Unmarshal(b, &out)

			for _, e := range out.Errors {
				if strings.Contains(e, "existing mount") {
					t.Logf("existing mount: '%s' (%x)", name, name)
					for _, n := range namesList {
						if strings.Contains(n, name) || strings.Contains(name, n) {
							t.Logf("possible mount: %s", n)
						}
					}
					if canonicalName != name {
						t.Logf("found differing name: '%s', cleaned: '%s'", name, canonicalName)
					}
				}
			}
		}

		testResponseStatus(t, resp, expect)
	})
}

func not[T any](f func(T) bool) func(T) bool {
	return func(t T) bool {
		return !f(t)
	}
}
