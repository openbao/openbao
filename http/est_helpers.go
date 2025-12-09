package http

import (
	"net/http"

	"github.com/openbao/openbao/sdk/v2/helper/consts"
)

func setESTWWWAuthenticateHeader(w http.ResponseWriter) {
	if w == nil {
		return
	}
	if w.Header().Get("WWW-Authenticate") == "" {
		w.Header().Set("WWW-Authenticate", consts.ESTWWWAuthenticateHeaderValue)
	}
}
