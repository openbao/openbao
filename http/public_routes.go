package http

import (
	"context"
	"net/http"

	"github.com/openbao/openbao/vault"
)

type (
	contextKeyPublicRoutes string
)

const (
	IsPublicRouteRequestContextKey contextKeyPublicRoutes = "public_route_request"
)

func wrapPublicRoutesHandler(h http.Handler, props *vault.HandlerProperties) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		ctx := req.Context()

		if props != nil && props.ListenerConfig != nil && props.ListenerConfig.OnlyPublicRoutes {
			ctx = context.WithValue(req.Context(), IsPublicRouteRequestContextKey, true)
		}

		h.ServeHTTP(writer, req.WithContext(ctx))
	})
}
