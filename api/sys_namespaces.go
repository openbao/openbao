package api

import (
	"context"
	"fmt"
	"net/http"
)

type UnsealNamespaceInput struct {
	Path  string `json:"path"`
	Key   string `json:"key"`
	Reset bool   `json:"reset"`
}

type NamespaceSealStatusOutput struct {
	Type        string `json:"type"`
	Initialized bool   `json:"initialized"`
	Sealed      bool   `json:"sealed"`
	T           int    `json:"t"`
	N           int    `json:"n"`
	Progress    int    `json:"progress"`
	Nonce       string `json:"nonce"`
}

func (s *Sys) UnsealNamespace(req *UnsealNamespaceInput) (*NamespaceSealStatusOutput, error) {
	return s.UnsealNamespaceWithContext(context.Background(), req)
}

func (s *Sys) UnsealNamespaceWithContext(ctx context.Context, req *UnsealNamespaceInput) (*NamespaceSealStatusOutput, error) {
	body := map[string]any{"key": req.Key, "reset": req.Reset}

	r := s.c.NewRequest(http.MethodPut, fmt.Sprintf("/v1/sys/namespaces/%s/unseal", req.Path))
	if err := r.SetJSONBody(body); err != nil {
		return nil, err
	}

	ctx, cancelFunc := s.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	resp, err := s.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}

	//nolint:errcheck // ignoring the error here as its only fulfilling the signature and not returning any sensible error
	defer resp.Body.Close()

	var result struct {
		Data *NamespaceSealStatusOutput
	}
	err = resp.DecodeJSON(&result)
	return result.Data, err
}

func (c *Sys) SealNamespace(name string) error {
	return c.SealNamespaceWithContext(context.Background(), name)
}

func (c *Sys) SealNamespaceWithContext(ctx context.Context, name string) error {
	r := c.c.NewRequest(http.MethodPut, fmt.Sprintf("/v1/sys/namespaces/%s/seal", name))

	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	_, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	return nil
}
