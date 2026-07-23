// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package listenerutil

import (
	"bytes"
	"crypto/sha256"
	"net"
	"os"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
)

func NewTLSReloadListener(ln net.Listener, paths []string, interval time.Duration, reload func() error, logger hclog.Logger) net.Listener {
	wg := &sync.WaitGroup{}
	stop := make(chan struct{})
	wg.Go(func() {
		pollTLSCertificateChanges(paths, interval, reload, stop, logger)
	})
	return &tlsReloadListener{Listener: ln, wg: wg, stop: stop}
}

type tlsReloadListener struct {
	net.Listener
	wg   *sync.WaitGroup
	stop chan struct{}
}

func (l *tlsReloadListener) Close() error {
	close(l.stop)
	l.wg.Wait()
	return l.Listener.Close()
}

func pollTLSCertificateChanges(paths []string, interval time.Duration, reload func() error, stopCh <-chan struct{}, logger hclog.Logger) {
	hash := func() []byte {
		h := sha256.New()
		for _, p := range paths {
			data, err := os.ReadFile(p)
			if err != nil {
				logger.Warn("tls auto-reload: cannot read file", "path", p, "error", err)
				continue
			}
			h.Write(data)
		}
		return h.Sum(nil)
	}

	last := hash()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			current := hash()
			if bytes.Equal(current, last) {
				continue
			}

			if err := reload(); err != nil {
				logger.Warn("tls auto-reload: reload failed, keeping previous certificate", "error", err)
				continue
			}

			last = current
			logger.Info("tls auto-reload: reloaded TLS certificate", "paths", paths)
		}
	}
}
