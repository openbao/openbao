// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/cli"
	remotedb "github.com/openbao/openbao/plugins/database/remote-db-plugin"
	proto "github.com/openbao/openbao/plugins/database/remote-db-plugin/proto/gen"
	"github.com/openbao/openbao/plugins/database/remote-db-plugin/runner"
	"github.com/posener/complete"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

// RelayRunCommand is the long-running spoke daemon. It connects to the hub's
// gRPC proxy port using mTLS (with credentials produced by `bao relay join`),
// dispatches inbound requests to a long-lived in-process plugin runner, and
// sends periodic heartbeats so the hub can mark the spoke healthy in
// `bao relay list`.
//
// The certificate's Common Name is the spoke's authoritative identity; the
// hub reads it off the verified peer cert. Concurrent in-flight requests are
// matched to responses via the AgentMessage.RequestId field and dispatched on
// independent goroutines so a slow plugin call never blocks others.
type RelayRunCommand struct {
	*BaseCommand

	flagServer            string
	flagCredentialsDir    string
	flagServerName        string
	flagHeartbeatInterval time.Duration
	flagMaxConcurrency    int
	flagRenewCheckEvery   time.Duration
	flagRenewThreshold    float64
}

var (
	_ cli.Command             = (*RelayRunCommand)(nil)
	_ cli.CommandAutocomplete = (*RelayRunCommand)(nil)
)

func (c *RelayRunCommand) Synopsis() string {
	return "Run the spoke daemon (connects to a hub and serves DB plugin requests)"
}

func (c *RelayRunCommand) Help() string {
	helpText := `
Usage: bao relay run [options]

  Long-running spoke daemon. Connects to a hub OpenBao's proxy gRPC port
  using the credentials produced by 'bao relay join', then serves database
  plugin requests in-process against locally-reachable databases.

  The credentials directory must contain:

      cert.pem    client cert issued by 'bao relay join'
      key.pem     matching private key
      ca.pem      spoke-CA root used to verify the hub

  Example:

      $ bao relay run \
          -server=hub.example.com:50053 \
          -credentials-dir=/etc/openbao-spoke

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *RelayRunCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetNone)
	f := set.NewFlagSet("Command Options")

	f.StringVar(&StringVar{
		Name:    "server",
		Target:  &c.flagServer,
		Default: "localhost:50053",
		Usage:   "Hub gRPC address (host:port).",
	})
	f.StringVar(&StringVar{
		Name:    "credentials-dir",
		Target:  &c.flagCredentialsDir,
		Default: "/etc/openbao-spoke",
		Usage:   "Directory containing cert.pem, key.pem, ca.pem.",
	})
	f.StringVar(&StringVar{
		Name:    "server-name",
		Target:  &c.flagServerName,
		Default: "",
		Usage:   "Override SNI / expected hub CN (defaults to the host part of -server).",
	})
	f.DurationVar(&DurationVar{
		Name:    "heartbeat-interval",
		Target:  &c.flagHeartbeatInterval,
		Default: 15 * time.Second,
		Usage:   "Liveness heartbeat cadence. 0 disables.",
	})
	f.IntVar(&IntVar{
		Name:    "max-concurrency",
		Target:  &c.flagMaxConcurrency,
		Default: 32,
		Usage:   "Max concurrent in-flight requests from the hub.",
	})
	f.DurationVar(&DurationVar{
		Name:    "renew-check-every",
		Target:  &c.flagRenewCheckEvery,
		Default: time.Hour,
		Usage:   "How often to check whether the client cert is past its renewal threshold. 0 disables auto-renewal.",
	})
	f.Float64Var(&Float64Var{
		Name:    "renew-threshold",
		Target:  &c.flagRenewThreshold,
		Default: 0.5,
		Usage:   "Renew when this fraction of the cert lifetime has elapsed (0.5 = half-life).",
	})
	return set
}

func (c *RelayRunCommand) AutocompleteArgs() complete.Predictor { return nil }
func (c *RelayRunCommand) AutocompleteFlags() complete.Flags    { return c.Flags().Completions() }

func (c *RelayRunCommand) Run(args []string) int {
	if err := c.Flags().Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	tlsCfg, err := loadSpokeTLS(c.flagCredentialsDir, c.flagServerName, c.flagServer)
	if err != nil {
		c.UI.Error(fmt.Sprintf("tls: %s", err))
		return 1
	}
	spokeName := tlsCfg.Certificates[0].Leaf.Subject.CommonName
	c.UI.Info(fmt.Sprintf("connecting to hub as spoke %q", spokeName))

	conn, err := grpc.NewClient(
		c.flagServer,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(remotedb.MaxMessageBytes),
			grpc.MaxCallSendMsgSize(remotedb.MaxMessageBytes),
		),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		c.UI.Error(fmt.Sprintf("dial: %s", err))
		return 1
	}
	defer func() { _ = conn.Close() }()

	// streamCtx is cancellable so a SIGINT/SIGTERM (or a send failure) can
	// unblock stream.Recv promptly instead of waiting on gRPC keepalive.
	streamCtx, cancelStream := context.WithCancel(context.Background())
	defer cancelStream()

	stream, err := proto.NewAgentServiceClient(conn).Connect(streamCtx)
	if err != nil {
		c.UI.Error(fmt.Sprintf("open stream: %s", err))
		return 1
	}

	// hbCtx scopes the heartbeat + renewal goroutines and the runner's idle
	// evictor. Cancelled from the sender goroutine when Send fails, and from
	// the graceful-shutdown path so those goroutines exit before we close
	// the send channel.
	hbCtx, cancelHB := context.WithCancel(context.Background())
	defer cancelHB()

	// stream.Send is not safe for concurrent calls. A single sender goroutine
	// drains sendCh and calls Send; producers (heartbeat, request handlers)
	// post through send() below. A senderWG tracks every goroutine that may
	// call send(), so the shutdown path can wait for them before closing
	// sendCh. Without that wait, a slow plugin call finishing after the recv
	// loop returns would send on a closed channel and panic.
	sendCh := make(chan *proto.AgentMessage, 64)
	sendDone := make(chan struct{})
	sendErrCh := make(chan error, 1)
	var senderWG sync.WaitGroup
	go func() {
		defer close(sendDone)
		for msg := range sendCh {
			if err := stream.Send(msg); err != nil {
				// Wrap with the failing message's metadata so the log line
				// names which request couldn't be delivered. The err itself
				// is the canonical cause.
				wrapped := fmt.Errorf("send failed (request_id=%q is_heartbeat=%t is_response=%t): %w",
					msg.RequestId, msg.IsHeartbeat, msg.IsResponse, err)
				select {
				case sendErrCh <- wrapped:
				default:
				}
				// Cancel hbCtx so heartbeat/renewal stop firing, and cancel
				// streamCtx so the recv loop unblocks instead of waiting on
				// keepalive. Drain the rest so producers don't block forever.
				cancelHB()
				cancelStream()
				for range sendCh {
				}
				return
			}
		}
	}()
	send := func(msg *proto.AgentMessage) error {
		select {
		case sendCh <- msg:
			return nil
		case <-sendDone:
			return fmt.Errorf("send: stream closed")
		}
	}

	if err := send(&proto.AgentMessage{ClientName: spokeName, IsResponse: false}); err != nil {
		c.UI.Error(fmt.Sprintf("register: %s", err))
		close(sendCh)
		<-sendDone
		return 1
	}
	ack, err := stream.Recv()
	if err != nil {
		c.UI.Error(fmt.Sprintf("recv ack: %s", err))
		close(sendCh)
		<-sendDone
		return 1
	}
	c.UI.Info(fmt.Sprintf("registered: %s", ack.Output))

	if c.flagHeartbeatInterval > 0 {
		senderWG.Add(1)
		go func() {
			defer senderWG.Done()
			runSpokeHeartbeat(hbCtx, send, spokeName, c.flagHeartbeatInterval, c.UI)
		}()
	}
	if c.flagRenewCheckEvery > 0 {
		// Renewal opens its own short-lived RPC; it doesn't write to sendCh,
		// so it isn't part of senderWG. hbCtx cancellation still stops it.
		go runCertRenewal(hbCtx, RenewSpokeCertInput{
			Server:         c.flagServer,
			ServerName:     c.flagServerName,
			CredentialsDir: c.flagCredentialsDir,
		}, c.flagRenewCheckEvery, c.flagRenewThreshold, c.UI)
	}

	r := runner.NewPluginRunner()
	// Evict cached plugin instances that haven't been touched within the TTL.
	// Catches mounts the hub forgot to Close (process crash, deleted while
	// the spoke was offline). hbCtx cancels on shutdown so the evictor exits
	// with the daemon.
	r.StartIdleEvictor(hbCtx)

	// Worker pool bounds concurrency. Each inbound request is dispatched on
	// a worker; the request_id flows back on the response so the hub can
	// match it to its waiter.
	sem := make(chan struct{}, c.flagMaxConcurrency)

	// Recv loop runs in a goroutine so the main goroutine can select between
	// it and the shutdown signal. recvErr is read after recvDone closes, so
	// no synchronization is needed.
	recvDone := make(chan struct{})
	var recvErr error
	go func() {
		defer close(recvDone)
		for {
			msg, err := stream.Recv()
			if err != nil {
				recvErr = err
				return
			}
			select {
			case sendErr := <-sendErrCh:
				recvErr = sendErr
				return
			default:
			}
			// Heartbeats and the initial Connected ack don't carry work.
			if msg.Command == "" || msg.IsResponse {
				continue
			}

			sem <- struct{}{}
			senderWG.Add(1)
			go func(m *proto.AgentMessage) {
				defer senderWG.Done()
				defer func() { <-sem }()
				output, execErr := r.ExecuteRequest(m.Command)
				resp := &proto.AgentMessage{
					ClientName: spokeName,
					RequestId:  m.RequestId,
					IsResponse: true,
				}
				if execErr != nil {
					resp.Error = execErr.Error()
				} else {
					resp.Output = output
				}
				if err := send(resp); err != nil {
					c.UI.Error(fmt.Sprintf("send response (req %s): %s", m.RequestId, err))
				}
			}(msg)
		}
	}()

	// Block until either SIGINT/SIGTERM or the recv loop returns on its own
	// (stream error, EOF, send-loop failure). When a signal arrives, cancel
	// the stream so Recv unblocks and the goroutine returns.
	shutdownCh := MakeShutdownCh()
	signaled := false
	select {
	case <-shutdownCh:
		c.UI.Info("shutdown signal received; draining")
		signaled = true
		cancelStream()
		<-recvDone
	case <-recvDone:
	}

	// Graceful drain. Ordering:
	//   1. senderWG.Wait — every goroutine that may still write sendCh exits.
	//      Until this returns, closing sendCh would risk send-on-closed.
	//   2. cancelHB — stop the renewal ticker and the runner's idle evictor.
	//      Heartbeat is already in senderWG.
	//   3. close(sendCh) + <-sendDone — sender drains anything buffered and
	//      exits cleanly.
	//   4. r.Shutdown — drops the slot ref on every cached plugin. In-flight
	//      handlers are already done (step 1), so each db.Close runs now.
	senderWG.Wait()
	cancelHB()
	close(sendCh)
	<-sendDone
	r.Shutdown()

	if signaled {
		return 0
	}
	if recvErr == nil || errors.Is(recvErr, io.EOF) {
		c.UI.Info("hub disconnected")
		return 0
	}
	if s, ok := status.FromError(recvErr); ok && s.Code() == codes.Canceled {
		// Stream was cancelled by the send-loop after a Send failure; the
		// real cause is in sendErrCh and was reported into recvErr.
		c.UI.Error(fmt.Sprintf("stream cancelled: %s", recvErr))
		return 1
	}
	c.UI.Error(fmt.Sprintf("stream error: %s", recvErr))
	return 1
}

// runCertRenewal ticks on `every` and renews the spoke's client cert once it
// passes the threshold fraction of its lifetime. Failures are logged and
// retried on the next tick — there is no point bailing out of the daemon
// because the hub is briefly unreachable. The renewed cert is written to
// disk; in-flight gRPC connections stay on the old cert until they
// reconnect, which is fine if renewal runs with a sensible threshold
// (default 0.5).
func runCertRenewal(ctx context.Context, in RenewSpokeCertInput, every time.Duration, threshold float64, ui cli.Ui) {
	t := time.NewTicker(every)
	defer t.Stop()
	// Check once at startup; an operator restarting a daemon with an
	// almost-expired cert shouldn't have to wait for the first tick.
	maybeRenew(ctx, in, threshold, ui)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			maybeRenew(ctx, in, threshold, ui)
		}
	}
}

func maybeRenew(ctx context.Context, in RenewSpokeCertInput, threshold float64, ui cli.Ui) {
	notBefore, notAfter, err := CurrentSpokeCertWindow(in.CredentialsDir)
	if err != nil {
		ui.Error(fmt.Sprintf("renew: read cert: %s", err))
		return
	}
	if !PastRenewalThreshold(notBefore, notAfter, threshold, time.Now()) {
		return
	}
	res, err := RenewSpokeCert(ctx, in)
	if err != nil {
		ui.Error(fmt.Sprintf("renew: %s", err))
		return
	}
	ui.Info(fmt.Sprintf("renewed cert for %q; new expiry %s", res.CommonName,
		res.NotAfter.UTC().Format(time.RFC3339)))
}

// runSpokeHeartbeat fires an IsHeartbeat frame every interval. Hub side
// increments its last-seen timestamp on receipt; the spoke considers itself
// dead when the stream errors out (Send will report and we just stop ticking).
func runSpokeHeartbeat(ctx context.Context, send func(*proto.AgentMessage) error, spokeName string, interval time.Duration, ui cli.Ui) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := send(&proto.AgentMessage{
				ClientName:  spokeName,
				IsHeartbeat: true,
			}); err != nil {
				ui.Error(fmt.Sprintf("heartbeat: %s", err))
				return
			}
		}
	}
}

// loadSpokeTLS reads cert/key/ca from credsDir and returns a tls.Config
// suitable for grpc.NewClient. The leaf cert is parsed so the CN is available
// as the spoke identity without a second open of the PEM file.
func loadSpokeTLS(credsDir, serverName, serverAddr string) (*tls.Config, error) {
	certPath := filepath.Join(credsDir, "cert.pem")
	keyPath := filepath.Join(credsDir, "key.pem")
	caPath := filepath.Join(credsDir, "ca.pem")

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load client cert/key from %s: %w", credsDir, err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse client cert: %w", err)
	}
	cert.Leaf = leaf

	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%s did not yield any CA certs", caPath)
	}

	// Verify the leaf chains to the bundled ca.pem before we hand it to gRPC.
	// A credentials directory left half-rotated (cert.pem from a fresh join,
	// ca.pem from the prior CA) would otherwise only surface as an opaque
	// TLS handshake error at the first gRPC dial — long after the operator
	// has left the terminal. Catch it here so `bao relay run` (and `bao
	// relay renew`) fail at startup with a clear cause. Mirrors the
	// hub-side check in bootstrap/state.go SetIdentity.
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		// The underlying err from x509.Verify already names the specific
		// cause (expired, not yet valid, KU mismatch, unknown authority).
		// Wrap with where to look, not a guess at why — "does not chain"
		// reads as "your ca.pem is wrong" even when the actual problem is
		// "your cert.pem expired, run bao relay join again".
		return nil, fmt.Errorf("spoke cert in %s failed verification: %w", credsDir, err)
	}

	if serverName == "" {
		host, _, _ := strings.Cut(serverAddr, ":")
		serverName = host
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		// Match the hub's floor (bootstrap/state.go pins TLS 1.3). Both sides
		// ship in the same bao binary, so there's no compatibility cost; the
		// asymmetric 1.2 floor here only mattered if a spoke ever talked to a
		// non-bao server, which it shouldn't.
		MinVersion: tls.VersionTLS13,
	}, nil
}
