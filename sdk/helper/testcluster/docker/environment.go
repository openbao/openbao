// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package docker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	mathrand "math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/volume"
	docker "github.com/docker/docker/client"
	"github.com/hashicorp/go-cleanhttp"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
	"github.com/openbao/openbao/api/v2"
	dockhelper "github.com/openbao/openbao/sdk/v2/helper/docker"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/helper/testcluster"
	uberAtomic "go.uber.org/atomic"
	"golang.org/x/net/http2"
)

var (
	_ testcluster.VaultCluster     = &DockerCluster{}
	_ testcluster.VaultClusterNode = &DockerClusterNode{}
)

const MaxClusterNameLength = 52

// DockerCluster is used to managing the lifecycle of the test Vault cluster
type DockerCluster struct {
	ClusterName string

	ClusterNodes []*DockerClusterNode

	// Certificate fields
	*testcluster.CA
	RootCAs *x509.CertPool

	barrierKeys  [][]byte
	recoveryKeys [][]byte
	tmpDir       string

	// rootToken is the initial root token created when the Vault cluster is
	// created.
	rootToken string
	DockerAPI *docker.Client
	ID        string
	Logger    log.Logger
	builtTags map[string]struct{}

	storage testcluster.ClusterStorage
}

func (dc *DockerCluster) NamedLogger(s string) log.Logger {
	return dc.Logger.Named(s)
}

func (dc *DockerCluster) ClusterID() string {
	return dc.ID
}

func (dc *DockerCluster) Nodes() []testcluster.VaultClusterNode {
	ret := make([]testcluster.VaultClusterNode, len(dc.ClusterNodes))
	for i := range dc.ClusterNodes {
		ret[i] = dc.ClusterNodes[i]
	}
	return ret
}

func (dc *DockerCluster) GetBarrierKeys() [][]byte {
	return dc.barrierKeys
}

func testKeyCopy(key []byte) []byte {
	result := make([]byte, len(key))
	copy(result, key)
	return result
}

func (dc *DockerCluster) GetRecoveryKeys() [][]byte {
	ret := make([][]byte, len(dc.recoveryKeys))
	for i, k := range dc.recoveryKeys {
		ret[i] = testKeyCopy(k)
	}
	return ret
}

func (dc *DockerCluster) GetBarrierOrRecoveryKeys() [][]byte {
	return dc.GetBarrierKeys()
}

func (dc *DockerCluster) SetBarrierKeys(keys [][]byte) {
	dc.barrierKeys = make([][]byte, len(keys))
	for i, k := range keys {
		dc.barrierKeys[i] = testKeyCopy(k)
	}
}

func (dc *DockerCluster) SetRecoveryKeys(keys [][]byte) {
	dc.recoveryKeys = make([][]byte, len(keys))
	for i, k := range keys {
		dc.recoveryKeys[i] = testKeyCopy(k)
	}
}

func (dc *DockerCluster) GetCACertPEMFile() string {
	return dc.CACertPEMFile
}

func (dc *DockerCluster) Cleanup() {
	dc.cleanup()
}

func (dc *DockerCluster) cleanup() error {
	var result *multierror.Error
	for _, node := range dc.ClusterNodes {
		if err := node.cleanup(); err != nil {
			result = multierror.Append(result, err)
		}
	}

	return result.ErrorOrNil()
}

// GetRootToken returns the root token of the cluster, if set
func (dc *DockerCluster) GetRootToken() string {
	return dc.rootToken
}

func (dc *DockerCluster) SetRootToken(s string) {
	dc.Logger.Trace("cluster root token changed", "helpful_env", fmt.Sprintf("BAO_TOKEN=%s BAO_CACERT=/openbao/config/ca.pem", s))
	dc.rootToken = s
}

func (n *DockerClusterNode) Name() string {
	return n.Cluster.ClusterName + "-" + n.NodeID
}

func (dc *DockerCluster) setupNode0(ctx context.Context) error {
	client := dc.ClusterNodes[0].client

	var resp *api.InitResponse
	var err error
	for ctx.Err() == nil {
		resp, err = client.Sys().Init(&api.InitRequest{
			SecretShares:    3,
			SecretThreshold: 3,
		})
		if err == nil && resp != nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	if resp == nil {
		return errors.New("nil response to init request")
	}

	for _, k := range resp.Keys {
		raw, err := hex.DecodeString(k)
		if err != nil {
			return err
		}
		dc.barrierKeys = append(dc.barrierKeys, raw)
	}

	for _, k := range resp.RecoveryKeys {
		raw, err := hex.DecodeString(k)
		if err != nil {
			return err
		}
		dc.recoveryKeys = append(dc.recoveryKeys, raw)
	}

	dc.rootToken = resp.RootToken
	client.SetToken(dc.rootToken)
	dc.ClusterNodes[0].client = client

	err = testcluster.UnsealNode(ctx, dc, 0)
	if err != nil {
		return err
	}

	err = ensureLeaderMatches(ctx, client, func(leader *api.LeaderResponse) error {
		if !leader.IsSelf {
			return fmt.Errorf("node %d leader=%v, expected=%v", 0, leader.IsSelf, true)
		}

		return nil
	})

	status, err := client.Sys().SealStatusWithContext(ctx)
	if err != nil {
		return err
	}
	dc.ID = status.ClusterID
	return err
}

func (dc *DockerCluster) clusterReady(ctx context.Context) error {
	for i, node := range dc.ClusterNodes {
		expectLeader := i == 0
		err := ensureLeaderMatches(ctx, node.client, func(leader *api.LeaderResponse) error {
			if expectLeader != leader.IsSelf {
				return fmt.Errorf("node %d leader=%v, expected=%v", i, leader.IsSelf, expectLeader)
			}

			return nil
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func (dc *DockerCluster) setupCA(opts *DockerClusterOptions) error {
	var err error
	var ca testcluster.CA

	if opts != nil && opts.CAKey != nil {
		ca.CAKey = opts.CAKey
	} else {
		ca.CAKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
	}

	var caBytes []byte
	if opts != nil && len(opts.CACert) > 0 {
		caBytes = opts.CACert
	} else {
		serialNumber := mathrand.New(mathrand.NewSource(time.Now().UnixNano())).Int63()
		CACertTemplate := &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "localhost",
			},
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			SerialNumber:          big.NewInt(serialNumber),
			NotBefore:             time.Now().Add(-30 * time.Second),
			NotAfter:              time.Now().Add(262980 * time.Hour),
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		caBytes, err = x509.CreateCertificate(rand.Reader, CACertTemplate, CACertTemplate, ca.CAKey.Public(), ca.CAKey)
		if err != nil {
			return err
		}
	}
	CACert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return err
	}
	ca.CACert = CACert
	ca.CACertBytes = caBytes

	CACertPEMBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	}
	ca.CACertPEM = pem.EncodeToMemory(CACertPEMBlock)

	ca.CACertPEMFile = filepath.Join(dc.tmpDir, "ca", "ca.pem")
	err = os.WriteFile(ca.CACertPEMFile, ca.CACertPEM, 0o755)
	if err != nil {
		return err
	}

	marshaledCAKey, err := x509.MarshalECPrivateKey(ca.CAKey)
	if err != nil {
		return err
	}
	CAKeyPEMBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: marshaledCAKey,
	}
	ca.CAKeyPEM = pem.EncodeToMemory(CAKeyPEMBlock)

	dc.CA = &ca

	return nil
}

func (n *DockerClusterNode) setupCert(ip string) error {
	var err error

	n.ServerKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	serialNumber := mathrand.New(mathrand.NewSource(time.Now().UnixNano())).Int63()
	certTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: n.Name(),
		},
		DNSNames:    []string{"localhost", n.Name()},
		IPAddresses: []net.IP{net.IPv6loopback, net.ParseIP("127.0.0.1"), net.ParseIP(ip)},
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		SerialNumber: big.NewInt(serialNumber),
		NotBefore:    time.Now().Add(-30 * time.Second),
		NotAfter:     time.Now().Add(262980 * time.Hour),
	}
	n.ServerCertBytes, err = x509.CreateCertificate(rand.Reader, certTemplate, n.Cluster.CACert, n.ServerKey.Public(), n.Cluster.CAKey)
	if err != nil {
		return err
	}
	n.ServerCert, err = x509.ParseCertificate(n.ServerCertBytes)
	if err != nil {
		return err
	}
	n.ServerCertPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: n.ServerCertBytes,
	})

	marshaledKey, err := x509.MarshalECPrivateKey(n.ServerKey)
	if err != nil {
		return err
	}
	n.ServerKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: marshaledKey,
	})

	n.ServerCertPEMFile = filepath.Join(n.WorkDir, "cert.pem")
	err = os.WriteFile(n.ServerCertPEMFile, n.ServerCertPEM, 0o755)
	if err != nil {
		return err
	}

	n.ServerKeyPEMFile = filepath.Join(n.WorkDir, "key.pem")
	err = os.WriteFile(n.ServerKeyPEMFile, n.ServerKeyPEM, 0o755)
	if err != nil {
		return err
	}

	tlsCert, err := tls.X509KeyPair(n.ServerCertPEM, n.ServerKeyPEM)
	if err != nil {
		return err
	}

	certGetter := NewCertificateGetter(n.ServerCertPEMFile, n.ServerKeyPEMFile, "")
	if err := certGetter.Reload(); err != nil {
		return err
	}
	tlsConfig := &tls.Config{
		Certificates:   []tls.Certificate{tlsCert},
		RootCAs:        n.Cluster.RootCAs,
		ClientCAs:      n.Cluster.RootCAs,
		ClientAuth:     tls.RequestClientCert,
		NextProtos:     []string{"h2", "http/1.1"},
		GetCertificate: certGetter.GetCertificate,
	}

	n.tlsConfig = tlsConfig

	err = os.WriteFile(filepath.Join(n.WorkDir, "ca.pem"), n.Cluster.CACertPEM, 0o755)
	if err != nil {
		return err
	}
	return nil
}

func NewTestDockerCluster(t *testing.T, opts *DockerClusterOptions) *DockerCluster {
	if opts == nil {
		opts = &DockerClusterOptions{}
	}
	if opts.ClusterName == "" {
		opts.ClusterName = strings.ReplaceAll(t.Name(), "/", "-")
	}
	if opts.Logger == nil {
		opts.Logger = logging.NewVaultLogger(log.Trace).Named(t.Name())
	}
	if opts.NetworkName == "" {
		opts.NetworkName = os.Getenv("TEST_DOCKER_NETWORK_NAME")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)

	dc, err := NewDockerCluster(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	dc.Logger.Trace("cluster started", "helpful_env", fmt.Sprintf("BAO_TOKEN=%s BAO_CACERT=/openbao/config/ca.pem", dc.GetRootToken()))
	return dc
}

func NewDockerCluster(ctx context.Context, opts *DockerClusterOptions) (*DockerCluster, error) {
	api, err := dockhelper.NewDockerAPI()
	if err != nil {
		return nil, err
	}

	if opts == nil {
		opts = &DockerClusterOptions{}
	}
	if opts.Logger == nil {
		opts.Logger = log.NewNullLogger()
	}

	dc := &DockerCluster{
		DockerAPI:   api,
		ClusterName: opts.ClusterName,
		Logger:      opts.Logger,
		builtTags:   map[string]struct{}{},
		CA:          opts.CA,
		storage:     opts.Storage,
	}

	if err := dc.setupDockerCluster(ctx, opts); err != nil {
		dc.Cleanup()
		return nil, err
	}

	return dc, nil
}

// DockerClusterNode represents a single instance of Vault in a cluster
type DockerClusterNode struct {
	NodeID               string
	HostPort             string
	client               *api.Client
	ServerCert           *x509.Certificate
	ServerCertBytes      []byte
	ServerCertPEM        []byte
	ServerCertPEMFile    string
	ServerKey            *ecdsa.PrivateKey
	ServerKeyPEM         []byte
	ServerKeyPEMFile     string
	tlsConfig            *tls.Config
	WorkDir              string
	Cluster              *DockerCluster
	Container            *types.ContainerJSON
	DockerAPI            *docker.Client
	Service              *dockhelper.Service
	Runner               *dockhelper.Runner
	Logger               log.Logger
	cleanupContainer     func()
	RealAPIAddr          string
	ContainerNetworkName string
	ContainerIPAddress   string
	ImageRepo            string
	ImageTag             string
	DataVolumeName       string
	cleanupVolume        func()
}

func (n *DockerClusterNode) TLSConfig() *tls.Config {
	return n.tlsConfig.Clone()
}

func (n *DockerClusterNode) APIClient() *api.Client {
	// We clone to ensure that whenever this method is called, the caller gets
	// back a pristine client, without e.g. any namespace or token changes that
	// might pollute a shared client.  We clone the config instead of the
	// client because (1) Client.clone propagates the replicationStateStore and
	// the httpClient pointers, (2) it doesn't copy the tlsConfig at all, and
	// (3) if clone returns an error, it doesn't feel as appropriate to panic
	// below.  Who knows why clone might return an error?
	cfg := n.client.CloneConfig()
	client, err := api.NewClient(cfg)
	if err != nil {
		// It seems fine to panic here, since this should be the same input
		// we provided to NewClient when we were setup, and we didn't panic then.
		// Better not to completely ignore the error though, suppose there's a
		// bug in CloneConfig?
		panic(fmt.Sprintf("NewClient error on cloned config: %v", err))
	}
	client.SetToken(n.Cluster.rootToken)
	return client
}

// NewAPIClient creates and configures a Vault API client to communicate with
// the running Vault Cluster for this DockerClusterNode
func (n *DockerClusterNode) apiConfig() (*api.Config, error) {
	transport := cleanhttp.DefaultPooledTransport()
	transport.TLSClientConfig = n.TLSConfig()
	if err := http2.ConfigureTransport(transport); err != nil {
		return nil, err
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			// This can of course be overridden per-test by using its own client
			return errors.New("redirects not allowed in these tests")
		},
	}
	config := api.DefaultConfig()
	if config.Error != nil {
		return nil, config.Error
	}
	config.Address = fmt.Sprintf("https://%s", n.HostPort)
	config.HttpClient = client
	config.MaxRetries = 0
	return config, nil
}

func (n *DockerClusterNode) newAPIClient() (*api.Client, error) {
	config, err := n.apiConfig()
	if err != nil {
		return nil, err
	}
	client, err := api.NewClient(config)
	if err != nil {
		return nil, err
	}
	client.SetToken(n.Cluster.GetRootToken())
	return client, nil
}

// Cleanup kills the container of the node and deletes its data volume
func (n *DockerClusterNode) Cleanup() {
	n.cleanup()
}

// Stop kills the container of the node
func (n *DockerClusterNode) Stop() {
	n.cleanupContainer()
}

func (n *DockerClusterNode) cleanup() error {
	if n.Container == nil || n.Container.ID == "" {
		return nil
	}
	n.cleanupContainer()
	n.cleanupVolume()
	return nil
}

func (n *DockerClusterNode) Start(ctx context.Context, opts *DockerClusterOptions) error {
	if n.DataVolumeName == "" {
		vol, err := n.DockerAPI.VolumeCreate(ctx, volume.CreateOptions{})
		if err != nil {
			return err
		}
		n.DataVolumeName = vol.Name
		n.cleanupVolume = func() {
			_ = n.DockerAPI.VolumeRemove(ctx, vol.Name, false)
		}
	}
	vaultCfg := map[string]interface{}{}
	ports := []string{"8200/tcp", "8201/tcp"}
	listeners := []interface{}{
		map[string]interface{}{
			"tcp": map[string]interface{}{
				"address":       fmt.Sprintf("%s:%d", "0.0.0.0", 8200),
				"tls_cert_file": "/openbao/config/cert.pem",
				"tls_key_file":  "/openbao/config/key.pem",
				"telemetry": map[string]interface{}{
					"unauthenticated_metrics_access": true,
				},
			},
		},
	}
	if opts.ClusterOptions.VaultNodeConfig != nil && opts.ClusterOptions.VaultNodeConfig.AdditionalListeners != nil {
		lsCfg := opts.ClusterOptions.VaultNodeConfig.AdditionalListeners
		listeners = append(listeners, lsCfg...)
		for _, lCfgRaw := range lsCfg {
			lCfg := lCfgRaw.(map[string]interface{})
			for lType, lValueRaw := range lCfg {
				if lType == "unix" {
					continue
				}

				lValue := lValueRaw.(map[string]interface{})
				address, ok := lValue["address"].(string)
				if !ok {
					continue
				}

				host, port, err := net.SplitHostPort(address)
				if err != nil {
					return fmt.Errorf("failed to split host/port in listener config: %w\n\tcfg: %#v", err, lValue)
				}

				if host != "127.0.0.1" && host != "localhost" {
					ports = append(ports, fmt.Sprintf("%v/%v", port, lType))
				}
			}
		}
	}
	vaultCfg["listener"] = listeners

	vaultCfg["telemetry"] = map[string]interface{}{
		"disable_hostname": true,
	}

	// Setup storage. Default is raft.
	storageType := "raft"
	storageOpts := map[string]interface{}{
		// TODO add options from vnc
		"path":    "/openbao/file",
		"node_id": n.NodeID,
	}

	if opts.Storage != nil {
		storageType = opts.Storage.Type()
		storageOpts = opts.Storage.Opts()
	}

	if opts != nil && opts.VaultNodeConfig != nil {
		for k, v := range opts.VaultNodeConfig.StorageOptions {
			if _, ok := storageOpts[k].(string); !ok {
				storageOpts[k] = v
			}
		}
	}
	vaultCfg["storage"] = map[string]interface{}{
		storageType: storageOpts,
	}

	//// disable_mlock is required for working in the Docker environment with
	//// custom plugins
	vaultCfg["disable_mlock"] = true
	vaultCfg["api_addr"] = `https://{{- GetAllInterfaces | exclude "flags" "loopback" | attr "address" -}}:8200`
	vaultCfg["cluster_addr"] = `https://{{- GetAllInterfaces | exclude "flags" "loopback" | attr "address" -}}:8201`

	vaultCfg["administrative_namespace_path"] = opts.AdministrativeNamespacePath

	systemJSON, err := json.Marshal(vaultCfg)
	if err != nil {
		return err
	}
	err = os.WriteFile(filepath.Join(n.WorkDir, "system.json"), systemJSON, 0o644)
	if err != nil {
		return err
	}

	if opts.VaultNodeConfig != nil {
		localCfg := *opts.VaultNodeConfig
		userJSON, err := json.Marshal(localCfg)
		if err != nil {
			return err
		}
		err = os.WriteFile(filepath.Join(n.WorkDir, "user.json"), userJSON, 0o644)
		if err != nil {
			return err
		}
	}

	// Create a temporary cert so vault will start up
	err = n.setupCert("127.0.0.1")
	if err != nil {
		return err
	}

	caDir := filepath.Join(n.Cluster.tmpDir, "ca")

	// setup plugin bin copy if needed
	copyFromTo := map[string]string{
		n.WorkDir: "/openbao/config",
		caDir:     "/usr/local/share/ca-certificates/",
	}

	var wg sync.WaitGroup
	wg.Add(1)
	var seenLogs uberAtomic.Bool
	logConsumer := func(s string) {
		if seenLogs.CAS(false, true) {
			wg.Done()
		}
		n.Logger.Trace(s)
	}
	logStdout := &LogConsumerWriter{logConsumer}
	logStderr := &LogConsumerWriter{func(s string) {
		if seenLogs.CAS(false, true) {
			wg.Done()
		}
		testcluster.JSONLogNoTimestamp(n.Logger, s)
	}}

	env := []string{
		// For now we're using disable_mlock, because this is for testing
		// anyway, and because it prevents us using external plugins.
		"SKIP_SETCAP=true",
		"BAO_LOG_FORMAT=json",
	}
	if opts.Root {
		env = append(env, "BAO_SKIP_DROP_ROOT=true")
	}

	r, err := dockhelper.NewServiceRunner(dockhelper.RunOptions{
		ImageRepo: n.ImageRepo,
		ImageTag:  n.ImageTag,
		// We don't need to run update-ca-certificates in the container, because
		// we're providing the CA in the raft join call, and otherwise Vault
		// servers don't talk to one another on the API port.
		Cmd:             append([]string{"server"}, opts.Args...),
		Env:             env,
		Ports:           ports,
		ContainerName:   n.Name(),
		NetworkName:     opts.NetworkName,
		CopyFromTo:      copyFromTo,
		LogConsumer:     logConsumer,
		LogStdout:       logStdout,
		LogStderr:       logStderr,
		PreDelete:       true,
		DoNotAutoRemove: true,
		PostStart: func(containerID string, realIP string) error {
			err := n.setupCert(realIP)
			if err != nil {
				return err
			}

			// If we signal Vault before it installs its sighup handler, it'll die.
			wg.Wait()
			n.Logger.Trace("running poststart", "containerID", containerID, "IP", realIP)
			return n.Runner.RefreshFiles(ctx, containerID)
		},
		Capabilities:      []string{"NET_ADMIN"},
		OmitLogTimestamps: true,
		VolumeNameToMountPoint: map[string]string{
			n.DataVolumeName: "/openbao/file",
		},
	})
	if err != nil {
		return err
	}
	n.Runner = r

	probe := opts.StartProbe
	if probe == nil {
		probe = func(c *api.Client) error {
			_, err = c.Sys().SealStatus()
			return err
		}
	}
	svc, _, err := r.StartNewService(ctx, false, false, func(ctx context.Context, host string, port int) (dockhelper.ServiceConfig, error) {
		config, err := n.apiConfig()
		if err != nil {
			return nil, err
		}
		config.Address = fmt.Sprintf("https://%s:%d", host, port)
		client, err := api.NewClient(config)
		if err != nil {
			return nil, err
		}
		err = probe(client)
		if err != nil {
			return nil, err
		}

		return dockhelper.NewServiceHostPort(host, port), nil
	})
	if err != nil {
		return err
	}

	n.Service = svc
	n.HostPort = svc.Config.Address()
	n.Container = svc.Container
	netName := opts.NetworkName
	if netName == "" {
		if len(svc.Container.NetworkSettings.Networks) > 1 {
			return fmt.Errorf("Set d.RunOptions.NetworkName instead for container with multiple networks: %v", svc.Container.NetworkSettings.Networks)
		}
		for netName = range svc.Container.NetworkSettings.Networks {
			// Networks above is a map; we just need to find the first and
			// only key of this map (network name). The range handles this
			// for us, but we need a loop construction in order to use range.
		}
	}
	n.ContainerNetworkName = netName
	n.ContainerIPAddress = svc.Container.NetworkSettings.Networks[netName].IPAddress
	n.RealAPIAddr = "https://" + n.ContainerIPAddress + ":8200"
	n.cleanupContainer = svc.Cleanup

	client, err := n.newAPIClient()
	if err != nil {
		return err
	}
	client.SetToken(n.Cluster.rootToken)
	n.client = client
	return nil
}

func (n *DockerClusterNode) Pause(ctx context.Context) error {
	return n.DockerAPI.ContainerPause(ctx, n.Container.ID)
}

func (n *DockerClusterNode) AddNetworkDelay(ctx context.Context, delay time.Duration, targetIP string) error {
	ip := net.ParseIP(targetIP)
	if ip == nil {
		return fmt.Errorf("targetIP %q is not an IP address", targetIP)
	}
	// Let's attempt to get a unique handle for the filter rule; we'll assume that
	// every targetIP has a unique last octet, which is true currently for how
	// we're doing docker networking.
	lastOctet := ip.To4()[3]

	stdout, stderr, exitCode, err := n.Runner.RunCmdWithOutput(ctx, n.Container.ID, []string{
		"/bin/sh",
		"-xec", strings.Join([]string{
			fmt.Sprintf("echo isolating node %s", targetIP),
			"apk add iproute2",
			// If we're running this script a second time on the same node,
			// the add dev will fail; since we only want to run the netem
			// command once, we'll do so in the case where the add dev doesn't fail.
			"tc qdisc add dev eth0 root handle 1: prio && " +
				fmt.Sprintf("tc qdisc add dev eth0 parent 1:1 handle 2: netem delay %dms", delay/time.Millisecond),
			// Here we create a u32 filter as per https://man7.org/linux/man-pages/man8/tc-u32.8.html
			// Its parent is 1:0 (which I guess is the root?)
			// Its handle must be unique, so we base it on targetIP
			fmt.Sprintf("tc filter add dev eth0 parent 1:0 protocol ip pref 55 handle ::%x u32 match ip dst %s flowid 2:1", lastOctet, targetIP),
		}, "; "),
	})
	if err != nil {
		return err
	}

	n.Logger.Trace(string(stdout))
	n.Logger.Trace(string(stderr))
	if exitCode != 0 {
		return fmt.Errorf("got nonzero exit code from iptables: %d", exitCode)
	}
	return nil
}

// PartitionFromCluster will cause the node to be disconnected at the network
// level from the rest of the docker cluster. It does so in a way that the node
// will not see TCP RSTs and all packets it sends will be "black holed". It
// attempts to keep packets to and from the host intact which allows docker
// daemon to continue streaming logs and any test code to continue making
// requests from the host to the partitioned node.
func (n *DockerClusterNode) PartitionFromCluster(ctx context.Context) error {
	stdout, stderr, exitCode, err := n.Runner.RunCmdWithOutput(ctx, n.Container.ID, []string{
		"/bin/sh",
		"-xec", strings.Join([]string{
			fmt.Sprintf("echo partitioning container from network"),
			"apk add iproute2",
			// Get the gateway address for the bridge so we can allow host to
			// container traffic still.
			"GW=$(ip r | grep default | grep eth0 | cut -f 3 -d' ')",
			// First delete the rules in case this is called twice otherwise we'll add
			// multiple copies and only remove one in Unpartition (yay iptables).
			// Ignore the error if it didn't exist.
			"iptables -D INPUT -i eth0 ! -s \"$GW\" -j DROP | true",
			"iptables -D OUTPUT -o eth0 ! -d \"$GW\" -j DROP | true",
			// Add rules to drop all packets in and out of the docker network
			// connection.
			"iptables -I INPUT -i eth0 ! -s \"$GW\" -j DROP",
			"iptables -I OUTPUT -o eth0 ! -d \"$GW\" -j DROP",
		}, "; "),
	})
	if err != nil {
		return err
	}

	n.Logger.Trace(string(stdout))
	n.Logger.Trace(string(stderr))
	if exitCode != 0 {
		return fmt.Errorf("got nonzero exit code from iptables: %d", exitCode)
	}
	return nil
}

// UnpartitionFromCluster reverses a previous call to PartitionFromCluster and
// restores full connectivity. Currently assumes the default "bridge" network.
func (n *DockerClusterNode) UnpartitionFromCluster(ctx context.Context) error {
	stdout, stderr, exitCode, err := n.Runner.RunCmdWithOutput(ctx, n.Container.ID, []string{
		"/bin/sh",
		"-xec", strings.Join([]string{
			fmt.Sprintf("echo un-partitioning container from network"),
			// Get the gateway address for the bridge so we can allow host to
			// container traffic still.
			"GW=$(ip r | grep default | grep eth0 | cut -f 3 -d' ')",
			// Remove the rules, ignore if they are not present or iptables wasn't
			// installed yet (i.e. no-one called PartitionFromCluster yet).
			"iptables -D INPUT -i eth0 ! -s \"$GW\" -j DROP | true",
			"iptables -D OUTPUT -o eth0 ! -d \"$GW\" -j DROP | true",
		}, "; "),
	})
	if err != nil {
		return err
	}

	n.Logger.Trace(string(stdout))
	n.Logger.Trace(string(stderr))
	if exitCode != 0 {
		return fmt.Errorf("got nonzero exit code from iptables: %d", exitCode)
	}
	return nil
}

type LogConsumerWriter struct {
	consumer func(string)
}

func (l LogConsumerWriter) Write(p []byte) (n int, err error) {
	// TODO this assumes that we're never passed partial log lines, which
	// seems a safe assumption for now based on how docker looks to implement
	// logging, but might change in the future.
	scanner := bufio.NewScanner(bytes.NewReader(p))
	scanner.Buffer(make([]byte, 64*1024), bufio.MaxScanTokenSize)
	for scanner.Scan() {
		l.consumer(scanner.Text())
	}
	return len(p), nil
}

// DockerClusterOptions has options for setting up the docker cluster
type DockerClusterOptions struct {
	testcluster.ClusterOptions
	CAKey       *ecdsa.PrivateKey
	NetworkName string
	ImageRepo   string
	ImageTag    string
	CA          *testcluster.CA
	VaultBinary string
	Args        []string
	StartProbe  func(*api.Client) error
	Storage     testcluster.ClusterStorage
	Root        bool
	Entrypoint  string
}

func DefaultOptions(t *testing.T) *DockerClusterOptions {
	return &DockerClusterOptions{
		ImageRepo:   "quay.io/openbao/openbao",
		ImageTag:    "latest",
		VaultBinary: api.ReadBaoVariable("BAO_BINARY"),
		ClusterOptions: testcluster.ClusterOptions{
			NumCores:    3,
			ClusterName: strings.ReplaceAll(t.Name(), "/", "-"),
			VaultNodeConfig: &testcluster.VaultNodeConfig{
				LogLevel: "TRACE",
			},
		},
	}
}

func ensureLeaderMatches(ctx context.Context, client *api.Client, ready func(response *api.LeaderResponse) error) error {
	var leader *api.LeaderResponse
	var err error
	for ctx.Err() == nil {
		leader, err = client.Sys().Leader()
		switch {
		case err != nil:
		case leader == nil:
			err = errors.New("nil response to leader check")
		default:
			err = ready(leader)
			if err == nil {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("error checking leader: %v", err)
}

const DefaultNumCores = 3

// creates a managed docker container running Vault
func (dc *DockerCluster) setupDockerCluster(ctx context.Context, opts *DockerClusterOptions) error {
	if opts.TmpDir != "" {
		if _, err := os.Stat(opts.TmpDir); os.IsNotExist(err) {
			if err := os.MkdirAll(opts.TmpDir, 0o700); err != nil {
				return err
			}
		}
		dc.tmpDir = opts.TmpDir
	} else {
		tempDir, err := os.MkdirTemp("", "vault-test-cluster-")
		if err != nil {
			return err
		}
		dc.tmpDir = tempDir
	}
	caDir := filepath.Join(dc.tmpDir, "ca")
	if err := os.MkdirAll(caDir, 0o755); err != nil {
		return err
	}

	var numCores int
	if opts.NumCores == 0 {
		numCores = DefaultNumCores
	} else {
		numCores = opts.NumCores
	}

	if dc.CA == nil {
		if err := dc.setupCA(opts); err != nil {
			return err
		}
	}
	dc.RootCAs = x509.NewCertPool()
	dc.RootCAs.AddCert(dc.CA.CACert)

	if dc.storage != nil {
		if err := dc.storage.Start(ctx, &opts.ClusterOptions); err != nil {
			return err
		}
	}

	for i := 0; i < numCores; i++ {
		if err := dc.addNode(ctx, opts); err != nil {
			return err
		}
		if opts.SkipInit {
			continue
		}
		if i == 0 {
			if err := dc.setupNode0(ctx); err != nil {
				return nil
			}
		} else {
			if err := dc.joinNode(ctx, i, 0); err != nil {
				return err
			}
		}
	}

	return nil
}

func (dc *DockerCluster) AddNode(ctx context.Context, opts *DockerClusterOptions) error {
	leaderIdx, err := testcluster.LeaderNode(ctx, dc)
	if err != nil {
		return err
	}
	if err := dc.addNode(ctx, opts); err != nil {
		return err
	}

	return dc.joinNode(ctx, len(dc.ClusterNodes)-1, leaderIdx)
}

func (dc *DockerCluster) addNode(ctx context.Context, opts *DockerClusterOptions) error {
	tag, err := dc.setupImage(ctx, opts)
	if err != nil {
		return err
	}
	i := len(dc.ClusterNodes)
	nodeID := fmt.Sprintf("core-%d", i)
	node := &DockerClusterNode{
		DockerAPI: dc.DockerAPI,
		NodeID:    nodeID,
		Cluster:   dc,
		WorkDir:   filepath.Join(dc.tmpDir, nodeID),
		Logger:    dc.Logger.Named(nodeID),
		ImageRepo: opts.ImageRepo,
		ImageTag:  tag,
	}
	dc.ClusterNodes = append(dc.ClusterNodes, node)
	if err := os.MkdirAll(node.WorkDir, 0o755); err != nil {
		return err
	}
	if err := node.Start(ctx, opts); err != nil {
		return err
	}
	return nil
}

func (dc *DockerCluster) joinNode(ctx context.Context, nodeIdx int, leaderIdx int) error {
	if dc.storage != nil && dc.storage.Type() != "raft" {
		// Storage is not raft so nothing to do but unseal.
		return testcluster.UnsealNode(ctx, dc, nodeIdx)
	}

	leader := dc.ClusterNodes[leaderIdx]

	if nodeIdx >= len(dc.ClusterNodes) {
		return fmt.Errorf("invalid node %d", nodeIdx)
	}
	node := dc.ClusterNodes[nodeIdx]
	client := node.APIClient()

	var resp *api.RaftJoinResponse
	resp, err := client.Sys().RaftJoinWithContext(ctx, &api.RaftJoinRequest{
		// When running locally on a bridge network, the containers must use their
		// actual (private) IP to talk to one another.  Our code must instead use
		// the portmapped address since we're not on their network in that case.
		LeaderAPIAddr:    leader.RealAPIAddr,
		LeaderCACert:     string(dc.CACertPEM),
		LeaderClientCert: string(node.ServerCertPEM),
		LeaderClientKey:  string(node.ServerKeyPEM),
	})
	if resp == nil || !resp.Joined {
		return fmt.Errorf("nil or negative response from raft join request: %v", resp)
	}
	if err != nil {
		return fmt.Errorf("failed to join cluster: %w", err)
	}

	return testcluster.UnsealNode(ctx, dc, nodeIdx)
}

func (dc *DockerCluster) setupImage(ctx context.Context, opts *DockerClusterOptions) (string, error) {
	if opts == nil {
		opts = &DockerClusterOptions{}
	}
	sourceTag := opts.ImageTag
	if sourceTag == "" {
		sourceTag = "latest"
	}

	if opts.VaultBinary == "" {
		return sourceTag, nil
	}

	suffix := "testing"
	if sha := os.Getenv("COMMIT_SHA"); sha != "" {
		suffix = sha
	}
	tag := sourceTag + "-" + suffix
	if _, ok := dc.builtTags[tag]; ok {
		return tag, nil
	}

	f, err := os.Open(opts.VaultBinary)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	bCtx := dockhelper.NewBuildContext()
	bCtx["bao"] = &dockhelper.FileContents{
		Data: data,
		Mode: 0o755,
	}

	if len(opts.Entrypoint) > 0 {
		ef, err := os.Open(opts.Entrypoint)
		if err != nil {
			return "", err
		}
		defer ef.Close()

		edata, err := io.ReadAll(ef)
		if err != nil {
			return "", err
		}

		bCtx["entrypoint"] = &dockhelper.FileContents{
			Data: edata,
			Mode: 0o755,
		}
	}

	containerFile := fmt.Sprintf(`
FROM %s:%s
COPY bao /bin/bao
`, opts.ImageRepo, sourceTag)

	if opts.Root {
		containerFile += "USER root\n"
	}
	if len(opts.Entrypoint) > 0 {
		containerFile += "COPY entrypoint /usr/local/bin/docker-entrypoint.sh\n"
	}

	_, err = dockhelper.BuildImage(ctx, dc.DockerAPI, containerFile, bCtx,
		dockhelper.BuildRemove(true), dockhelper.BuildForceRemove(true),
		dockhelper.BuildPullParent(true),
		dockhelper.BuildTags([]string{opts.ImageRepo + ":" + tag}))
	if err != nil {
		return "", err
	}
	dc.builtTags[tag] = struct{}{}
	return tag, nil
}

/* Notes on testing the non-bridge network case:
- you need the test itself to be running in a container so that it can use
  the network; create the network using
    docker network create testvault
- this means that you need to mount the docker socket in that test container,
  but on macos there's stuff that prevents that from working; to hack that,
  on the host run
    sudo ln -s "$HOME/Library/Containers/com.docker.docker/Data/docker.raw.sock" /var/run/docker.sock.raw
- run the test container like
    docker run --rm -it --network testvault \
      -v /var/run/docker.sock.raw:/var/run/docker.sock \
      -v $(pwd):/home/circleci/go/src/github.com/openbao/openbao/ \
      -w /home/circleci/go/src/github.com/openbao/openbao/ \
      "docker.mirror.hashicorp.services/cimg/go:1.19.2" /bin/bash
- in the container you may need to chown/chmod /var/run/docker.sock; use `docker ps`
  to test if it's working

*/
