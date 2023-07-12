package k8s

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

func SetupPortForwarding(kubeContext, namespace, pod string) (localPort int, close func(), err error) {
	config, err := kubeConfig(kubeContext)
	if err != nil {
		return 0, nil, err
	}

	k8sClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create client: %w", err)
	}

	url := k8sClient.CoreV1().RESTClient().Post().Resource("pods").Namespace(namespace).Name(pod).SubResource("portforward").URL()
	transport, upgrader, err := spdy.RoundTripperFor(config)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create transport: %w", err)
	}

	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, "POST", url)
	stopChan := make(chan struct{})
	readyChan := make(chan struct{})

	// Listen on random available local port, forwarding to 8200 in the Vault container.
	forwarder, err := portforward.New(dialer, []string{"0:8200"}, stopChan, readyChan, ioutil.Discard, os.Stderr)
	if err != nil {
		return 0, nil, err
	}

	errChan := make(chan error)
	go func() {
		if err := forwarder.ForwardPorts(); err != nil {
			errChan <- err
		}
	}()

	select {
	case err = <-errChan:
		return 0, nil, fmt.Errorf("failed to start forwarding: %w", err)
	case <-readyChan:
		break
	}

	if ports, err := forwarder.GetPorts(); err != nil {
		return 0, nil, fmt.Errorf("failed to get forwarded ports: %w", err)
	} else {
		localPort = int(ports[0].Local)
	}

	return localPort, func() {
		stopChan <- struct{}{}
		forwarder.Close()
	}, nil
}
