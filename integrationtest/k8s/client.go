package k8s

import (
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func ClientFromKubeConfig(kubeContext string) (*kubernetes.Clientset, error) {
	config, err := kubeConfig(kubeContext)
	if err != nil {
		return nil, err
	}

	k8sClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	return k8sClient, nil
}

func kubeConfig(kubeContext string) (*rest.Config, error) {
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{
			CurrentContext: kubeContext,
		},
	).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to setup config: %w", err)
	}

	return config, nil
}
