// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cluster

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/hashicorp/go-hclog"
)

func TestInmemCluster_Connect(t *testing.T) {
	cluster, err := NewInmemLayerCluster("c1", 3, log.New(&log.LoggerOptions{
		Mutex: &sync.Mutex{},
		Level: log.Trace,
		Name:  "inmem-cluster",
	}))
	if err != nil {
		t.Fatal(err)
	}

	server := cluster.layers[0]

	listener := server.Listeners()[0]
	var accepted int
	stopCh := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stopCh:
				return
			default:
			}

			listener.SetDeadline(time.Now().Add(5 * time.Second))

			_, err := listener.Accept()
			if err != nil {
				return
			}

			accepted++

		}
	}()

	// Make sure two nodes can connect in
	conn, err := cluster.layers[1].DialContext(t.Context(), server.addr, nil)
	if err != nil {
		t.Fatal(err)
	}

	if conn == nil {
		t.Fatal("nil conn")
	}

	conn, err = cluster.layers[2].DialContext(t.Context(), server.addr, nil)
	if err != nil {
		t.Fatal(err)
	}

	if conn == nil {
		t.Fatal("nil conn")
	}

	close(stopCh)
	wg.Wait()

	if accepted != 2 {
		t.Fatalf("expected 2 connections to be accepted, got %d", accepted)
	}
}

func TestInmemCluster_Disconnect(t *testing.T) {
	cluster, err := NewInmemLayerCluster("c1", 3, log.New(&log.LoggerOptions{
		Mutex: &sync.Mutex{},
		Level: log.Trace,
		Name:  "inmem-cluster",
	}))
	if err != nil {
		t.Fatal(err)
	}

	server := cluster.layers[0]
	server.Disconnect(cluster.layers[1].addr)

	listener := server.Listeners()[0]
	var accepted int
	stopCh := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stopCh:
				return
			default:
			}

			listener.SetDeadline(time.Now().Add(5 * time.Second))

			_, err := listener.Accept()
			if err != nil {
				return
			}

			accepted++

		}
	}()

	// Make sure node1 cannot connect in
	conn, err := cluster.layers[1].DialContext(t.Context(), server.addr, nil)
	if err == nil {
		t.Fatal("expected error")
	}

	if conn != nil {
		t.Fatal("expected nil conn")
	}

	// Node2 should be able to connect
	conn, err = cluster.layers[2].DialContext(t.Context(), server.addr, nil)
	if err != nil {
		t.Fatal(err)
	}

	if conn == nil {
		t.Fatal("nil conn")
	}

	close(stopCh)
	wg.Wait()

	if accepted != 1 {
		t.Fatalf("expected 1 connections to be accepted, got %d", accepted)
	}
}

func TestInmemCluster_DisconnectAll(t *testing.T) {
	cluster, err := NewInmemLayerCluster("c1", 3, log.New(&log.LoggerOptions{
		Mutex: &sync.Mutex{},
		Level: log.Trace,
		Name:  "inmem-cluster",
	}))
	if err != nil {
		t.Fatal(err)
	}

	server := cluster.layers[0]
	server.DisconnectAll()

	// Make sure nodes cannot connect in
	conn, err := cluster.layers[1].DialContext(t.Context(), server.addr, nil)
	if err == nil {
		t.Fatal("expected error")
	}

	if conn != nil {
		t.Fatal("expected nil conn")
	}

	conn, err = cluster.layers[2].DialContext(t.Context(), server.addr, nil)
	if err == nil {
		t.Fatal("expected error")
	}

	if conn != nil {
		t.Fatal("expected nil conn")
	}
}

func TestInmemCluster_ConnectCluster(t *testing.T) {
	cluster, err := NewInmemLayerCluster("c1", 3, log.New(&log.LoggerOptions{
		Mutex: &sync.Mutex{},
		Level: log.Trace,
		Name:  "inmem-cluster",
	}))
	if err != nil {
		t.Fatal(err)
	}
	cluster2, err := NewInmemLayerCluster("c2", 3, log.New(&log.LoggerOptions{
		Mutex: &sync.Mutex{},
		Level: log.Trace,
		Name:  "inmem-cluster",
	}))
	if err != nil {
		t.Fatal(err)
	}

	cluster.ConnectCluster(cluster2)

	var accepted atomic.Int32
	stopCh := make(chan struct{})
	var wg sync.WaitGroup
	acceptConns := func(listener NetworkListener) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
				}

				listener.SetDeadline(time.Now().Add(5 * time.Second))

				_, err := listener.Accept()
				if err != nil {
					return
				}

				accepted.Add(1)

			}
		}()
	}

	// Start a listener on each node.
	for _, node := range cluster.layers {
		acceptConns(node.Listeners()[0])
	}
	for _, node := range cluster2.layers {
		acceptConns(node.Listeners()[0])
	}

	// Make sure each node can connect to each other
	for _, node1 := range cluster.layers {
		for _, node2 := range cluster2.layers {
			conn, err := node1.DialContext(t.Context(), node2.addr, nil)
			if err != nil {
				t.Fatal(err)
			}

			if conn == nil {
				t.Fatal("nil conn")
			}

			conn, err = node2.DialContext(t.Context(), node1.addr, nil)
			if err != nil {
				t.Fatal(err)
			}

			if conn == nil {
				t.Fatal("nil conn")
			}
		}
	}

	close(stopCh)
	wg.Wait()

	if accepted.Load() != 18 {
		t.Fatalf("expected 18 connections to be accepted, got %d", accepted.Load())
	}
}
