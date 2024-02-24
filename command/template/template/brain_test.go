// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package template

import (
	"reflect"
	"testing"

	dep "github.com/hashicorp/consul-template/dependency"
)

func TestNewBrain(t *testing.T) {
	b := NewBrain()

	if b.data == nil {
		t.Errorf("expected data to not be nil")
	}

	if b.receivedData == nil {
		t.Errorf("expected receivedData to not be nil")
	}
}

func TestRecall(t *testing.T) {
	b := NewBrain()

	d, err := dep.NewCatalogNodesQuery("")
	if err != nil {
		t.Fatal(err)
	}

	nodes := []*dep.Node{
		{
			Node:    "node",
			Address: "address",
		},
	}

	b.Remember(d, nodes)

	data, ok := b.Recall(d)
	if !ok {
		t.Fatal("expected data from brain")
	}

	result := data.([]*dep.Node)
	if !reflect.DeepEqual(result, nodes) {
		t.Errorf("expected %#v to be %#v", result, nodes)
	}
}

func TestForceSet(t *testing.T) {
	b := NewBrain()

	d, err := dep.NewCatalogNodesQuery("")
	if err != nil {
		t.Fatal(err)
	}

	nodes := []*dep.Node{
		{
			Node:    "node",
			Address: "address",
		},
	}

	b.ForceSet(d.String(), nodes)

	data, ok := b.Recall(d)
	if !ok {
		t.Fatal("expected data from brain")
	}

	result := data.([]*dep.Node)
	if !reflect.DeepEqual(result, nodes) {
		t.Errorf("expected %#v to be %#v", result, nodes)
	}
}

func TestForget(t *testing.T) {
	b := NewBrain()

	d, err := dep.NewCatalogNodesQuery("")
	if err != nil {
		t.Fatal(err)
	}

	nodes := []*dep.Node{
		{
			Node:    "node",
			Address: "address",
		},
	}

	b.Remember(d, nodes)
	b.Forget(d)

	if _, ok := b.Recall(d); ok {
		t.Errorf("expected %#v to not be forgotten", d)
	}
}
