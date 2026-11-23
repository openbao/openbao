package namespace

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTree(t *testing.T) {
	t.Parallel()

	tree := NewTree(RootNamespace)

	namespaces1 := []*Namespace{
		{Path: "ns1/", ID: "00001", UUID: "00001"},
		{Path: "ns1/ns2/", ID: "00002", UUID: "00002"},
		{Path: "ns3/", ID: "00003", UUID: "00003"},
		{Path: "ns3/ns4/", ID: "00004", UUID: "00004"},
	}

	for _, entry := range namespaces1 {
		err := tree.Insert(entry)
		require.NoError(t, err)
	}
	err := tree.Validate()
	require.NoError(t, err)

	namespaces2 := []*Namespace{
		{Path: "ns3/ns6/ns7/", ID: "00007", UUID: "00007"},
		{Path: "ns3/ns8/ns9/", ID: "00009", UUID: "00009"},
	}

	for _, entry := range namespaces2 {
		err := tree.Insert(entry)
		require.Error(t, err)
	}

	namespaces3 := []*Namespace{
		{Path: "ns3/ns6/", ID: "00006", UUID: "00006"},
		{Path: "ns3/ns8/", ID: "00008", UUID: "00008"},
		{Path: "ns9/ns10/", ID: "00010", UUID: "00010"},
	}

	err = tree.Insert(namespaces3[0])
	require.NoError(t, err)
	err = tree.Insert(namespaces3[1])
	require.NoError(t, err)
	err = tree.Insert(namespaces3[2])
	require.Error(t, err)

	err = tree.Validate()
	require.NoError(t, err)

	beforeSize := tree.size
	err = tree.Delete("ns9/ns10/")
	require.NoError(t, err)
	require.Equal(t, beforeSize, tree.size)

	err = tree.Delete("ns3/")
	require.Error(t, err)
	require.Equal(t, beforeSize, tree.size)

	err = tree.Delete("ns1/ns2/")
	require.NoError(t, err)
	require.Equal(t, beforeSize-1, tree.size)

	count := 0
	require.NoError(t, tree.Walk("", false, func(n *Namespace) {
		count++
	}))
	require.Equal(t, 2, count)

	count = 0
	require.NoError(t, tree.Walk("", true, func(n *Namespace) {
		count++
	}))
	require.Equal(t, tree.size, count+1)

	entry := tree.Get("ns1/")
	require.NotNil(t, entry)
	require.Equal(t, namespaces1[0], entry)

	entry = tree.Get("ns3/ns4/foobar")
	require.Nil(t, entry)

	namespacePrefix, entry, pathSuffix := tree.LongestPrefix("ns3/ns4/foobar")
	require.NotNil(t, entry)
	require.Equal(t, "ns3/ns4/", namespacePrefix)
	require.Equal(t, "foobar", pathSuffix)
}
