package plugin

import (
	"context"
	"reflect"
	"testing"

	"github.com/hashicorp/go-plugin/test/grpc"
	"google.golang.org/grpc"
)

func TestGRPCClient_App(t *testing.T) {
	client, server := TestPluginGRPCConn(t, map[string]Plugin{
		"test": new(testInterfacePlugin),
	})
	defer client.Close()
	defer server.Stop()

	raw, err := client.Dispense("test")
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	impl, ok := raw.(testInterface)
	if !ok {
		t.Fatalf("bad: %#v", raw)
	}

	result := impl.Double(21)
	if result != 42 {
		t.Fatalf("bad: %#v", result)
	}

	err = impl.Bidirectional()
	if err != nil {
		t.Fatal(err)
	}
}

func TestGRPCConn_BidirectionalPing(t *testing.T) {
	conn, _ := TestGRPCConn(t, func(s *grpc.Server) {
		grpctest.RegisterPingPongServer(s, &pingPongServer{})
	})
	defer conn.Close()
	pingPongClient := grpctest.NewPingPongClient(conn)

	pResp, err := pingPongClient.Ping(context.Background(), &grpctest.PingRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if pResp.Msg != "pong" {
		t.Fatal("Bad PingPong")
	}
}

func TestGRPCC_Stream(t *testing.T) {
	client, server := TestPluginGRPCConn(t, map[string]Plugin{
		"test": new(testInterfacePlugin),
	})
	defer client.Close()
	defer server.Stop()

	raw, err := client.Dispense("test")
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	impl, ok := raw.(testStreamer)
	if !ok {
		t.Fatalf("bad: %#v", raw)
	}

	expected := []int32{21, 22, 23, 24, 25, 26}
	result, err := impl.Stream(21, 27)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(result, expected) {
		t.Fatalf("expected: %v\ngot: %v", expected, result)
	}
}

func TestGRPCClient_Ping(t *testing.T) {
	client, server := TestPluginGRPCConn(t, map[string]Plugin{
		"test": new(testInterfacePlugin),
	})
	defer client.Close()
	defer server.Stop()

	// Run a couple pings
	if err := client.Ping(); err != nil {
		t.Fatalf("err: %s", err)
	}
	if err := client.Ping(); err != nil {
		t.Fatalf("err: %s", err)
	}

	// Close the remote end
	server.server.Stop()

	// Test ping fails
	if err := client.Ping(); err == nil {
		t.Fatal("should error")
	}
}
