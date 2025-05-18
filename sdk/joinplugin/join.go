package joinplugin

import (
	"context"

	"github.com/hashicorp/go-plugin"
	"github.com/openbao/openbao/sdk/v2/joinplugin/pb"
	"google.golang.org/grpc"
)

type Addr struct {
	Scheme string
	Host   string
	Port   uint16
}

type Join interface {
	Candidates(context.Context, map[string]string) ([]Addr, error)
	Cleanup(context.Context) error
}

type JoinPlugin struct {
	plugin.NetRPCUnsupportedPlugin

	Impl Join
}

// TODO: Should this take a config/context, like logical.Factory?
type Factory func() (Join, error)

type gRPCClient struct {
	pb.JoinClient
}

type gRPCServer struct {
	pb.UnimplementedJoinServer

	Impl Join
}

var HandshakeConfig = plugin.HandshakeConfig{
	MagicCookieKey:   "BAO_JOIN_PLUGIN",
	MagicCookieValue: "f4204b06-eb34-4f02-8564-a8ba687343a3",
}

func (g *gRPCServer) Candidates(ctx context.Context, args *pb.CandidateArgs) (*pb.Candidates, error) {
	v, err := g.Impl.Candidates(ctx, args.Config)
	if err != nil {
		return nil, err
	}
	candidates := make([]*pb.Candidate, 0, len(v))
	for _, c := range v {
		candidate := &pb.Candidate{Scheme: c.Scheme, Host: c.Host, Port: uint32(c.Port)}
		candidates = append(candidates, candidate)
	}
	return &pb.Candidates{Candidates: candidates}, nil
}

func (g *gRPCServer) Cleanup(ctx context.Context, args *pb.Empty) (*pb.Empty, error) {
	err := g.Impl.Cleanup(ctx)
	if err != nil {
		return nil, err
	}
	return &pb.Empty{}, err
}

func (g *gRPCClient) Candidates(ctx context.Context, config map[string]string) ([]Addr, error) {
	reply, err := g.JoinClient.Candidates(ctx, &pb.CandidateArgs{Config: config})
	if err != nil {
		return nil, err
	}
	candidates := make([]Addr, 0, len(reply.Candidates))
	for _, c := range reply.Candidates {
		candidates = append(candidates, Addr{Scheme: c.Scheme, Host: c.Host, Port: uint16(c.Port)})
	}
	return candidates, nil
}

func (g *gRPCClient) Cleanup(ctx context.Context) error {
	_, err := g.JoinClient.Cleanup(ctx, &pb.Empty{})
	return err
}

func (j *JoinPlugin) GRPCClient(ctx context.Context, b *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &gRPCClient{JoinClient: pb.NewJoinClient(c)}, nil
}

func (j *JoinPlugin) GRPCServer(b *plugin.GRPCBroker, s *grpc.Server) error {
	pb.RegisterJoinServer(s, &gRPCServer{Impl: j.Impl})
	return nil
}

var (
	_ plugin.Plugin     = &JoinPlugin{}
	_ plugin.GRPCPlugin = &JoinPlugin{}
)
