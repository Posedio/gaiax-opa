package grpcplugin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Posedio/gaiax-opa/internal/grpcpb"
	"github.com/Posedio/gaiax-opa/pkg/decisionlog"

	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/runtime"
	"github.com/open-policy-agent/opa/v1/util"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/structpb"
)

const grpcPluginName = "grpc"

func init() {
	runtime.RegisterPlugin(grpcPluginName, &grpcFactory{})
}

// grpcConfig holds the plugin configuration parsed from OPA's config file.
type grpcConfig struct {
	Addr string `json:"addr"` // e.g. ":50051"
}

type grpcFactory struct{}

func (grpcFactory) Validate(_ *plugins.Manager, config []byte) (any, error) {
	c := grpcConfig{}
	if err := util.Unmarshal(config, &c); err != nil {
		return nil, err
	}
	if c.Addr == "" {
		return nil, errors.New("grpc plugin: addr is required")
	}
	return c, nil
}

func (grpcFactory) New(m *plugins.Manager, config any) plugins.Plugin {
	return &grpcPlugin{
		manager: m,
		config:  config.(grpcConfig),
	}
}

// grpcPlugin runs a gRPC server that exposes OPA policy evaluation.
type grpcPlugin struct {
	manager  *plugins.Manager
	config   grpcConfig
	server   *grpc.Server
	mu       sync.Mutex
	stopOnce sync.Once
}

func (p *grpcPlugin) Start(_ context.Context) error {
	lis, err := net.Listen("tcp", p.config.Addr)
	if err != nil {
		return fmt.Errorf("grpc plugin: listen %s: %w", p.config.Addr, err)
	}

	p.mu.Lock()
	p.server = grpc.NewServer()
	grpcpb.RegisterOPAServiceServer(p.server, &opaServiceServer{manager: p.manager})
	p.mu.Unlock()

	var listenerr error

	go func(listenerr error) {
		if err := p.server.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			listenerr = err
			p.manager.Logger().Error("gRPC plugin: serve error: %v", err)
		}
	}(listenerr)

	time.Sleep(100 * time.Millisecond)
	if listenerr != nil {
		return listenerr
	}

	p.manager.UpdatePluginStatus(grpcPluginName, &plugins.Status{State: plugins.StateOK})
	p.manager.Logger().Info("gRPC plugin: listening on %s", p.config.Addr)

	return nil
}

func (p *grpcPlugin) Stop(_ context.Context) {
	p.stopOnce.Do(func() {
		if p.server != nil {
			p.manager.Logger().Info("gRPC server shuting down")
			p.server.GracefulStop()
		}
		p.manager.UpdatePluginStatus(grpcPluginName, &plugins.Status{State: plugins.StateNotReady})
	})
}

func (p *grpcPlugin) Reconfigure(ctx context.Context, config any) {
	p.Stop(ctx)
	p.stopOnce = sync.Once{} // reset for restart
	p.config = config.(grpcConfig)
	if err := p.Start(ctx); err != nil {
		p.manager.Logger().Error("gRPC plugin: reconfigure failed: %v", err)
	}
}

type opaServiceServer struct {
	grpcpb.UnimplementedOPAServiceServer
	manager *plugins.Manager
}

func (s *opaServiceServer) Query(ctx context.Context, req *grpcpb.QueryRequest) (*grpcpb.QueryResponse, error) {
	query := "data." + strings.ReplaceAll(req.GetPath(), "/", ".")
	input := req.GetInput().AsMap()

	reqMetadata := metadataFromIncomingContext(ctx)
	respMetadata := map[string]any{}

	remoteAddr := "grpc"
	if p, ok := peer.FromContext(ctx); ok {
		remoteAddr = p.Addr.String()
	}

	customLog := func() map[string]any {
		c := map[string]any{}
		if len(reqMetadata) > 0 {
			c["request_metadata"] = reqMetadata
		}
		if len(respMetadata) > 0 {
			c["response_metadata"] = respMetadata
		}
		if len(c) == 0 {
			return nil
		}
		return c
	}

	pq, err := rego.New(
		rego.Query(query),
		rego.Store(s.manager.Store),
		rego.Compiler(s.manager.GetCompiler()),
	).PrepareForEval(ctx)
	if err != nil {
		decisionlog.Log(ctx, s.manager, req.GetPath(), remoteAddr, input, nil, err, customLog())
		return &grpcpb.QueryResponse{Error: err.Error()}, nil
	}

	rs, evalErr := pq.Eval(ctx,
		rego.EvalInput(input),
		rego.EvalRequestMetadata(reqMetadata),
		rego.EvalResponseMetadata(respMetadata),
	)

	decisionlog.Log(ctx, s.manager, req.GetPath(), remoteAddr, input, rs, evalErr, customLog())

	if err := sendResponseMetadata(ctx, respMetadata); err != nil {
		s.manager.Logger().Warn("gRPC plugin: failed to send response metadata: %v", err)
	}

	if evalErr != nil {
		return &grpcpb.QueryResponse{Error: evalErr.Error()}, nil
	}
	if len(rs) == 0 {
		return &grpcpb.QueryResponse{Error: "undefined"}, nil
	}

	result, err := structpb.NewStruct(decisionlog.CollectResults(rs))
	if err != nil {
		return &grpcpb.QueryResponse{Error: fmt.Sprintf("serialize result: %v", err)}, nil
	}
	return &grpcpb.QueryResponse{Result: result, Allowed: allAllowed(rs)}, nil
}

func metadataFromIncomingContext(ctx context.Context) map[string]any {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok || len(md) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(md))
	for k, v := range md {
		switch len(v) {
		case 0:
			continue
		case 1:
			out[k] = v[0]
		default:
			values := make([]any, len(v))
			for i, s := range v {
				values[i] = s
			}
			out[k] = values
		}
	}
	return out
}

func sendResponseMetadata(ctx context.Context, m map[string]any) error {
	if len(m) == 0 {
		return nil
	}
	out := metadata.MD{}
	for k, v := range m {
		switch x := v.(type) {
		case string:
			out.Append(k, x)
		case []any:
			for _, e := range x {
				out.Append(k, fmt.Sprint(e))
			}
		case []string:
			out.Append(k, x...)
		default:
			out.Append(k, fmt.Sprint(v))
		}
	}
	return grpc.SetTrailer(ctx, out)
}

func allAllowed(rs rego.ResultSet) bool {
	if len(rs) == 0 {
		return false
	}
	for _, result := range rs {
		for _, expr := range result.Expressions {
			switch v := expr.Value.(type) {
			case map[string]interface{}:
				allow, ok := v["allow"]
				if !ok {
					return false
				}
				b, ok := allow.(bool)
				if !ok || !b {
					return false
				}
			case bool:
				if !v {
					return false
				}
			default:
				return false
			}
		}
	}
	return true
}
