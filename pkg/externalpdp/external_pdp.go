package externalpdp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/Posedio/gaiax-opa/pkg/builtins"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/runtime"
	"github.com/open-policy-agent/opa/v1/types"
	"github.com/open-policy-agent/opa/v1/util"
)

const pluginName = "external_pdp"

// registry is written by the plugin on Start/Reconfigure and read by the built-in.
var (
	mu       sync.RWMutex
	registry map[string]string // source name -> URL
)

func init() {
	runtime.RegisterPlugin(pluginName, &factory{})

	rego.RegisterBuiltin2(
		&rego.Function{
			Name:             "externalPDP",
			Decl:             types.NewFunction(types.Args(types.S, types.A), types.A),
			Nondeterministic: true,
		},
		callExternalPDP,
	)
}

// config holds the plugin configuration.
type config struct {
	Sources map[string]string `json:"sources"` // source name -> URL
}

type factory struct{}

func (factory) Validate(_ *plugins.Manager, raw []byte) (any, error) {
	c := config{}
	if err := util.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	if len(c.Sources) == 0 {
		return nil, errors.New("external_pdp: sources must not be empty")
	}
	return c, nil
}

func (factory) New(m *plugins.Manager, cfg any) plugins.Plugin {
	return &plugin{manager: m, config: cfg.(config)}
}

type plugin struct {
	manager *plugins.Manager
	config  config
}

func (p *plugin) Start(_ context.Context) error {
	mu.Lock()
	registry = p.config.Sources
	mu.Unlock()
	p.manager.UpdatePluginStatus(pluginName, &plugins.Status{State: plugins.StateOK})
	p.manager.Logger().Info("external_pdp plugin: registered %d source(s)", len(p.config.Sources))
	return nil
}

func (p *plugin) Stop(_ context.Context) {
	mu.Lock()
	registry = nil
	mu.Unlock()
	p.manager.UpdatePluginStatus(pluginName, &plugins.Status{State: plugins.StateNotReady})
}

func (p *plugin) Reconfigure(_ context.Context, cfg any) {
	c := cfg.(config)
	mu.Lock()
	registry = c.Sources
	p.config = c
	mu.Unlock()
}

// callExternalPDP is the built-in implementation for externalPDP(source, input).
func callExternalPDP(bctx rego.BuiltinContext, sourceTerm, inputTerm *ast.Term) (*ast.Term, error) {
	var sourceName string
	if err := ast.As(sourceTerm.Value, &sourceName); err != nil {
		return nil, fmt.Errorf("externalPDP: invalid source name: %w", err)
	}

	mu.RLock()
	url, ok := registry[sourceName]
	mu.RUnlock()
	if !ok {
		return builtins.ErrorMessageToTerm(fmt.Errorf("externalPDP: unknown source %q", sourceName))
	}

	var input any
	if err := ast.As(inputTerm.Value, &input); err != nil {
		return nil, fmt.Errorf("externalPDP: invalid input: %w", err)
	}

	body, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("externalPDP: marshal input: %w", err)
	}

	req, err := http.NewRequestWithContext(bctx.Context, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("externalPDP: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return builtins.ErrorMessageToTerm(fmt.Errorf("externalPDP: request to %q failed: %w", sourceName, err))
	}
	defer resp.Body.Close()

	var result any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return builtins.ErrorMessageToTerm(fmt.Errorf("externalPDP: decode response from %q: %w", sourceName, err))
	}

	if m, ok := result.(map[string]any); ok {
		if r, exists := m["result"]; exists {
			result = r
		}
	}

	val, err := ast.InterfaceToValue(result)
	if err != nil {
		return nil, fmt.Errorf("externalPDP: convert result: %w", err)
	}
	return ast.NewTerm(val), nil
}
