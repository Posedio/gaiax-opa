package cliexec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sync"

	"github.com/Posedio/gaiax-opa/pkg/builtins"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/runtime"
	"github.com/open-policy-agent/opa/v1/types"
	"github.com/open-policy-agent/opa/v1/util"
)

const pluginName = "cli_exec"

// instance is set on Start and cleared on Stop.
var (
	mu       sync.RWMutex
	instance *plugin
)

func init() {
	runtime.RegisterPlugin(pluginName, &factory{})

	// cliExec(commandName, args) -> any
	// commandName is the key from the config commands map.
	// args is an array whose elements are appended as JSON-encoded positional CLI
	// arguments after the base command. Pass an empty array when no extra arguments
	// are needed.
	rego.RegisterBuiltin2(
		&rego.Function{
			Name:             "cliExec",
			Decl:             types.NewFunction(types.Args(types.S, types.NewArray(nil, types.A)), types.A),
			Nondeterministic: true,
		},
		cliExec,
	)
}

// config holds the plugin configuration parsed from OPA's config file.
//
// Each command is a slice where the first element is the executable and the
// remaining elements are fixed arguments prepended before the dynamic args
// passed from Rego.
//
// Example OPA config snippet:
//
//	plugins:
//	  cli_exec:
//	    commands:
//	      validate_vat:   ["python3", "/opt/scripts/validate_vat.py"]
//	      check_cert:     ["/usr/bin/openssl", "verify", "-CAfile", "/etc/ssl/ca.pem"]
//	      my_tool:        ["/opt/bin/mytool", "--json"]
type config struct {
	Commands map[string][]string `json:"commands"`
}

type factory struct{}

func (factory) Validate(_ *plugins.Manager, raw []byte) (any, error) {
	c := config{}
	if err := util.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	if len(c.Commands) == 0 {
		return nil, errors.New("cli_exec: commands must not be empty")
	}
	for name, cmd := range c.Commands {
		if len(cmd) == 0 {
			return nil, fmt.Errorf("cli_exec: command %q must have at least one element (the executable)", name)
		}
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
	instance = p
	mu.Unlock()
	p.manager.UpdatePluginStatus(pluginName, &plugins.Status{State: plugins.StateOK})
	p.manager.Logger().Info("cli_exec plugin: started with %d command(s)", len(p.config.Commands))
	return nil
}

func (p *plugin) Stop(_ context.Context) {
	mu.Lock()
	instance = nil
	mu.Unlock()
	p.manager.UpdatePluginStatus(pluginName, &plugins.Status{State: plugins.StateNotReady})
	p.manager.Logger().Info("cli_exec plugin: stopped")
}

func (p *plugin) Reconfigure(_ context.Context, cfg any) {
	mu.Lock()
	p.config = cfg.(config)
	mu.Unlock()
	p.manager.Logger().Info("cli_exec plugin: reconfigured with %d command(s)", len(p.config.Commands))
}

// cliExec is the Rego built-in implementation.
//
// Rego usage:  result := cliExec("command_name", [arg1, arg2, ...])
//
// The base command from config is used as-is; each element of the args array is
// JSON-encoded and appended as a positional CLI argument. The command must write
// valid JSON to stdout; that value becomes the return value. Anything written to
// stderr is forwarded to OPA's logger at warn level.
func cliExec(bctx rego.BuiltinContext, nameTerm, argsTerm *ast.Term) (*ast.Term, error) {
	var commandName string
	if err := ast.As(nameTerm.Value, &commandName); err != nil {
		return nil, fmt.Errorf("cliExec: invalid command name: %w", err)
	}

	mu.RLock()
	p := instance
	var cfg config
	if p != nil {
		cfg = p.config
	}
	mu.RUnlock()
	if p == nil {
		return builtins.ErrorMessageToTerm(errors.New("cliExec: plugin not started"))
	}

	baseCmd, ok := cfg.Commands[commandName]
	if !ok {
		return builtins.ErrorMessageToTerm(fmt.Errorf("cliExec: unknown command %q", commandName))
	}

	// Unpack the args array and serialize each element as a JSON CLI argument.
	arr, ok := argsTerm.Value.(*ast.Array)
	if !ok {
		return nil, fmt.Errorf("cliExec: second argument must be an array")
	}
	cmdArgs := make([]string, len(baseCmd[1:]))
	copy(cmdArgs, baseCmd[1:])
	for i := 0; i < arr.Len(); i++ {
		var v any
		if err := ast.As(arr.Elem(i).Value, &v); err != nil {
			return nil, fmt.Errorf("cliExec: invalid argument %d: %w", i, err)
		}
		b, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("cliExec: marshal argument %d: %w", i, err)
		}
		cmdArgs = append(cmdArgs, string(b))
	}

	cmd := exec.CommandContext(bctx.Context, baseCmd[0], cmdArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if stderrStr := stderr.String(); stderrStr != "" {
			p.manager.Logger().Error("cli_exec: command %q stderr: %s", commandName, stderrStr)
		}
		return builtins.ErrorMessageToTerm(fmt.Errorf("cliExec: command %q failed: %w", commandName, err))
	}

	if stderrStr := stderr.String(); stderrStr != "" {
		p.manager.Logger().Warn("cli_exec: command %q stderr: %s", commandName, stderrStr)
	}

	var result any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		p.manager.Logger().Error("cli_exec: command %q produced non-JSON output: %s", commandName, stdout.String())
		return builtins.ErrorMessageToTerm(fmt.Errorf("cliExec: command %q stdout is not valid JSON: %w", commandName, err))
	}

	val, err := ast.InterfaceToValue(result)
	if err != nil {
		p.manager.Logger().Error("cli_exec: convert result from %q: %v", commandName, err)
		return nil, fmt.Errorf("cliExec: convert result: %w", err)
	}
	return ast.NewTerm(val), nil
}
