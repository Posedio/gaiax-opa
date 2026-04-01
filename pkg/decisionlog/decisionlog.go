package decisionlog

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/plugins/logs"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/server"
)

type logger interface {
	Log(context.Context, *server.Info) error
}

// Log submits a decision to the OPA decision log orchestrator.
// It is a no-op if the decision_logs plugin is not configured.
func Log(ctx context.Context, m *plugins.Manager, path, remoteAddr string, input map[string]any, rs rego.ResultSet, evalErr error, custom map[string]any) {
	dl, ok := m.Plugin(logs.Name).(logger)
	if !ok {
		return
	}

	var result *any
	if len(rs) > 0 {
		v := any(CollectResults(rs))
		result = &v
	}

	inputVal := any(input)
	info := &server.Info{
		DecisionID: uuid.New().String(),
		Path:       path,
		Input:      &inputVal,
		Results:    result,
		Error:      evalErr,
		Timestamp:  time.Now().UTC(),
		RemoteAddr: remoteAddr,
		Custom:     custom,
	}

	if err := dl.Log(ctx, info); err != nil {
		m.Logger().Error("decision log failed: %v", err)
	}
}

func CollectResults(rs rego.ResultSet) map[string]any {
	if len(rs) == 1 && len(rs[0].Expressions) == 1 {
		if m, ok := rs[0].Expressions[0].Value.(map[string]any); ok {
			return m
		}
		return map[string]any{"result": rs[0].Expressions[0].Value}
	}

	all := make([]any, 0, len(rs))
	for _, r := range rs {
		for _, expr := range r.Expressions {
			all = append(all, expr.Value)
		}
	}
	return map[string]any{"results": all}
}
