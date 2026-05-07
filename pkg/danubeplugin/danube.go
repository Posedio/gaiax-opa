package danubeplugin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Posedio/gaia-x-go/signer"
	vc "github.com/Posedio/gaia-x-go/verifiableCredentials"
	"github.com/Posedio/gaiax-opa/pkg/decisionlog"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/runtime"
	"github.com/open-policy-agent/opa/v1/topdown"
	"github.com/open-policy-agent/opa/v1/util"
)

const danubePluginName = "danube"

func init() {
	runtime.RegisterPlugin(danubePluginName, &danubeFactory{})
}

// danubeConfig holds the plugin configuration parsed from OPA's config file.
type danubeConfig struct {
	KeyPath            string                   `json:"keyPath"`
	SigAlgo            string                   `json:"sigAlgo"`
	Issuer             string                   `json:"issuer"`
	VerificationMethod string                   `json:"verificationMethod"`
	Path               string                   `json:"path"`
	Debug              bool                     `json:"debug"`
	CompliancePolicies []compliancePolicyConfig `json:"compliancePolicies"`
}

// compliancePolicyConfig binds a Rego policy query to a trust scope. Each entry
// is exposed as its own HTTP endpoint at <Path>/<TrustScope> and issues
// credentials whose ID is built from its own IDPrefix.
type compliancePolicyConfig struct {
	Policy     string `json:"policy"`
	TrustScope string `json:"trustScope"`
	IDPrefix   string `json:"idPrefix"`
}

type danubeFactory struct{}

func (danubeFactory) Validate(_ *plugins.Manager, config []byte) (any, error) {
	c := danubeConfig{}
	if err := util.Unmarshal(config, &c); err != nil {
		return nil, err
	}
	if c.KeyPath == "" {
		return nil, errors.New("danube plugin: keyPath is required")
	}
	if c.SigAlgo == "" {
		return nil, errors.New("danube plugin: sigAlgo is required")
	}
	if c.Issuer == "" {
		return nil, errors.New("danube plugin: issuer is required")
	}
	if c.VerificationMethod == "" {
		return nil, errors.New("danube plugin: verificationMethod is required")
	}

	if c.Path == "" {
		return nil, errors.New("danube plugin: path is required")
	}

	if len(c.CompliancePolicies) == 0 {
		return nil, errors.New("danube plugin: at least one compliancePolicies entry is required")
	}
	seen := make(map[string]struct{}, len(c.CompliancePolicies))
	for i, cp := range c.CompliancePolicies {
		if cp.Policy == "" {
			return nil, fmt.Errorf("danube plugin: compliancePolicies[%d].policy is required", i)
		}
		if cp.TrustScope == "" {
			return nil, fmt.Errorf("danube plugin: compliancePolicies[%d].trustScope is required", i)
		}
		if cp.IDPrefix == "" {
			return nil, fmt.Errorf("danube plugin: compliancePolicies[%d].idPrefix is required", i)
		}
		if _, dup := seen[cp.TrustScope]; dup {
			return nil, fmt.Errorf("danube plugin: duplicate trustScope %q in compliancePolicies", cp.TrustScope)
		}
		seen[cp.TrustScope] = struct{}{}
	}

	return c, nil
}

func (danubeFactory) New(m *plugins.Manager, config any) plugins.Plugin {
	p := &danubePlugin{
		manager: m,
		config:  config.(danubeConfig),
	}

	for _, cp := range p.config.CompliancePolicies {
		route := p.config.Path + "/" + cp.TrustScope
		m.ExtraRoute(route, route, p.makeComplianceHandler(cp, route))
	}
	m.ExtraRoute("/trust-scope", "/trust-scope", p.trustScopeHandler)
	return p
}

// danubePlugin is an OPA plugin that integrates with a Danube service.
type danubePlugin struct {
	manager  *plugins.Manager
	config   danubeConfig
	mu       sync.Mutex
	stopOnce sync.Once
	stopCh   chan struct{}
	signer   signer.Signer
}

func (p *danubePlugin) SignerInit() error {
	sigA := jwa.SignatureAlgorithm{}

	err := json.Unmarshal([]byte("\""+p.config.SigAlgo+"\""), &sigA)
	if err != nil {
		return fmt.Errorf("signature algorithm: %w", err)
	}
	path, err := filepath.Abs(p.config.KeyPath)
	if err != nil {
		return err
	}

	set, err := jwk.ReadFile(filepath.Clean(path), jwk.WithPEM(true))
	if err != nil {
		return err
	}

	key, ok := set.Key(0)
	if !ok {
		return errors.New("private key not found")
	}

	sig, err := signer.NewSigner(&signer.IssuerSetting{
		Key:                key,
		Alg:                sigA,
		Issuer:             p.config.Issuer,
		VerificationMethod: p.config.VerificationMethod,
	})
	if err != nil {
		return err
	}
	p.signer = sig

	//p.manager.ExtraRoutes()

	return nil

}

// errorResponse is the standard JSON error envelope returned by the plugin.
type errorResponse struct {
	Message    string   `json:"message"`
	Error      string   `json:"error"`
	StatusCode int      `json:"statusCode"`
	Errors     []string `json:"errors"`
}

func writeJSONError(w http.ResponseWriter, status int, message, label string, errs []string) {
	if errs == nil {
		errs = []string{}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(errorResponse{
		Message:    message,
		Error:      label,
		StatusCode: status,
		Errors:     errs,
	})
}

// quickValidateJWT checks the structural form of a compact JWS/JWT without
// verifying the signature: three non-empty base64url segments, with the
// header decoding to a JSON object that carries an "alg" claim.
func quickValidateJWT(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("expected 3 dot-separated segments, got %d", len(parts))
	}
	for i, p := range parts {
		if p == "" {
			return fmt.Errorf("segment %d is empty", i)
		}
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("header is not valid base64url: %w", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("header is not valid JSON: %w", err)
	}
	if _, ok := header["alg"]; !ok {
		return errors.New("header is missing the alg claim")
	}
	return nil
}

func (p *danubePlugin) trustScopeHandler(w http.ResponseWriter, _ *http.Request) {
	scopes := make([]string, 0, len(p.config.CompliancePolicies))
	for _, cp := range p.config.CompliancePolicies {
		scopes = append(scopes, cp.TrustScope)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(scopes)
}

func (p *danubePlugin) makeComplianceHandler(cp compliancePolicyConfig, route string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p.danubeHandler(cp, route, w, r)
	}
}

func (p *danubePlugin) danubeHandler(cp compliancePolicyConfig, route string, w http.ResponseWriter, r *http.Request) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/vp+jwt" {
		writeJSONError(w, http.StatusUnsupportedMediaType,
			"Content-Type must be application/vp+jwt", "Unsupported Media Type", nil)
		return
	}

	q := r.URL.Query()

	vcid := q.Get("vcid")
	complianceLevel := q.Get("complianceLevel")

	all, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest,
			"failed to read request body", "Invalid request", nil)
		return
	}
	defer r.Body.Close()
	jwt := strings.TrimSpace(string(all))
	if jwt == "" {
		writeJSONError(w, http.StatusBadRequest,
			"empty request body", "Invalid request", nil)
		return
	}
	if err := quickValidateJWT(jwt); err != nil {
		writeJSONError(w, http.StatusBadRequest,
			"Unsupported Verifiable Presentation", "Invalid verifiable presentation",
			[]string{err.Error()})
		return
	}
	m := map[string]interface{}{"jwt": jwt}

	if vcid != "" {
		m["vcid"] = vcid
	}
	if complianceLevel != "" {
		m["complianceLevel"] = complianceLevel
	}

	regoOpts := []func(*rego.Rego){
		rego.Query(cp.Policy),
		rego.Store(p.manager.Store),
		rego.Compiler(p.manager.GetCompiler()),
	}
	if p.config.Debug {
		regoOpts = append(regoOpts,
			rego.EnablePrintStatements(true),
			rego.PrintHook(topdown.NewPrintHook(os.Stderr)),
		)
	}

	reqMetadata := map[string]any{
		"trust_scope": cp.TrustScope,
		"route":       route,
	}
	if vcid != "" {
		reqMetadata["vcid"] = vcid
	}
	if complianceLevel != "" {
		reqMetadata["compliance_level"] = complianceLevel
	}

	respMetadata := map[string]any{}
	customLog := func() map[string]any {
		c := map[string]any{"request_metadata": reqMetadata}
		if len(respMetadata) > 0 {
			c["response_metadata"] = respMetadata
		}
		return c
	}

	pq, err := rego.New(regoOpts...).PrepareForEval(r.Context())
	if err != nil {
		decisionlog.Log(r.Context(), p.manager, route, r.RemoteAddr, m, nil, err, customLog())
		writeJSONError(w, http.StatusInternalServerError,
			"policy preparation failed", "Internal error", []string{err.Error()})
		return
	}

	rs, err := pq.Eval(r.Context(),
		rego.EvalInput(m),
		rego.EvalRequestMetadata(reqMetadata),
		rego.EvalResponseMetadata(respMetadata),
	)
	decisionlog.Log(r.Context(), p.manager, route, r.RemoteAddr, m, rs, err, customLog())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError,
			"policy evaluation failed", "Internal error", []string{err.Error()})
		return
	}

	re := decisionlog.CollectResults(rs)

	errs, _ := re["deny"].([]any)
	msgs := make([]string, 0, len(errs))
	for _, e := range errs {
		if s, ok := e.(string); ok {
			msgs = append(msgs, s)
		}
	}

	if allowed, _ := re["allow"].(bool); !allowed {
		writeJSONError(w, http.StatusBadRequest,
			"Unsupported Verifiable Presentation", "Invalid verifiable presentation", msgs)
		return
	}
	if _, ok := re["deny"]; ok {
		if len(msgs) > 0 {
			writeJSONError(w, http.StatusBadRequest,
				"Unsupported Verifiable Presentation", "Invalid verifiable presentation", msgs)
			return
		}

	}

	cs, ok := re["cs"].(map[string]any)
	if !ok {
		writeJSONError(w, http.StatusInternalServerError,
			"cs not found in policy result", "Internal error", nil)
		return
	}

	suffixRaw, ok := re["suffix"].(string)
	if !ok {
		writeJSONError(w, http.StatusInternalServerError,
			"suffix for vc id not found in policy result", "Internal error", nil)
		return
	}

	suffix := url.PathEscape(suffixRaw)

	options := []vc.VerifiableCredentialOption{
		vc.WithValidFromNow(),
		vc.WithGaiaXContext(),
		vc.WithIssuer(p.config.Issuer),
		vc.WithValidFor(time.Hour * 24 * 365), //todo option
	}
	typeRaw, ok := re["type"].(string)
	if ok {
		options = append(options, vc.WithAdditionalTypes(typeRaw))
	}

	if vcid == "" {
		options = append(options, vc.WithVCID(cp.IDPrefix+"/"+suffix))
	} else {
		options = append(options, vc.WithVCID(vcid))
	}

	contexRaw, ok := re["context"].(map[string]any)
	if ok {
		for id, ele := range contexRaw {
			if id == "" {
				if _, k := ele.(string); k {
					options = append(options, vc.WithContextString(ele.(string)))
				}
			} else {
				if _, k := ele.(string); k {
					options = append(options, vc.WithContextMapping(id, ele.(string)))
				}
			}
		}
	}

	vcN, err := vc.NewEmptyVerifiableCredentialV2(options...)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError,
			"failed to build verifiable credential", "Internal error", []string{err.Error()})
		return
	}

	cs["@id"] = vcN.ID + "#cs"
	err = vcN.AddToCredentialSubject(cs)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError,
			"failed to add credential subject", "Internal error", []string{err.Error()})
		return
	}

	err = p.signer.SelfSign(vcN)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError,
			"failed to sign verifiable credential", "Internal error", []string{err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/vc+jwt")
	w.WriteHeader(http.StatusOK)
	w.Write(vcN.GetOriginalJWS())
}

func (p *danubePlugin) Start(_ context.Context) error {
	p.mu.Lock()
	p.stopCh = make(chan struct{})
	p.mu.Unlock()

	err := p.SignerInit()
	if err != nil {
		p.manager.Logger().Info("Danube plugin: error %v", err)
		return err
	}

	p.manager.UpdatePluginStatus(danubePluginName, &plugins.Status{State: plugins.StateOK})
	p.manager.Logger().Info("Danube plugin: signer started with issuer=%s", p.config.Issuer)

	return nil
}

func (p *danubePlugin) Stop(_ context.Context) {
	p.stopOnce.Do(func() {
		p.mu.Lock()
		if p.stopCh != nil {
			close(p.stopCh)
		}
		p.mu.Unlock()
		p.manager.UpdatePluginStatus(danubePluginName, &plugins.Status{State: plugins.StateNotReady})
		p.manager.Logger().Info("Danube plugin: stopped")
	})
}

func (p *danubePlugin) Reconfigure(ctx context.Context, config any) {
	p.Stop(ctx)
	p.stopOnce = sync.Once{} // reset for restart
	p.config = config.(danubeConfig)
	if err := p.Start(ctx); err != nil {
		p.manager.Logger().Error("Danube plugin: reconfigure failed: %v", err)
	}
}
