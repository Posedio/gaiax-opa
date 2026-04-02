package danubeplugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
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
	"github.com/open-policy-agent/opa/v1/util"
)

const danubePluginName = "danube"

func init() {
	runtime.RegisterPlugin(danubePluginName, &danubeFactory{})
}

// danubeConfig holds the plugin configuration parsed from OPA's config file.
type danubeConfig struct {
	KeyPath            string `json:"keyPath"`
	SigAlgo            string `json:"sigAlgo"`
	Issuer             string `json:"issuer"`
	VerificationMethod string `json:"verificationMethod"`
	Path               string `json:"path"`
	Policy             string `json:"policy"`
	IDPrefix           string `json:"idPrefix"`
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
	if c.Policy == "" {
		return nil, errors.New("danube plugin: query is required")
	}
	if c.IDPrefix == "" {
		return nil, errors.New("danube plugin: idPrefix is required")
	}

	return c, nil
}

func (danubeFactory) New(m *plugins.Manager, config any) plugins.Plugin {
	p := &danubePlugin{
		manager: m,
		config:  config.(danubeConfig),
	}

	m.ExtraRoute(p.config.Path, p.config.Path, p.danubeHandler)
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

	p.manager.ExtraRoutes()

	return nil

}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (p *danubePlugin) danubeHandler(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	all, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	defer r.Body.Close()
	m := map[string]interface{}{}
	err = json.Unmarshal(all, &m)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	rs, err := rego.New(
		rego.Query(p.config.Policy),
		rego.Input(m),
		rego.Store(p.manager.Store),
		rego.Compiler(p.manager.GetCompiler()),
	).Eval(r.Context())
	decisionlog.Log(r.Context(), p.manager, p.config.Path, r.RemoteAddr, m, rs, err, nil)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	re := decisionlog.CollectResults(rs)

	if allowed, _ := re["allow"].(bool); !allowed {
		errs, _ := re["deny"].([]any)
		msgs := make([]string, 0, len(errs))
		for _, e := range errs {
			if s, ok := e.(string); ok {
				msgs = append(msgs, s)
			}
		}
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]any{"allow": false, "errors": msgs})
		return
	}

	cs, ok := re["cs"].(map[string]any)
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "cs not found in policy result")
		return
	}

	suffixRaw, ok := re["suffix"].(string)
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "suffix for vc id not found in policy result")
		return
	}

	suffix := url.PathEscape(suffixRaw)

	options := []vc.VerifiableCredentialOption{
		vc.WithVCID(p.config.IDPrefix + "/" + suffix),
		vc.WithValidFromNow(),
		vc.WithGaiaXContext(),
		vc.WithIssuer(p.config.Issuer),
		vc.WithValidFor(time.Hour * 24 * 365), //todo option
	}
	typeRaw, ok := re["type"].(string)
	if ok {
		options = append(options, vc.WithAdditionalTypes(typeRaw))
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
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	cs["@id"] = vcN.ID + "#cs"
	err = vcN.AddToCredentialSubject(cs)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	err = p.signer.SelfSign(vcN)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	json.NewEncoder(w).Encode(map[string]any{
		"vc-jwt": string(vcN.GetOriginalJWS()),
	})
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
