package builtins

import (
	"encoding/json"
	"fmt"

	"github.com/Posedio/gaia-x-go/compliance"
	"github.com/Posedio/gaia-x-go/verifiableCredentials"
	"github.com/Posedio/godrl"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/types"
)

const loireComplianceType = "gx:LabelCredential"

func odrl(_ rego.BuiltinContext, pol, req *ast.Term) (*ast.Term, error) {
	var policy json.RawMessage
	var odrlReq godrl.OdrlRequest
	if err := ast.As(pol.Value, &policy); err != nil {
		fmt.Println("error getting policy")
		return nil, err
	}
	if err := ast.As(req.Value, &odrlReq); err != nil {
		fmt.Printf("error getting request: %v", err)
		return nil, err
	}

	loadedPol, err := godrl.LoadPolicy(policy)
	ok, report, err := godrl.Evaluate(loadedPol, odrlReq)
	if err != nil {
		return ErrorMessageToTerm(err)
	}

	m := map[string]any{
		"ok":     ok,
		"report": report,
	}

	return interfaceToTerm(m)
}

func interfaceToTerm(a any) (*ast.Term, error) {
	value, err := ast.InterfaceToValue(a)
	if err != nil {
		fmt.Println(err) //actual error
		return nil, err
	}

	return ast.NewTerm(value), nil
}

func ErrorMessageToTerm(e error) (*ast.Term, error) {
	m := map[string]any{
		"error": e.Error(),
	}
	value, err := ast.InterfaceToValue(m)
	if err != nil {
		fmt.Println(err) //actual error
		return nil, err
	}
	return ast.NewTerm(value), nil
}

type resolveConfig struct {
	fullResolve          bool
	validateGXCompliance bool
}

type resolveOption func(*resolveConfig)

func withFullResolve() resolveOption {
	return func(config *resolveConfig) {
		config.fullResolve = true
	}
}

func withValidateGXCompliance() resolveOption {
	return func(config *resolveConfig) {
		config.validateGXCompliance = true
	}
}

type cachedVP struct { //todo implement cache
	vp  *verifiableCredentials.VerifiablePresentation
	vcs []*verifiableCredentials.VerifiableCredential
}

func resolveJWT(_ rego.BuiltinContext, req *ast.Term, opt ...resolveOption) (map[string]any, error) {
	config := &resolveConfig{}
	for _, o := range opt {
		o(config)
	}

	cached := &cachedVP{}
	var token string
	err := ast.As(req.Value, &token)
	if err != nil {
		fmt.Println(err) //actual internal error
		return nil, fmt.Errorf("internal error: %v", err)
	}
	cached.vp, err = verifiableCredentials.VPFROMJWT([]byte(token))
	if err != nil {
		return nil, fmt.Errorf("error on resolving verifiable presentation: %v", err)
	}
	cached.vcs, err = cached.vp.DecodeEnvelopedCredentials()
	if err != nil {
		fmt.Println(err)
		return nil, fmt.Errorf("internal error: %v", err)
	}

	for _, vc := range cached.vcs {
		err := vc.Verify(verifiableCredentials.IssuerMatch())
		if err != nil {
			return nil, err
		}
	}

	m := map[string]any{
		"vp":  cached.vp,
		"vcs": cached.vcs,
	}
	if config.fullResolve {
		rvcs, err := cached.vp.DecodeCredentialsAndResolveAllReferences()
		if err != nil {
			fmt.Println(err)
			return nil, fmt.Errorf("internal error: %v", err)
		}
		m["css"] = rvcs
	}
	if config.validateGXCompliance {
		vcWithType, err := cached.vp.GetCredentialsWithType(loireComplianceType) //only loire
		if err != nil {
			return nil, fmt.Errorf("error getting credentials for loire compliance type: %v", err)
		}
		if len(vcWithType) != 1 {
			return nil, fmt.Errorf("expected exactly one gaia-x compliance credential type")
		}

		gxCompliance, err := compliance.ValidateGXCompliance(cached.vp, vcWithType[0])
		m["compliance"] = gxCompliance

	}

	return m, nil
}

func vpFromJWT(ctx rego.BuiltinContext, req *ast.Term) (*ast.Term, error) {
	resolve, err := resolveJWT(ctx, req)
	if err != nil {
		return ErrorMessageToTerm(err)
	}

	return interfaceToTerm(resolve)
}

func vpFromJWTGX(ctx rego.BuiltinContext, req *ast.Term) (*ast.Term, error) {
	resolve, err := resolveJWT(ctx, req, withValidateGXCompliance())
	if err != nil {
		return ErrorMessageToTerm(err)
	}

	return interfaceToTerm(resolve)
}

func vpFromJWTResolved(ctx rego.BuiltinContext, req *ast.Term) (*ast.Term, error) {
	resolve, err := resolveJWT(ctx, req, withFullResolve())
	if err != nil {
		return ErrorMessageToTerm(err)
	}

	return interfaceToTerm(resolve)
}

func vcFromJWT(_ rego.BuiltinContext, req *ast.Term) (*ast.Term, error) {
	var token string
	err := ast.As(req.Value, &token)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	vc, err := verifiableCredentials.VCFromJWT([]byte(token))
	if err != nil {
		return ErrorMessageToTerm(err)
	}

	err = vc.Verify(verifiableCredentials.IssuerMatch())
	if err != nil {
		return ErrorMessageToTerm(err)
	}

	return interfaceToTerm(vc)
}

func init() {
	rego.RegisterBuiltin2(
		&rego.Function{
			Name: "odrl",
			Decl: types.NewFunction(types.Args(types.A, types.A), types.A),
		},
		odrl,
	)
	rego.RegisterBuiltin1(
		&rego.Function{
			Name: "resolveVPFromJWT",
			Decl: types.NewFunction(types.Args(types.A), types.A),
		},
		vpFromJWT,
	)
	rego.RegisterBuiltin1(
		&rego.Function{
			Name: "resolveVPFromJWTWithGXCompliance",
			Decl: types.NewFunction(types.Args(types.A), types.A),
		},
		vpFromJWTGX)
	rego.RegisterBuiltin1(
		&rego.Function{
			Name: "resolveVCFromJWT",
			Decl: types.NewFunction(types.Args(types.A), types.A),
		},
		vcFromJWT,
	)
	rego.RegisterBuiltin1(
		&rego.Function{
			Name: "fullResolveVPFromJWT",
			Decl: types.NewFunction(types.Args(types.A), types.A),
		},
		vpFromJWTResolved,
	)
}
