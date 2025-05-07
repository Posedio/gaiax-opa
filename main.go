package main

import (
	"encoding/json"
	"fmt"
	"github.com/Posedio/gaia-x-go/verifiableCredentials"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/cmd"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
	"gitlab.euprogigant.kube.a1.digital/philipp.seifert-kehrer/godrl"
	"os"
)

func odrl(_ rego.BuiltinContext, pol, req *ast.Term) (*ast.Term, error) {
	fmt.Println("calling engine custom built-in")
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
		fmt.Println("error evaluating")
		return nil, err
	}
	fmt.Println(report)

	return ast.BooleanTerm(ok), nil
}

func VPFromJWT(_ rego.BuiltinContext, req *ast.Term) (*ast.Term, error) {
	var token string
	err := ast.As(req.Value, &token)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	vp, err := verifiableCredentials.VPFROMJWT([]byte(token))
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	err = vp.Verify(verifiableCredentials.IssuerMatch())
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	vcs, err := vp.DecodeEnvelopedCredentials()
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	for _, vc := range vcs {
		err := vc.Verify(verifiableCredentials.IssuerMatch())
		if err != nil {
			fmt.Println(err)
			return nil, err
		}
	}

	m := map[string]interface{}{
		"vp":  vp,
		"vcs": vcs,
	}

	value, err := ast.InterfaceToValue(m)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	t := &ast.Term{Value: value}

	return t, nil
}

func VPFromJWTResolved(_ rego.BuiltinContext, req *ast.Term) (*ast.Term, error) {
	var token string
	err := ast.As(req.Value, &token)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	vp, err := verifiableCredentials.VPFROMJWT([]byte(token))
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	err = vp.Verify(verifiableCredentials.IssuerMatch())
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	vcs, err := vp.DecodeEnvelopedCredentials()
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	for _, vc := range vcs {
		err := vc.Verify(verifiableCredentials.IssuerMatch())
		if err != nil {
			fmt.Println(err)
			return nil, err
		}
	}

	rvcs, err := vp.DecodeCredentialsAndResolveAllReferences()
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	m := map[string]interface{}{
		"vp":  vp,
		"vcs": vcs,
		"css": rvcs,
	}

	value, err := ast.InterfaceToValue(m)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	t := &ast.Term{Value: value}

	return t, nil
}

func VCFromJWT(_ rego.BuiltinContext, req *ast.Term) (*ast.Term, error) {
	var token string
	err := ast.As(req.Value, &token)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	vc, err := verifiableCredentials.VCFromJWT([]byte(token))
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	err = vc.Verify(verifiableCredentials.IssuerMatch())
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	value, err := ast.InterfaceToValue(vc)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	t := &ast.Term{Value: value}

	return t, nil
}

func main() {
	rego.RegisterBuiltin2(
		&rego.Function{
			Name: "odrl",
			Decl: types.NewFunction(types.Args(types.A, types.A), types.B),
		},
		odrl,
	)
	rego.RegisterBuiltin1(
		&rego.Function{
			Name: "resolveVPFromJWT",
			Decl: types.NewFunction(types.Args(types.A), types.A),
		},
		VPFromJWT,
	)
	rego.RegisterBuiltin1(
		&rego.Function{
			Name: "resolveVCFromJWT",
			Decl: types.NewFunction(types.Args(types.A), types.A),
		},
		VCFromJWT,
	)
	rego.RegisterBuiltin1(
		&rego.Function{
			Name: "fullResolveVPFromJWT",
			Decl: types.NewFunction(types.Args(types.A), types.A),
		},
		VPFromJWTResolved,
	)

	if err := cmd.RootCommand.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
