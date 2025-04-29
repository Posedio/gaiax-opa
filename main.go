package main

import (
	"fmt"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/cmd"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
	"gitlab.euprogigant.kube.a1.digital/philipp.seifert-kehrer/godrl/engine"
	"os"
)

func odrl(bctx rego.BuiltinContext, pol, req *ast.Term) (*ast.Term, error) {
	fmt.Println("calling engine custom built-in")
	var policy engine.Policy
	var odrlReq engine.OdrlRequest
	if err := ast.As(pol.Value, &policy); err != nil {
		fmt.Println("error getting policy")
		return nil, err
	}
	if err := ast.As(req.Value, &odrlReq); err != nil {
		fmt.Printf("error getting request: %v", err)
		return nil, err
	}

	ok, err := engine.Evaluate(policy, odrlReq)
	if err != nil {
		fmt.Println("error evaluating")
		return nil, err
	}

	return ast.BooleanTerm(ok), nil
}

// FIXME might (at some point) be smarter to outsource opa integration in separate repo, but not until independent use of godrl necessary
func main() {
	rego.RegisterBuiltin2(
		&rego.Function{
			Name: "odrl",
			Decl: types.NewFunction(types.Args(types.A, types.A), types.B),
		},
		odrl,
	)

	if err := cmd.RootCommand.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
