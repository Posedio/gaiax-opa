# gaiax-opa

OPA extension for Gaia-X and ODRL

## Project structure

```
api/proto/              # protobuf definitions
cmd/                    # binary entrypoint (main package)
doc/                    # deployment configs and examples
internal/grpcpb/        # generated protobuf/gRPC code
pkg/builtins/           # custom OPA built-in functions
pkg/decisionlog/        # shared decision log helper used by all plugins
pkg/grpcplugin/         # gRPC plugin (build tag: grpc)
pkg/danubeplugin/       # Danube credential issuance plugin (build tag: danube)
pkg/externalpdp/        # external PDP built-in + plugin (build tag: external_pdp)
```

## Usage

see doc/deployment folder


### Build

to build with Gaia-X OVC use:

`go build --tags=gaiax_ovc -v -o gaiax-opa ./cmd/`

to build with the gRPC plugin:

`go build --tags=grpc -v -o gaiax-opa ./cmd/`

to build with both Gaia-X OVC and gRPC:

`go build --tags="gaiax_ovc grpc" -v -o gaiax-opa ./cmd/`

to build with the Danube plugin:

`go build --tags=danube -v -o gaiax-opa ./cmd/`

to build with the file logger plugin (structured JSON log rotation via lumberjack):

`go build --tags=file_logger -v -o gaiax-opa ./cmd/`

to build with the external PDP plugin:

`go build --tags=external_pdp -v -o gaiax-opa ./cmd/`

to build with all plugins:

`go build --tags="gaiax_ovc grpc danube file_logger external_pdp" -v -o gaiax-opa ./cmd/`

The gRPC plugin registers an `OPAService` gRPC server (proto at `api/proto/opa.proto`).
Enable it in the OPA config file:

```yaml
plugins:
  grpc:
    addr: ":50051"
```

The Danube plugin integrates OPA with a Danube service for credential issuance.
Enable it in the OPA config file:

```yaml
plugins:
  danube:
    keyPath: "/path/to/private.key"
    sigAlgo: "EdDSA"
    issuer: "did:web:example.com"
    verificationMethod: "did:web:example.com#key-1"
    path: "/danube" #host is the same as the OPA server, currently not available in the grpc plugin
    policy: "data.verify.legalPerson"
    idPrefix: "https://example.com/credentials"
```

The `external_pdp` plugin registers the `externalPDP(source, input)` built-in function.
Sources are named HTTP endpoints configured server-side, so Rego policies stay decoupled from URLs.
Enable it in the OPA config file:

```yaml
plugins:
  external_pdp:
    sources:
      other_opa: "http://other-opa:8181/v1/data/my/policy"
      legacy_pdp: "https://pdp.example.com/decide"
```

Usage in Rego:

```rego
ex_result := externalPDP("other_opa", input)

deny contains msg if {
    ex_result.error
    msg := ex_result.error
}

allow if {
    not ex_result.error
    ex_result.allow
}
```

The function unwraps OPA's `{"result": ...}` envelope automatically.
On network or configuration errors it returns `{"error": "..."}` so policies can handle failures explicitly rather than aborting evaluation.


```yaml
decision_logs:
  console: true
```

to build the Docker image (includes both `gaiax_ovc` and `grpc` by default):

```bash
docker build -t gaiax-opa .
```

to build without the gRPC plugin:

```bash
docker build --build-arg BUILD_TAGS=gaiax_ovc -t gaiax-opa .
```

to run the test policies:

`./gaiax-opa run --server --log-level=debug --addr=:8181 --watch doc/deployment/policies`

or with grpc and decision logs (note: HTTP listen address must be set via `--addr`, not via config file)

`./gaiax-opa run --server --addr=:8182 --config-file="./doc/examples/opa-config.yaml" --watch ./doc/deployment/policies`



## Development

### Regenerate gRPC proto for grpc plugin

```bash
protoc \
  --go_out=. --go_opt=paths=import \
  --go-grpc_out=. --go-grpc_opt=paths=import \
  --proto_path=api/proto \
  api/proto/opa.proto
```



## Contributing
Contributions are welcome, just open a pull request, please add/extend tests if you add new features.

## Contributor
Philipp Seifert-Kehrer, Posedio GmbH

Stefan Dumss, Posedio GmbH

## License
Released under MIT License, see the LICENCE file



Copyright (c) 2025 Posedio GmbH