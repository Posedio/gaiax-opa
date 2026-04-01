# gaiax-opa

OPA extension for Gaia-X and ODRL

## Project structure

```
api/proto/          # protobuf definitions
cmd/                # binary entrypoint (main package)
doc/                # deployment configs and examples
internal/grpcpb/    # generated protobuf/gRPC code
pkg/builtins/       # custom OPA built-in functions
pkg/grpcplugin/     # gRPC plugin for OPA (build tag: grpc)
pkg/danubeplugin/   # Danube plugin for OPA (build tag: danube)
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

to build with all plugins:

`go build --tags="gaiax_ovc grpc danube" -v -o gaiax-opa ./cmd/`

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