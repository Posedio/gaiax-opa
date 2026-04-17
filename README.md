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
pkg/cliexec/            # CLI exec built-in + plugin (build tag: cli_exec)
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

to build with the CLI exec plugin:

`go build --tags=cli_exec -v -o gaiax-opa ./cmd/`

to build with all plugins:

`go build --tags="gaiax_ovc grpc danube file_logger external_pdp cli_exec" -v -o gaiax-opa ./cmd/`

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

> **Security warning — `cli_exec`**
> The plugin executes arbitrary binaries on the OPA host with the same OS privileges as the OPA process.
> Misconfiguration can lead to **arbitrary command execution**:
> - **Use absolute paths** for all executables in the config. Relative paths depend on the working directory at runtime and may resolve to attacker-controlled binaries.
> - **Treat all Rego `input` values as untrusted.** Arguments passed from Rego are JSON-encoded (no shell expansion occurs), but they are still forwarded verbatim to the process. Validate or sanitise sensitive values inside the command itself.
> - **Restrict config file permissions.** The `commands` map is the sole allowlist of what can be executed. If an attacker can modify the config, they can run any binary.
> - **Apply least-privilege.** Run OPA under a dedicated user with no write access to command paths.

The `cli_exec` plugin registers the `cliExec(commandName, argsArray)` built-in function.
Commands are referenced by name from the config, so Rego policies stay decoupled from executable paths.
Each element of the args array is JSON-encoded and appended as a positional CLI argument after the base command.
The command must print valid JSON to stdout; that value is returned to Rego.
Anything written to stderr is forwarded to OPA's logger.
Enable it in the OPA config file:

```yaml
plugins:
  cli_exec:
    commands:
      validate_vat:  ["python3", "/opt/scripts/validate_vat.py"]
      check_cert:    ["/usr/bin/openssl", "verify", "-CAfile", "/etc/ssl/ca.pem"]
      my_tool:       ["/opt/bin/mytool", "--json"]
```

Usage in Rego:

```rego
result := cliExec("validate_vat", [input.claim, {"extra": "data"}])

errors contains msg if {
    result.error
    msg := result.error
}

allow if {
    not result.error
    result.valid == true
}
```

Example command script (`validate_vat.py`):

```python
import sys, json

claim = json.loads(sys.argv[1])
extra = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}

# write result as JSON to stdout
print(json.dumps({"valid": True, "claim": claim}))
```

On command errors or non-JSON output the built-in returns `{"error": "..."}` so policies can handle failures explicitly rather than aborting evaluation.


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

to run with docker compose (includes Python for cli_exec scripts):

```bash
docker compose -f doc/deployment/docker-compose/docker-compose.yaml up --build
```

to run the test policies:

`./gaiax-opa run --server --log-level=debug --addr=:8181 --watch doc/deployment/policies`

or with grpc and decision logs (note: HTTP listen address must be set via `--addr`, not via config file)

`./gaiax-opa run --server --addr=:8182 --config-file="./doc/examples/opa-config.yaml" --watch ./doc/examples/policies`



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