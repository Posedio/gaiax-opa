# gaiax-opa

OPA extension for Gaia-X and ODRL

## Usage

see doc/deployment folder

## Development 
to build with Gaia-X OVC use:

`go build --tags=gaiax_ovc -v -o gaiax-opa`

to run the test policies:

` ./gaiax-opa run --server --log-level=debug --addr=:8181 --watch doc/deployment/policies`

or with grpc and decision logs

`:/gaiax-opa run --server --config-file="./doc/examples/opa-config.yaml" --watch ./doc/deployment/policies`

## Contributing
Contributions are welcome, just open a pull request, please add/extend tests if you add new features.

## Contributor
Philipp Seifert-Kehrer, Posedio GmbH

Stefan Dumss, Posedio GmbH

## License
Released under MIT License, see the LICENCE file



Copyright (c) 2025 Posedio GmbH