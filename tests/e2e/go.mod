module golang-fbom-generator/tests/e2e

go 1.23.0

toolchain go1.24.4

replace golang-fbom-generator/tests/shared => ../shared

require (
	golang-fbom-generator/tests/shared v0.0.0-00010101000000-000000000000
	gopkg.in/yaml.v2 v2.4.0
)

require (
	golang.org/x/mod v0.27.0 // indirect
	golang.org/x/sync v0.16.0 // indirect
	golang.org/x/tools v0.36.0 // indirect
)
