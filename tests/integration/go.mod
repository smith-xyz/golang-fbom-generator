module golang-fbom-generator/tests/integration

go 1.23.0

toolchain go1.24.4

replace golang-fbom-generator/tests/shared => ../shared

replace github.com/smith-xyz/golang-fbom-generator => ../..

require (
	github.com/smith-xyz/golang-fbom-generator v0.0.0-00010101000000-000000000000
	golang.org/x/tools v0.36.0
)

require (
	github.com/BurntSushi/toml v1.5.0 // indirect
	golang.org/x/mod v0.27.0 // indirect
	golang.org/x/sync v0.16.0 // indirect
)
