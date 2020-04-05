# Windesheim security / Winnote

## Usage

In order to run the application you need to get a pre-built binary from the releases tab or clone the repository and run from source code(follow the instructions below).
After getting a working executable, download the .config.dist.yaml file and input correct values. Prerequisites are: a mysql server, SMTP enabled mailserver and google recaptchaV2 keys.
After all surrounding infrastructure is set up, run the executable with the `-c` flag and specify the path to the config file.

## Building

Build for common platforms(will build for linux, windows and mac all both 32-bit and 64-bit architectures):
1. `make build`

Or if you are using a platform which Golang can compile to but is not one of the above manually compile:
1. `go get -u github.com/gobuffalo/packr/v2/packr2`
2. `packr2`
3. `go build`