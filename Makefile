build: packr build-linux-386 build-linux-amd64 build-windows-386 build-windows-amd64 build-darwin-386 build-darwin-amd64

packr:
	packr2

build-linux-386:
	CGO_ENABLED=0 GOOS=linux GOARCH=386 go build -o dist/winnote-linux-386 .

build-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dist/winnote-linux-amd64 .

build-windows-386:
	CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -o dist/winnote-windows-386 .

build-windows-amd64:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o dist/winnote-windows-amd64 .

build-darwin-386:
	CGO_ENABLED=0 GOOS=darwin GOARCH=386 go build -o dist/winnote-darwin-386 .

build-darwin-amd64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o dist/winnote-darwin-amd64 .