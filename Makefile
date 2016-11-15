VERSION=V2016111502


all: windows windows32 linux darwin

-include sshkeys.mk

LDFLAGS=-X main.Version=$(VERSION) -X main.HCUser=$(HCUSER) -X main.HCKey=$(HCKEY)

windows:
	GOOS=windows GOARCH=amd64 go build -o binaries/jmcassh$(VERSION).exe --ldflags "$(LDFLAGS)" main.go

windows32:
	GOOS=windows GOARCH=386 go build -o binaries/jmcassh32$(VERSION).exe --ldflags "-$(LDFLAGS)" main.go


linux:
	GOOS=linux GOARCH=amd64 go build -o binaries/jmcassh$(VERSION)-linux --ldflags "$(LDFLAGS)" main.go

darwin:
	GOOS=darwin GOARCH=amd64 go build -o binaries/jmcassh$(VERSION)-darwin --ldflags "$(LDFLAGS)" main.go

