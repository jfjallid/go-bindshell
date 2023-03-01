# Add an authorized_keys file in directory with permitted pubkeys to specify allowed users.
# Add an ssh CA keypair called ca and ca.pub to support certificate authentication.


BINDPORT=2023

all:
	GOOS=linux GOARCH=amd64 go build -tags shell,portforwards,certauth,pubkeyauth,passauth -ldflags "-s -w -X main.bindPortStr=${BINDPORT}"
	GOOS=windows GOARCH=386 go build -tags shell,portforwards,certauth,pubkeyauth,passauth -ldflags "-s -w -X main.bindPortStr=${BINDPORT}" -o bindshell.exe .

shellonly:
	GOOS=linux GOARCH=amd64 go build -tags shell -ldflags "-s -w -X main.bindPortStr=${BINDPORT}"
	GOOS=windows GOARCH=386 go build -tags shell -ldflags "-s -w -X main.bindPortStr=${BINDPORT}" -o bindshell.exe .

forwardonly:
	GOOS=linux GOARCH=amd64 go build -tags portforwards -ldflags "-s -w -X main.bindPortStr=${BINDPORT}"
	GOOS=windows GOARCH=386 go build -tags portforwards -ldflags "-s -w -X main.bindPortStr=${BINDPORT}" -o bindshell.exe .

clean:
	rm -f bindshell
	rm -f bindshell.exe
