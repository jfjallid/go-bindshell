# Add an authorized_keys file in directory with permitted pubkeys to specify allowed users.
#
all:
	go build -ldflags "-s -w"
	GOOS=windows GOARCH=386 go build -ldflags "-s -w" -o bindshell.exe .

clean:
	rm -f bindshell
	rm -f bindshell.exe
