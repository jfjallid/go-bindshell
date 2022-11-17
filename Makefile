# Add an authorized_keys file in directory with permitted pubkeys to specify allowed users.
#
all:
	go build -ldflags "-s -w"

clean:
	rm -f bindshell
