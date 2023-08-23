# go-bindshell

## Description
go-bindshell is a fairly minimal and likely not entirely standard-conforming
SSH server that was created to serve as an authenticated bindshell. It includes
support for command execution, spawning a shell, port forwards and socks proxy
in both directions. PTY support is limited to only Linux as Windows demands for
now too much work to implement properly.

Supported authentication schemes are password auth, public key auth and
certificate auth. Certificate and public key auth supports features for
restricting access to certain features on a per-user basis. For instance, maybe
user1 only needs access to port forwarding while user2 should be able to execute
local commands on the server hosting the bindshell.
Note that the users are not bound to local user accounts and everyone that
authenticates against the bindshell will execute commands as the same user
account that was used to launch the server.

This package is also built in modules to support compiling a binary with only
support for a specific authentication scheme and only a subset of the features:
spawning a PTY, executing commands, and performing port forwards.
For more information on how to limit available functionality, refer to the
Makefile.

## Authentication schemes
There are tree authentication schemes available:

- Password authentication
- Public key authentication
- Certificate authentication

### Password authentication
To support password based authentication there must be a file named users.json
in the project directory at compile time. This json file contains a list of
objects with the required keys "Username" and "Password". An example is
provided in users.json.example

### Public key authentication
To support public key authentication there must be an authorized_keys file
in the project directory.
For now this mode of authentication does not support usernames but only a list
of allowed public keys. This means that any username could be used to
authenticate against the bindshell as long as the public key is included in
the authorized_keys file.

### Certificate authentication
Using certificate based authentication it is possible to generate client
certificates that grants access to the bindshell for a limited duration, for
a specific username, and with a subset of functionality available such as only
portforwarding but no local command execution.

However, setup is a bit more complex. To support this mode of authentication
a ca keypair has to be generated and then used to sign user public keys to
generate certificates.
The process of generating new certificates can be inspired or facilitated by
the helper utility gen.sh that is included in the repo. There is also another
helper utility called revoke.sh that is included to help create a certificate
revocation list.

When compiling the project with certificate auth the following files are
required to be present in the project directory:

- ca.pub (Should contain the SSH CA certificate public key bytes)
- host (Should contain the server's private SSH key used for server authentication)
- host-cert.pub (Should contain the server's SSH certificate used for server authentication)
- revokedCerts (Should contain a list of revoked certificates)
