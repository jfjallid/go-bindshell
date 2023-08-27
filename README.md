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
user1 only needs access to port forwarding while user2 should be able to
execute local commands on the server hosting the bindshell.
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
local command execution but no port forwarding.

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

### Custom privileges
Privileges/features that can be toggled on a per-user bases include:

- Local port forwarding (-L flag)
- Reverse port forwarding (-R flag)
- Spawning of a PTY

When using Public key authentication there are a lot of possible attributes
that can be used in the authorized_keys file to enable or disable functionality
for a given pubkey.

Currently the following keywords are supported for use in the authorized_keys
file:

- restrict: By default everything is allowed unless explicitly denied, this keyword reverses that logic
- no-pty
- no-port-forwarding: Disables port forwarding in both directions and overrules any other keywords.
- pty
- permitlisten: Can be supplied multiple times to explicitly allow a given port
- permitopen: Can be supplised multiple times to explicitly allow a given port

permitlisten and permitopen can be supplied with the single value "any" or
"none" to enable or disable all local and reverse forwards respectively.

When using Certificate authentication, things are a bit more complex.
The Extensions list of the client certificate is used to enable or disable a
given feature. An empty extension list means that nothing is allowed that can
be toggled.

Due to how SSH certificates are defined, a given certificate extension name
must only occur once, and must be in a lexical order. ssh-keygen is a useful
tool for generating ssh client certificates but it only supports general
extensions to either allow all or block all port forwarding in both directions.
However, it is possible to supply custom extensions.

To allow granular permissions for local and reverse port forwards, the
"permitlisten" and "permitopen" custom extensions are supported. To workaround
the limitation of unique extension names, the permission parsing logic only
checks that the extesion name begins with permitlisten or permitopen, so when
multiple permitlisten statements are to be included in a certificate, add them
as permitlisten1, permitlisten2, permitlisten3, etc. Same goes for permitopen.

Currently the following extensions are supported for use with client
certificates:

- permit-port-forwarding: Allows all port forwards in both directions
- permit-pty
- permitlisten: Can be supplied multiple times to explicitly allow a given port using a new suffix for each rule
- permitopen: Can be supplied multiple times to explicitly allow a given port using a new suffix for each rule

permitlisten and permitopen can be supplied with the single value "any" or
"none" to enable or disable all local and reverse forwards respectively.
