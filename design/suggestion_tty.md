# Terminal handling design

## Responsibility separation and overall design

Given that each client must be authenticated with an user to start an interactive session via SSH. It is practically necessary that each shell runs isolated from the rest of the application in order to respect user privileges and avoid possible attacks. For this reason, we delegate responsibilities to different processes:

 - Main process: Listens for new client connections over a TCP socket and spawns a new monitor process for each accepted connection.
 - Monitor process: Spawns a network process, it will also take care of allocating a terminal and spawning the command with the shell.
 - Network process: Handles the client connection that was delegated by the monitor process using the SSH protocol. It also requests a new command and terminal to the monitor process.

## Process spawning and terminal allocation

The monitor process runs on a new session as the leader. This configuration guarantees that the current connection with the client and the shell command will remain active even if the SSH server were unexpectedly terminated. Before spawning the network process, a UNIX socket is created for IPC. When a command request arrives via the socket to the monitor process, a new pseudo-terminal is allocated and its follower side is set as the controlling terminal for the session.

Then, the command process is spawned and the leader side of the pseudo-terminal is sent over the UNIX socket to the network process using the `SCM_RIGHTS` functionality. Once received, the network process will asyncronously copy data, in both directions, between the pseudo-terminal leader and the TCP socket.

### Why do we need a monitor process?

There are two alternatives to having a monitor process:

- Move all the monitor logic to the main process.
- Move all the monitor logic to the network process. 

However both options are less secure because the monitor process will handle authentication data (once authentication is implemented) and it is not network-facing. On the other hand, the main process and the network process are network-facing but never handle authentication data. This separation provides an extra layer of security.

### Why do we need more than one monitor?

It would be possible to monitor all the network processes with a single process instead. However, this would mean that all the authentication data of different users would be handled by the same process.

## Acknowledgements
Most of the design here is heavily inspired by the design of [OpenSSH](https://www.openssh.org/) and some ideas from the [Linux Programing Interface](https://man7.org/tlpi/index.html) book.
