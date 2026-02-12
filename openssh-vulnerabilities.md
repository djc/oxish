# OpenSSH vulnerabilities from OpenCVE

Vulnerabilities affecting the **openssh** product (vendor: openbsd) as listed on
[OpenCVE](https://app.opencve.io/cve/?product=openssh&vendor=openbsd).

- **[CVE-2025-61985](https://app.opencve.io/cve/CVE-2025-61985)** (2025-10-08) — CVSS: **3.6 Low** —
  ssh in OpenSSH before 10.1 allows the '\0' character in an ssh:// URI, potentially leading to code
  execution when a ProxyCommand is used.

- **[CVE-2025-61984](https://app.opencve.io/cve/CVE-2025-61984)** (2025-11-11) — CVSS: **3.6 Low** —
  ssh in OpenSSH before 10.1 allows control characters in usernames that originate from certain
  possibly untrusted sources, potentially leading to code execution when a ProxyCommand is used.

- **[CVE-2025-32728](https://app.opencve.io/cve/CVE-2025-32728)** (2025-05-22) — CVSS: **4.3
  Medium** — In sshd in OpenSSH before 10.0, the DisableForwarding directive does not adhere to the
  documentation stating that it disables X11 and agent forwarding.

- **[CVE-2025-26466](https://app.opencve.io/cve/CVE-2025-26466)** (2026-02-10) — CVSS: **5.9
  Medium** — A flaw was found in the OpenSSH package. For each ping packet the SSH server receives,
  a pong packet is allocated in a memory buffer and stored in a queue of packages. It is only freed
  when the server/client key exchange has finished. A malicious client may keep sending such
  packages, leading to an uncontrolled increase in memory consumption on the server side.
  Consequently, the server may become unavailable, resulting in a denial of service attack.

- **[CVE-2025-26465](https://app.opencve.io/cve/CVE-2025-26465)** (2026-01-29) — CVSS: **6.8
  Medium** — A vulnerability was found in OpenSSH when the VerifyHostKeyDNS option is enabled. A
  machine-in-the-middle attack can be performed by a malicious machine impersonating a legit server.
  This issue occurs due to how OpenSSH mishandles error codes in specific conditions when verifying
  the host key.

- **[CVE-2024-39894](https://app.opencve.io/cve/CVE-2024-39894)** (2025-11-04) — CVSS: **7.5 High**
  — OpenSSH 9.5 through 9.7 before 9.8 sometimes allows timing attacks against echo-off password
  entry (e.g., for su and Sudo) because of an ObscureKeystrokeTiming logic error.

- **[CVE-2024-6387](https://app.opencve.io/cve/CVE-2024-6387)** (2025-12-11) — CVSS: **8.1 High** —
  A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race
  condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated,
  remote attacker may be able to trigger it by failing to authenticate within a set time period.

- **[CVE-2023-51767](https://app.opencve.io/cve/CVE-2023-51767)** (2025-11-18) — CVSS: **7.0 High**
  — OpenSSH through 10.0, when common types of DRAM are used, might allow row hammer attacks (for
  authentication bypass) because the integer value of authenticated in mm_answer_authpassword does
  not resist flips of a single bit. (Disputed)

- **[CVE-2023-51385](https://app.opencve.io/cve/CVE-2023-51385)** (2025-12-18) — CVSS: **6.5
  Medium** — In ssh in OpenSSH before 9.6, OS command injection might occur if a user name or host
  name has shell metacharacters, and this name is referenced by an expansion token in certain
  situations.

- **[CVE-2023-51384](https://app.opencve.io/cve/CVE-2023-51384)** (2024-11-21) — CVSS: **5.5
  Medium** — In ssh-agent in OpenSSH before 9.6, certain destination constraints can be incompletely
  applied. When destination constraints are specified during addition of PKCS#11-hosted private
  keys, these constraints are only applied to the first key.

- **[CVE-2023-48795](https://app.opencve.io/cve/CVE-2023-48795)** (2025-11-04) — CVSS: **5.9
  Medium** — The SSH transport protocol with certain OpenSSH extensions, found in OpenSSH before 9.6
  and other products, allows remote attackers to bypass integrity checks such that some packets are
  omitted (Terrapin attack).

- **[CVE-2023-38408](https://app.opencve.io/cve/CVE-2023-38408)** (2024-11-21) — CVSS: **9.8
  Critical** — The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an insufficiently
  trustworthy search path, leading to remote code execution if an agent is forwarded to an
  attacker-controlled system.

- **[CVE-2023-35812](https://app.opencve.io/cve/CVE-2023-35812)** (2025-07-12) — CVSS: **5.3
  Medium** — An issue was discovered in the Amazon Linux packages of OpenSSH 7.4 for Amazon Linux 1
  and 2, because of an incomplete fix for CVE-2019-6111 within these specific packages.

- **[CVE-2023-28531](https://app.opencve.io/cve/CVE-2023-28531)** (2025-11-04) — CVSS: **9.8
  Critical** — ssh-add in OpenSSH before 9.3 adds smartcard keys to ssh-agent without the intended
  per-hop destination constraints. The earliest affected version is 8.9.

- **[CVE-2023-25136](https://app.opencve.io/cve/CVE-2023-25136)** (2024-11-21) — CVSS: **6.5
  Medium** — OpenSSH server (sshd) 9.1 introduced a double-free vulnerability during
  options.kex_algorithms handling. This is fixed in OpenSSH 9.2. The double free can be leveraged,
  by an unauthenticated remote attacker in the default configuration, to jump to any location in the
  sshd address space.

- **[CVE-2022-31124](https://app.opencve.io/cve/CVE-2022-31124)** (2025-04-22) — CVSS: **7.7 High**
  — openssh_key_parser is an open source Python package providing utilities to parse and pack
  OpenSSH private and public key files. In versions prior to 0.0.6 if a field of a key is shorter
  than it is declared to be, the parser raises an error with a message containing the raw field
  value.

- **[CVE-2021-41617](https://app.opencve.io/cve/CVE-2021-41617)** (2024-11-21) — CVSS: **7.0 High**
  — sshd in OpenSSH 6.2 through 8.x before 8.8, when certain non-default configurations are used,
  allows privilege escalation because supplemental groups are not initialized as expected.

- **[CVE-2021-36368](https://app.opencve.io/cve/CVE-2021-36368)** (2024-11-21) — CVSS: **3.7 Low** —
  An issue was discovered in OpenSSH before 8.9. If a client is using public-key authentication with
  agent forwarding but without -oLogLevel=verbose, and an attacker has silently modified the server
  to support the None authentication option, then the user cannot determine whether FIDO
  authentication is going to confirm the intended connection. (Disputed)

- **[CVE-2021-28041](https://app.opencve.io/cve/CVE-2021-28041)** (2024-11-21) — CVSS: **7.1 High**
  — ssh-agent in OpenSSH before 8.5 has a double free that may be relevant in a few less-common
  scenarios, such as unconstrained agent-socket access on a legacy operating system, or the
  forwarding of an agent to an attacker-controlled host.

- **[CVE-2020-15778](https://app.opencve.io/cve/CVE-2020-15778)** (2025-07-28) — CVSS: **7.4 High**
  — scp in OpenSSH through 8.3p1 allows command injection in the scp.c toremote function, as
  demonstrated by backtick characters in the destination argument.

- **[CVE-2020-14145](https://app.opencve.io/cve/CVE-2020-14145)** (2025-12-18) — CVSS: **5.9
  Medium** — The client side in OpenSSH 5.7 through 8.4 has an Observable Discrepancy leading to an
  information leak in the algorithm negotiation. This allows man-in-the-middle attackers to target
  initial connection attempts.

- **[CVE-2020-12062](https://app.opencve.io/cve/CVE-2020-12062)** (2024-11-21) — CVSS: **7.5 High**
  — The scp client in OpenSSH 8.2 incorrectly sends duplicate responses to the server upon a utimes
  system call failure, which allows a malicious unprivileged user on the remote server to overwrite
  arbitrary files in the client's download directory.

- **[CVE-2019-16905](https://app.opencve.io/cve/CVE-2019-16905)** (2025-04-23) — CVSS: **7.8 High**
  — OpenSSH 7.7 through 7.9 and 8.x before 8.1, when compiled with an experimental key type, has a
  pre-authentication integer overflow if a client or server is configured to use a crafted XMSS key.

- **[CVE-2019-6111](https://app.opencve.io/cve/CVE-2019-6111)** (2025-12-18) — CVSS: **5.9 Medium**
  — An issue was discovered in OpenSSH 7.9. Due to the scp implementation being derived from 1983
  rcp, the server chooses which files/directories are sent to the client. A malicious scp server (or
  MitM attacker) can overwrite arbitrary files in the scp client target directory.

- **[CVE-2019-6110](https://app.opencve.io/cve/CVE-2019-6110)** (2025-12-18) — CVSS: **6.8 Medium**
  — In OpenSSH 7.9, due to accepting and displaying arbitrary stderr output from the server, a
  malicious server (or MitM attacker) can manipulate the client output, for example to use ANSI
  control codes to hide additional files being transferred.

- **[CVE-2019-6109](https://app.opencve.io/cve/CVE-2019-6109)** (2024-11-21) — CVSS: **6.8 Medium**
  — An issue was discovered in OpenSSH 7.9. Due to missing character encoding in the progress
  display, a malicious server (or MitM attacker) can employ crafted object names to manipulate the
  client output, e.g., by using ANSI control codes to hide additional files being transferred.

- **[CVE-2018-20685](https://app.opencve.io/cve/CVE-2018-20685)** (2025-12-17) — CVSS: **5.3
  Medium** — In OpenSSH 7.9, scp.c in the scp client allows remote SSH servers to bypass intended
  access restrictions via the filename of . or an empty filename. The impact is modifying the
  permissions of the target directory on the client side.

- **[CVE-2018-15919](https://app.opencve.io/cve/CVE-2018-15919)** (2025-12-18) — CVSS: **5.3
  Medium** — Remotely observable behaviour in auth-gss2.c in OpenSSH through 7.8 could be used by
  remote attackers to detect existence of users on a target system when GSS2 is in use.

- **[CVE-2018-15473](https://app.opencve.io/cve/CVE-2018-15473)** (2025-12-17) — CVSS: **5.9
  Medium** — OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying
  bailout for an invalid authenticating user until after the packet containing the request has been
  fully parsed.

- **[CVE-2017-15906](https://app.opencve.io/cve/CVE-2017-15906)** (2025-04-20) — CVSS: **5.3
  Medium** — The process_open function in sftp-server.c in OpenSSH before 7.6 does not properly
  prevent write operations in readonly mode, which allows attackers to create zero-length files.

- **[CVE-2016-20012](https://app.opencve.io/cve/CVE-2016-20012)** (2024-11-21) — CVSS: **5.3
  Medium** — OpenSSH through 8.7 allows remote attackers, who have a suspicion that a certain
  combination of username and public key is known to an SSH server, to test whether this suspicion
  is correct. (Disputed)

- **[CVE-2016-10708](https://app.opencve.io/cve/CVE-2016-10708)** (2024-11-21) — CVSS: **N/A** —
  sshd in OpenSSH before 7.4 allows remote attackers to cause a denial of service (NULL pointer
  dereference and daemon crash) via an out-of-sequence NEWKEYS message, as demonstrated by
  Honggfuzz.

- **[CVE-2016-10012](https://app.opencve.io/cve/CVE-2016-10012)** (2025-04-12) — CVSS: **N/A** — The
  shared memory manager (associated with pre-authentication compression) in sshd in OpenSSH before
  7.4 does not ensure that a bounds check is enforced by all compilers, which might allow local
  users to gain privileges.

- **[CVE-2016-10011](https://app.opencve.io/cve/CVE-2016-10011)** (2025-04-12) — CVSS: **N/A** —
  authfile.c in sshd in OpenSSH before 7.4 does not properly consider the effects of realloc on
  buffer contents, which might allow local users to obtain sensitive private-key information.

- **[CVE-2016-10010](https://app.opencve.io/cve/CVE-2016-10010)** (2025-04-12) — CVSS: **N/A** —
  sshd in OpenSSH before 7.4, when privilege separation is not used, creates forwarded Unix-domain
  sockets as root, which might allow local users to gain privileges via unspecified vectors.

- **[CVE-2016-10009](https://app.opencve.io/cve/CVE-2016-10009)** (2025-04-12) — CVSS: **N/A** —
  Untrusted search path vulnerability in ssh-agent.c in ssh-agent in OpenSSH before 7.4 allows
  remote attackers to execute arbitrary local PKCS#11 modules by leveraging control over a forwarded
  agent-socket.

- **[CVE-2016-8858](https://app.opencve.io/cve/CVE-2016-8858)** (2025-04-12) — CVSS: **N/A** — The
  kex_input_kexinit function in kex.c in OpenSSH 6.x and 7.x through 7.3 allows remote attackers to
  cause a denial of service (memory consumption) by sending many duplicate KEXINIT requests.
  (Disputed)

- **[CVE-2016-6515](https://app.opencve.io/cve/CVE-2016-6515)** (2025-04-12) — CVSS: **N/A** — The
  auth_password function in auth-passwd.c in sshd in OpenSSH before 7.3 does not limit password
  lengths for password authentication, which allows remote attackers to cause a denial of service
  (crypt CPU consumption) via a long string.

- **[CVE-2016-6210](https://app.opencve.io/cve/CVE-2016-6210)** (2025-04-20) — CVSS: **N/A** — sshd
  in OpenSSH before 7.3, when SHA256 or SHA512 are used for user password hashing, uses BLOWFISH
  hashing on a static password when the username does not exist, which allows remote attackers to
  enumerate users by leveraging the timing difference between responses.

- **[CVE-2016-3115](https://app.opencve.io/cve/CVE-2016-3115)** (2025-04-12) — CVSS: **N/A** —
  Multiple CRLF injection vulnerabilities in session.c in sshd in OpenSSH before 7.2p2 allow remote
  authenticated users to bypass intended shell-command restrictions via crafted X11 forwarding data.

- **[CVE-2016-1908](https://app.opencve.io/cve/CVE-2016-1908)** (2025-04-20) — CVSS: **9.8
  Critical** — The client in OpenSSH before 7.2 mishandles failed cookie generation for untrusted
  X11 forwarding and relies on the local X11 server for access-control decisions, which allows
  remote X11 clients to trigger a fallback and obtain trusted X11 forwarding privileges.

- **[CVE-2016-1907](https://app.opencve.io/cve/CVE-2016-1907)** (2025-04-12) — CVSS: **N/A** — The
  ssh_packet_read_poll2 function in packet.c in OpenSSH before 7.1p2 allows remote attackers to
  cause a denial of service (out-of-bounds read and application crash) via crafted network traffic.

- **[CVE-2016-0778](https://app.opencve.io/cve/CVE-2016-0778)** (2025-04-12) — CVSS: **N/A** — The
  (1) roaming_read and (2) roaming_write functions in roaming_common.c in the client in OpenSSH 5.x,
  6.x, and 7.x before 7.1p2, when certain proxy and forward options are enabled, do not properly
  maintain connection file descriptors, which allows remote servers to cause a denial of service
  (heap-based buffer overflow).

- **[CVE-2016-0777](https://app.opencve.io/cve/CVE-2016-0777)** (2025-04-12) — CVSS: **N/A** — The
  resend_bytes function in roaming_common.c in the client in OpenSSH 5.x, 6.x, and 7.x before 7.1p2
  allows remote servers to obtain sensitive information from process memory by requesting
  transmission of an entire buffer, as demonstrated by reading a private key.

- **[CVE-2015-8325](https://app.opencve.io/cve/CVE-2015-8325)** (2025-04-12) — CVSS: **N/A** — The
  do_setup_env function in session.c in sshd in OpenSSH through 7.2p2, when the UseLogin feature is
  enabled and PAM is configured to read .pam_environment files in user home directories, allows
  local users to gain privileges.

- **[CVE-2015-6565](https://app.opencve.io/cve/CVE-2015-6565)** (2025-04-12) — CVSS: **N/A** — sshd
  in OpenSSH 6.8 and 6.9 uses world-writable permissions for TTY devices, which allows local users
  to cause a denial of service (terminal disruption) or possibly have unspecified other impact.

- **[CVE-2015-6564](https://app.opencve.io/cve/CVE-2015-6564)** (2025-04-12) — CVSS: **N/A** —
  Use-after-free vulnerability in the mm_answer_pam_free_ctx function in monitor.c in sshd in
  OpenSSH before 7.0 on non-OpenBSD platforms might allow local users to gain privileges by
  leveraging control of the sshd uid.

- **[CVE-2015-6563](https://app.opencve.io/cve/CVE-2015-6563)** (2025-04-12) — CVSS: **N/A** — The
  monitor component in sshd in OpenSSH before 7.0 on non-OpenBSD platforms accepts extraneous
  username data in MONITOR_REQ_PAM_INIT_CTX requests, which allows local users to conduct
  impersonation attacks.

- **[CVE-2015-5600](https://app.opencve.io/cve/CVE-2015-5600)** (2025-04-12) — CVSS: **N/A** — The
  kbdint_next_device function in auth2-chall.c in sshd in OpenSSH through 6.9 does not properly
  restrict the processing of keyboard-interactive devices within a single connection, which makes it
  easier for remote attackers to conduct brute-force attacks or cause a denial of service (CPU
  consumption).

- **[CVE-2015-5352](https://app.opencve.io/cve/CVE-2015-5352)** (2025-04-12) — CVSS: **N/A** — The
  x11_open_helper function in channels.c in ssh in OpenSSH before 6.9, when ForwardX11Trusted mode
  is not used, lacks a check of the refusal deadline for X connections, which makes it easier for
  remote attackers to bypass intended access restrictions.

- **[CVE-2014-9278](https://app.opencve.io/cve/CVE-2014-9278)** (2025-04-12) — CVSS: **N/A** — The
  OpenSSH server, as used in Fedora and Red Hat Enterprise Linux 7 and when running in a Kerberos
  environment, allows remote authenticated users to log in as another user when they are listed in
  the .k5users file of that user.

- **[CVE-2014-2653](https://app.opencve.io/cve/CVE-2014-2653)** (2025-04-12) — CVSS: **N/A** — The
  verify_host_key function in sshconnect.c in the client in OpenSSH 6.6 and earlier allows remote
  servers to trigger the skipping of SSHFP DNS RR checking by presenting an unacceptable
  HostCertificate.

- **[CVE-2014-2532](https://app.opencve.io/cve/CVE-2014-2532)** (2025-04-12) — CVSS: **N/A** — sshd
  in OpenSSH before 6.6 does not properly support wildcards on AcceptEnv lines in sshd_config, which
  allows remote attackers to bypass intended environment restrictions.

- **[CVE-2014-1692](https://app.opencve.io/cve/CVE-2014-1692)** (2025-04-11) — CVSS: **N/A** — The
  hash_buffer function in schnorr.c in OpenSSH through 6.4, when Makefile.inc is modified to enable
  the J-PAKE protocol, does not initialize certain data structures, which might allow remote
  attackers to cause a denial of service (memory corruption).

- **[CVE-2013-4548](https://app.opencve.io/cve/CVE-2013-4548)** (2025-04-11) — CVSS: **N/A** — The
  mm_newkeys_from_blob function in monitor_wrap.c in sshd in OpenSSH 6.2 and 6.3, when an AES-GCM
  cipher is used, does not properly initialize memory for a MAC context data structure, which allows
  remote authenticated users to bypass intended ForceCommand and login-shell restrictions.

- **[CVE-2012-0814](https://app.opencve.io/cve/CVE-2012-0814)** (2025-04-11) — CVSS: **N/A** — The
  auth_parse_options function in auth-options.c in sshd in OpenSSH before 5.7 provides debug
  messages containing authorized_keys command options, which allows remote authenticated users to
  obtain potentially sensitive information.

- **[CVE-2011-5000](https://app.opencve.io/cve/CVE-2011-5000)** (2025-04-11) — CVSS: **N/A** — The
  ssh_gssapi_parse_ename function in gss-serv.c in OpenSSH 5.8 and earlier, when gssapi-with-mic
  authentication is enabled, allows remote authenticated users to cause a denial of service (memory
  consumption) via a large value in a certain length field.

- **[CVE-2011-4327](https://app.opencve.io/cve/CVE-2011-4327)** (2025-04-11) — CVSS: **N/A** —
  ssh-keysign.c in ssh-keysign in OpenSSH before 5.8p2 on certain platforms executes ssh-rand-helper
  with unintended open file descriptors, which allows local users to obtain sensitive key
  information via the ptrace system call.

- **[CVE-2011-0539](https://app.opencve.io/cve/CVE-2011-0539)** (2025-04-11) — CVSS: **N/A** — The
  key_certify function in usr.bin/ssh/key.c in OpenSSH 5.6 and 5.7, when generating legacy
  certificates using the -t command-line option in ssh-keygen, does not initialize the nonce field,
  which might allow remote attackers to obtain sensitive stack memory contents.

- **[CVE-2010-5107](https://app.opencve.io/cve/CVE-2010-5107)** (2025-04-11) — CVSS: **N/A** — The
  default configuration of OpenSSH through 6.1 enforces a fixed time limit between establishing a
  TCP connection and completing a login, which makes it easier for remote attackers to cause a
  denial of service (connection-slot exhaustion).

- **[CVE-2010-4755](https://app.opencve.io/cve/CVE-2010-4755)** (2025-04-11) — CVSS: **N/A** — The
  (1) remote_glob function in sftp-glob.c and the (2) process_put function in sftp.c in OpenSSH 5.8
  and earlier allow remote authenticated users to cause a denial of service (CPU and memory
  consumption) via crafted glob expressions.

- **[CVE-2010-4478](https://app.opencve.io/cve/CVE-2010-4478)** (2025-04-11) — CVSS: **N/A** —
  OpenSSH 5.6 and earlier, when J-PAKE is enabled, does not properly validate the public parameters
  in the J-PAKE protocol, which allows remote attackers to bypass the need for knowledge of the
  shared secret.

- **[CVE-2009-2904](https://app.opencve.io/cve/CVE-2009-2904)** (2025-04-09) — CVSS: **N/A** — A
  certain Red Hat modification to the ChrootDirectory feature in OpenSSH 4.8 allows local users to
  gain privileges via hard links to setuid programs that use configuration files within the chroot
  directory.

- **[CVE-2008-5161](https://app.opencve.io/cve/CVE-2008-5161)** (2025-04-09) — CVSS: **N/A** — Error
  handling in the SSH protocol in OpenSSH 4.7p1 and possibly other versions, when using a block
  cipher algorithm in CBC mode, makes it easier for remote attackers to recover certain plaintext
  data from an arbitrary block of ciphertext in an SSH session.

- **[CVE-2008-4109](https://app.opencve.io/cve/CVE-2008-4109)** (2025-04-09) — CVSS: **N/A** — A
  certain Debian patch for OpenSSH before 4.3p2-9etch3 uses functions that are not async-signal-safe
  in the signal handler for login timeouts, which allows remote attackers to cause a denial of
  service (connection slot exhaustion).

- **[CVE-2008-3844](https://app.opencve.io/cve/CVE-2008-3844)** (2025-04-09) — CVSS: **N/A** —
  Certain Red Hat Enterprise Linux (RHEL) 4 and 5 packages for OpenSSH, as signed in August 2008
  using a legitimate Red Hat GPG key, contain an externally introduced modification (Trojan Horse).

- **[CVE-2008-3259](https://app.opencve.io/cve/CVE-2008-3259)** (2025-04-09) — CVSS: **N/A** —
  OpenSSH before 5.1 sets the SO_REUSEADDR socket option when the X11UseLocalhost configuration
  setting is disabled, which allows local users on some platforms to hijack the X11 forwarding port.

- **[CVE-2008-3234](https://app.opencve.io/cve/CVE-2008-3234)** (2025-04-09) — CVSS: **N/A** — sshd
  in OpenSSH 4 on Debian GNU/Linux allows remote authenticated users to obtain access to arbitrary
  SELinux roles by appending a :/ (colon slash) sequence, followed by the role name, to the
  username.

- **[CVE-2008-1657](https://app.opencve.io/cve/CVE-2008-1657)** (2025-04-09) — CVSS: **N/A** —
  OpenSSH 4.4 up to versions before 4.9 allows remote authenticated users to bypass the sshd_config
  ForceCommand directive by modifying the .ssh/rc session file.

- **[CVE-2008-1483](https://app.opencve.io/cve/CVE-2008-1483)** (2025-04-09) — CVSS: **N/A** —
  OpenSSH 4.3p2 and possibly other versions allows local users to hijack forwarded X connections by
  causing ssh to set DISPLAY to :10, even when another process is listening on the associated port.

- **[CVE-2007-4752](https://app.opencve.io/cve/CVE-2007-4752)** (2025-04-09) — CVSS: **N/A** — ssh
  in OpenSSH before 4.7 does not properly handle when an untrusted cookie cannot be created and uses
  a trusted X11 cookie instead, which allows attackers to violate intended policy and gain
  privileges.

- **[CVE-2007-4654](https://app.opencve.io/cve/CVE-2007-4654)** (2025-04-09) — CVSS: **N/A** —
  Unspecified vulnerability in SSHield 1.6.1 with OpenSSH 3.0.2p1 on Cisco WebNS 8.20.0.1 on Cisco
  Content Services Switch (CSS) series 11000 devices allows remote attackers to cause a denial of
  service.

- **[CVE-2007-3102](https://app.opencve.io/cve/CVE-2007-3102)** (2025-04-09) — CVSS: **N/A** —
  Unspecified vulnerability in the linux_audit_record_event function in OpenSSH 4.3p2, as used on
  Fedora Core 6 and possibly other systems, allows remote attackers to write arbitrary characters to
  an audit log via a crafted username.

- **[CVE-2007-2768](https://app.opencve.io/cve/CVE-2007-2768)** (2025-04-09) — CVSS: **N/A** —
  OpenSSH, when using OPIE (One-Time Passwords in Everything) for PAM, allows remote attackers to
  determine the existence of certain user accounts, which displays a different response if the user
  account exists and is configured to use one-time passwords.

- **[CVE-2007-2243](https://app.opencve.io/cve/CVE-2007-2243)** (2025-04-09) — CVSS: **N/A** —
  OpenSSH 4.6 and earlier, when ChallengeResponseAuthentication is enabled, allows remote attackers
  to determine the existence of user accounts by attempting to authenticate via S/KEY.

- **[CVE-2006-5229](https://app.opencve.io/cve/CVE-2006-5229)** (2025-04-09) — CVSS: **N/A** —
  OpenSSH portable 4.1 on SUSE Linux, and possibly other platforms and versions, allows remote
  attackers to determine valid usernames via timing discrepancies in which responses take longer for
  valid usernames.

- **[CVE-2006-5052](https://app.opencve.io/cve/CVE-2006-5052)** (2025-04-09) — CVSS: **N/A** —
  Unspecified vulnerability in portable OpenSSH before 4.4, when running on some platforms, allows
  remote attackers to determine the validity of usernames via unknown vectors involving a GSSAPI
  "authentication abort."

- **[CVE-2006-5051](https://app.opencve.io/cve/CVE-2006-5051)** (2025-04-09) — CVSS: **8.1 High** —
  Signal handler race condition in OpenSSH before 4.4 allows remote attackers to cause a denial of
  service (crash), and possibly execute arbitrary code if GSSAPI authentication is enabled, via
  unspecified vectors that lead to a double-free.

- **[CVE-2006-4925](https://app.opencve.io/cve/CVE-2006-4925)** (2025-04-09) — CVSS: **N/A** —
  packet.c in ssh in OpenSSH allows remote attackers to cause a denial of service (crash) by sending
  an invalid protocol sequence with USERAUTH_SUCCESS before NEWKEYS, which causes newkeys[mode] to
  be NULL.

- **[CVE-2006-4924](https://app.opencve.io/cve/CVE-2006-4924)** (2025-04-09) — CVSS: **N/A** — sshd
  in OpenSSH before 4.4, when using the version 1 SSH protocol, allows remote attackers to cause a
  denial of service (CPU consumption) via an SSH packet that contains duplicate blocks.

- **[CVE-2006-0225](https://app.opencve.io/cve/CVE-2006-0225)** (2025-04-03) — CVSS: **N/A** — scp
  in OpenSSH 4.2p1 allows attackers to execute arbitrary commands via filenames that contain shell
  metacharacters or spaces, which are expanded twice.

- **[CVE-2005-2798](https://app.opencve.io/cve/CVE-2005-2798)** (2025-04-03) — CVSS: **N/A** — sshd
  in OpenSSH before 4.2, when GSSAPIDelegateCredentials is enabled, allows GSSAPI credentials to be
  delegated to clients who log in using non-GSSAPI methods.

- **[CVE-2005-2666](https://app.opencve.io/cve/CVE-2005-2666)** (2025-04-03) — CVSS: **N/A** — SSH,
  as implemented in OpenSSH before 4.0, stores hostnames, IP addresses, and keys in plaintext in the
  known_hosts file, which makes it easier for an attacker to generate a list of additional targets.

- **[CVE-2004-2069](https://app.opencve.io/cve/CVE-2004-2069)** (2025-04-03) — CVSS: **N/A** —
  sshd.c in OpenSSH 3.6.1p2 and 3.7.1p2, when using privilege separation, does not properly signal
  the non-privileged process when a session has been terminated after exceeding the LoginGraceTime
  setting, allowing DoS.

- **[CVE-2004-1653](https://app.opencve.io/cve/CVE-2004-1653)** (2025-04-03) — CVSS: **N/A** — The
  default configuration of OpenSSH allows forwarding TCP connections to the localhost, which could
  be used to connect to services that are only accessible from the localhost.

- **[CVE-2004-0175](https://app.opencve.io/cve/CVE-2004-0175)** (2025-04-03) — CVSS: **N/A** —
  Directory traversal vulnerability in scp for OpenSSH before 3.4p1 allows remote malicious servers
  to overwrite arbitrary files.

- **[CVE-2003-1562](https://app.opencve.io/cve/CVE-2003-1562)** (2025-04-03) — CVSS: **N/A** — sshd
  in OpenSSH 3.6.1p2 and earlier, when PermitRootLogin is disabled and using PAM
  keyboard-interactive authentication, does not insert a delay after a root login attempt with the
  correct password, enabling timing attacks.

- **[CVE-2003-0787](https://app.opencve.io/cve/CVE-2003-0787)** (2025-04-03) — CVSS: **N/A** — The
  PAM conversation function in OpenSSH 3.7.1 and 3.7.1p1 interprets an array of structures as an
  array of pointers, which allows attackers to modify the stack and possibly gain privileges.

- **[CVE-2003-0786](https://app.opencve.io/cve/CVE-2003-0786)** (2025-04-03) — CVSS: **N/A** — The
  SSH1 PAM challenge response authentication in OpenSSH 3.7.1 and 3.7.1p1, when Privilege Separation
  is disabled, does not check the result of the authentication attempt, allowing remote attackers to
  gain privileges.

- **[CVE-2003-0695](https://app.opencve.io/cve/CVE-2003-0695)** (2025-04-03) — CVSS: **N/A** —
  Multiple "buffer management errors" in OpenSSH before 3.7.1 may allow attackers to cause a denial
  of service or execute arbitrary code using (1) buffer_init in buffer.c, (2) buffer_free in
  buffer.c, or (3) a separate function in channels.c.

- **[CVE-2003-0693](https://app.opencve.io/cve/CVE-2003-0693)** (2025-04-03) — CVSS: **N/A** — A
  "buffer management error" in buffer_append_space of buffer.c for OpenSSH before 3.7 may allow
  remote attackers to execute arbitrary code by causing an incorrect amount of memory to be freed
  and corrupting the heap.

- **[CVE-2003-0682](https://app.opencve.io/cve/CVE-2003-0682)** (2025-04-03) — CVSS: **N/A** —
  "Memory bugs" in OpenSSH 3.7.1 and earlier, with unknown impact, a different set of
  vulnerabilities than CVE-2003-0693 and CVE-2003-0695.

- **[CVE-2003-0386](https://app.opencve.io/cve/CVE-2003-0386)** (2025-04-03) — CVSS: **N/A** —
  OpenSSH 3.6.1 and earlier, when restricting host access by numeric IP addresses and with
  VerifyReverseMapping disabled, allows remote attackers to bypass "from=" and "user@host" address
  restrictions.

- **[CVE-2003-0190](https://app.opencve.io/cve/CVE-2003-0190)** (2025-04-03) — CVSS: **N/A** —
  OpenSSH-portable 3.6.1p1 and earlier with PAM support enabled immediately sends an error message
  when a user does not exist, which allows remote attackers to determine valid usernames via a
  timing attack.

- **[CVE-2002-0640](https://app.opencve.io/cve/CVE-2002-0640)** (2025-04-03) — CVSS: **N/A** —
  Buffer overflow in sshd in OpenSSH 2.3.1 through 3.3 may allow remote attackers to execute
  arbitrary code via a large number of responses during challenge response authentication when using
  PAM.

- **[CVE-2002-0639](https://app.opencve.io/cve/CVE-2002-0639)** (2025-04-03) — CVSS: **9.8
  Critical** — Integer overflow in sshd in OpenSSH 2.9.9 through 3.3 allows remote attackers to
  execute arbitrary code during challenge response authentication.

- **[CVE-2002-0575](https://app.opencve.io/cve/CVE-2002-0575)** (2025-04-03) — CVSS: **N/A** —
  Buffer overflow in OpenSSH before 2.9.9 and 3.x before 3.2.1, with Kerberos/AFS support and
  KerberosTgtPassing or AFSTokenPassing enabled, allows remote and local authenticated users to gain
  privileges.

- **[CVE-2002-0083](https://app.opencve.io/cve/CVE-2002-0083)** (2025-04-03) — CVSS: **9.8
  Critical** — Off-by-one error in the channel code of OpenSSH 2.0 through 3.0.2 allows local users
  or remote malicious servers to gain privileges.

- **[CVE-2001-1585](https://app.opencve.io/cve/CVE-2001-1585)** (2025-04-03) — CVSS: **N/A** — SSH
  protocol 2 public key authentication in the development snapshot of OpenSSH 2.3.1 does not perform
  a challenge-response step to ensure that the client has the proper private key, allowing
  authentication bypass.

- **[CVE-2001-1507](https://app.opencve.io/cve/CVE-2001-1507)** (2025-04-03) — CVSS: **N/A** —
  OpenSSH before 3.0.1 with Kerberos V enabled does not properly authenticate users, which could
  allow remote attackers to login unchallenged.

- **[CVE-2001-1459](https://app.opencve.io/cve/CVE-2001-1459)** (2025-04-03) — CVSS: **N/A** —
  OpenSSH 2.9 and earlier does not initiate a Pluggable Authentication Module (PAM) session if
  commands are executed with no pty, which allows local users to bypass resource limits (rlimits)
  set in pam.d.

- **[CVE-2001-1382](https://app.opencve.io/cve/CVE-2001-1382)** (2025-04-03) — CVSS: **N/A** — The
  "echo simulation" traffic analysis countermeasure in OpenSSH before 2.9.9p2 sends an additional
  echo packet after the password and carriage return is entered, allowing attackers to detect the
  countermeasure.

- **[CVE-2001-1380](https://app.opencve.io/cve/CVE-2001-1380)** (2025-04-03) — CVSS: **N/A** —
  OpenSSH before 2.9.9, while using keypairs and multiple keys of different types, may not properly
  handle the "from" option associated with a key, allowing remote attackers to login from
  unauthorized IP addresses.

- **[CVE-2001-1029](https://app.opencve.io/cve/CVE-2001-1029)** (2025-04-03) — CVSS: **N/A** —
  libutil in OpenSSH on FreeBSD 4.4 and earlier does not drop privileges before verifying the
  capabilities for reading the copyright and welcome files, allowing local users to read arbitrary
  files.

- **[CVE-2001-0872](https://app.opencve.io/cve/CVE-2001-0872)** (2025-04-03) — CVSS: **N/A** —
  OpenSSH 3.0.1 and earlier with UseLogin enabled does not properly cleanse critical environment
  variables such as LD_PRELOAD, which allows local users to gain root privileges.

- **[CVE-2001-0816](https://app.opencve.io/cve/CVE-2001-0816)** (2025-04-03) — CVSS: **N/A** —
  OpenSSH before 2.9.9, when running sftp using sftp-server and using restricted keypairs, allows
  remote authenticated users to bypass authorized_keys2 command= restrictions using sftp commands.

- **[CVE-2001-0572](https://app.opencve.io/cve/CVE-2001-0572)** (2025-04-03) — CVSS: **N/A** — The
  SSH protocols 1 and 2 (aka SSH-2) as implemented in OpenSSH and other packages have various
  weaknesses which can allow a remote attacker to obtain information via sniffing: password lengths,
  auth type, authorized_keys count, command lengths.

- **[CVE-2001-0529](https://app.opencve.io/cve/CVE-2001-0529)** (2025-04-03) — CVSS: **N/A** —
  OpenSSH version 2.9 and earlier, with X forwarding enabled, allows a local attacker to delete any
  file named 'cookies' via a symlink attack.

- **[CVE-2001-0361](https://app.opencve.io/cve/CVE-2001-0361)** (2025-04-03) — CVSS: **N/A** —
  Implementations of SSH version 1.5, including OpenSSH up to version 2.3.0, allow a remote attacker
  to decrypt and/or alter traffic via a "Bleichenbacher attack" on PKCS#1 version 1.5.

- **[CVE-2001-0144](https://app.opencve.io/cve/CVE-2001-0144)** (2025-04-03) — CVSS: **N/A** — CORE
  SDI SSH1 CRC-32 compensation attack detector allows remote attackers to execute arbitrary commands
  on an SSH server or client via an integer overflow.

- **[CVE-2000-1169](https://app.opencve.io/cve/CVE-2000-1169)** (2025-04-03) — CVSS: **N/A** —
  OpenSSH SSH client before 2.3.0 does not properly disable X11 or agent forwarding, which could
  allow a malicious SSH server to gain access to the X11 display and sniff X11 events.

- **[CVE-2000-0999](https://app.opencve.io/cve/CVE-2000-0999)** (2025-04-03) — CVSS: **N/A** —
  Format string vulnerabilities in OpenBSD ssh program allow attackers to gain root privileges.

- **[CVE-2000-0525](https://app.opencve.io/cve/CVE-2000-0525)** (2025-04-03) — CVSS: **N/A** —
  OpenSSH does not properly drop privileges when the UseLogin option is enabled, which allows local
  users to execute arbitrary commands by providing the command to the ssh daemon.

- **[CVE-2000-0217](https://app.opencve.io/cve/CVE-2000-0217)** (2025-04-03) — CVSS: **N/A** — The
  default configuration of SSH allows X forwarding, which could allow a remote attacker to control a
  client's X sessions via a malicious xauth program.

- **[CVE-2000-0143](https://app.opencve.io/cve/CVE-2000-0143)** (2025-04-03) — CVSS: **N/A** — The
  SSH protocol server sshd allows local users without shell access to redirect a TCP connection
  through a service that uses the standard system password database for authentication, such as POP
  or FTP.

- **[CVE-1999-1010](https://app.opencve.io/cve/CVE-1999-1010)** (2025-04-03) — CVSS: **N/A** — An
  SSH 1.2.27 server allows a client to use the "none" cipher, even if it is not allowed by the
  server policy.
