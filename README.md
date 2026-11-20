# nat-detect

NAT behavior detection per RFC 4787 / RFC 5780, implemented in Python, Go, Rust, and Node.js. Tests UDP mapping and filtering against a STUN server. No dependencies.

All four programs do the same thing and print the same report, so use whichever language you prefer.

| File | Language | Requires |
|---|---|---|
| `nat_detect.py` | Python | Python 3.6+ |
| `nat_detect.go` | Go | Go 1.18+ |
| `nat_detect.rs` | Rust | Rust 1.65+ |
| `nat_detect.js` | Node.js | Node.js 16+ |

Each program is a single file that uses only its language's standard library.

## What it detects

RFC 4787 does not define NAT "types" such as full cone or symmetric. It defines two independent behaviors, and the old names are combinations of them. These programs measure both behaviors using the test procedure from RFC 5780.

| Behavior | Question it answers | Possible results |
|---|---|---|
| Mapping | Does the NAT reuse the same public address and port when you contact different destinations from one local socket? | Endpoint-Independent, Address-Dependent, Address and Port-Dependent |
| Filtering | Which remote hosts may send packets back through an existing mapping? | Endpoint-Independent, Address-Dependent, Address and Port-Dependent |

## Usage

The default server is `stunserver2025.stunprotocol.org:3478`. Pass a different one if you prefer (see [Server requirements](#server-requirements)).

**Python**

```sh
python3 nat_detect.py
python3 nat_detect.py stun.example.com:3478
```

**Go**

```sh
go run nat_detect.go
go run nat_detect.go -server stun.example.com:3478
```

**Rust**

```sh
rustc -O nat_detect.rs
./nat_detect
./nat_detect stun.example.com:3478
```

**Node.js**

```sh
node nat_detect.js
node nat_detect.js stun.example.com:3478
```

### Example output

This is an illustrative example. Addresses are from documentation ranges.

```
Server:  203.0.113.10:3478
Mapped:  198.51.100.7:40123
Mapping behavior:   Endpoint-Independent
Filtering behavior: Address and Port-Dependent
Legacy name (approximate): port-restricted cone
```

If the mapped address equals your local address, the programs also print a note that no NAT was detected.

## Reading the result

The "legacy name" line is a rough translation to the older RFC 3489 terms. It is approximate, so rely on the two behavior lines.

| Mapping | Filtering | Legacy name |
|---|---|---|
| Endpoint-Independent | Endpoint-Independent | Full cone |
| Endpoint-Independent | Address-Dependent | Restricted cone |
| Endpoint-Independent | Address and Port-Dependent | Port-restricted cone |
| Address-Dependent or Address and Port-Dependent | any | Symmetric |

Endpoint-Independent mapping is the property that matters most for peer-to-peer connections, because it lets a peer learn an address that other hosts can also reach. Non-Endpoint-Independent mapping usually means direct connections need a relay (TURN).

## Server requirements

The STUN server must support RFC 5780, which adds the `OTHER-ADDRESS` attribute and the `CHANGE-REQUEST` flags. Most public STUN servers, including Google's, do not. If the server does not send `OTHER-ADDRESS`, the programs stop with an error.

A server that supports RFC 5780 needs two different IP addresses and two ports, so that it can reply from an address and port different from the ones you contacted. If no public server works for you, run your own, for example with coturn on a host that has two public IPs.

## How it works

Let the server's primary address be `A1:P1` and its alternate address (from `OTHER-ADDRESS`) be `A2:P2`.

**Mapping test** (one local socket for every probe)

1. Send a Binding Request to `A1:P1` and record the mapped address `M1`.
2. Send one to `A2:P1` and record `M2`. If `M2 == M1`, mapping is Endpoint-Independent.
3. Otherwise send one to `A2:P2` and record `M3`. If `M3 == M2`, mapping is Address-Dependent. If not, it is Address and Port-Dependent.

**Filtering test** (a fresh socket, so the mapping test's packets to `A2` cannot have opened the filter)

1. Send a normal Binding Request to `A1:P1` to create a mapping.
2. Send a request with `CHANGE-REQUEST` set to change both IP and port. If a reply arrives from `A2:P2`, filtering is Endpoint-Independent.
3. Otherwise set only the change-port flag. If a reply arrives from `A1:P2`, filtering is Address-Dependent.
4. If neither reply arrives, filtering is Address and Port-Dependent.

Each probe is retried, with a one-second wait per attempt.

## Limitations

- IPv4 and UDP only. TCP behavior (RFC 5382) is not tested.
- RFC 4787 also covers port preservation, mapping lifetime, and hairpinning. These are not tested.
- A missing reply in the filtering test is treated as "blocked", but it can also be packet loss or a firewall. Rerun the program if the filtering result looks surprising.
- A server that ignores `CHANGE-REQUEST` makes the filtering result read as Address and Port-Dependent regardless of your NAT.
- A VPN, proxy, or carrier-grade NAT in the path changes what is measured. You are testing the whole path to the server, not only your home router.

## Status

All four programs were tested against a local fake STUN server that implements the RFC 5780 attributes on loopback. That covers message building, parsing, and the test logic, but only for the "no NAT" case. They have not been verified against a real NAT or against the public server named above.
