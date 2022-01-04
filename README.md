# DNSSEQ: PowerDNS with FALCON Signature Scheme

PowerDNS-based proof-of-concept implementation of DNSSEC using the post-quantum FALCON signature scheme.

## Usage

This repository can be used to provide either a local test setup, serve as a test setup on the Internet, or both.

### Local Test Setup

To test the PoC locally, this repository contains an authoritative DNS server *and* a DNS recursor supporting FALCON.
Run `setup.py` to create an initial setup. The authoritative server wil be configured with the following zones under
`.example.` and be available at `localhost:5301` (tcp/udp):

- `classic.example.`: signed with classical DNSSEC
- `falcon.example.`: signed with FALCON

Both zones contain A and AAAA records pointing to localhost (caution, if you are not querying directly to the recursor,
such answers may be filtered by additional DNS appliances that you use for rebind attack protection), as well as a TXT
record stating the purpose of the zones.

The recursor, available at `localhost:5302` will be equipped with an appropriate trust anchor for `.example`, so that
queries will validated and answered with authenticated data (AD) bit:

```
$ dig TXT @localhost -p 5302 falcon.example. +dnssec
[...]

;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 55224
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

[...]

;; ANSWER SECTION:
falcon.example.		3590	IN	TXT	"FALCON DNSSEQ PoC; details: github.com/nils-wisiol/dns-falcon"
falcon.example.		3590	IN	RRSIG	TXT 17 2 3600 20220113000000 20211223000000 948 falcon.example. OejPqJXFparczRg6+gLVPn1IVgayZOk8N+t/H92ViSuR7JMEkHmHK7lM Z2tXQbWT7jL25pSDiDvWRj4/X8kvbUxGAJUaFN/rM99N2VWnDGzoxylk R54flObVvNjghxm+j3lb3ox4u3x3rOqEb5m9WrkfpeVbldK6susSn7fp q2if9MUNgvfOfrjQCCz1E2cifBw9Dev2SUQJ5NDRvfT4bcZIvnL47FZm F4xH6BcXhv7SqDQd9E6oYtrJ6Q1IzHR7VRq0VW6R2Bo3BDaKL9KV03yR LXNUxr6Z442uVa/bOk4lKvcnymTLZ0LfwRxcElsFWiw2/5Q3r4vACtJI Vz922ZJQ4JhXpRs80UrapYOD6ame78GtRbfoEe6qrNQnUpeoybvIx4vZ zN+tE6lUewTDpolFJUSxJlpkmbAvUATxWXJwDrftFpZhTimjYL1b2hYt WDXbjOM7EciluBzUMj3M0qFx/dTd/ETqccf56Cl93WKPPiDGSYebR2I3 Vy5pPpVGWEx23gApbMHg9Joiz5QxdKhFp1BZsp93eODTIiizdfXDrl+m gp8lORM1Z5SIkzPR22rIB6GuNl4f/Xk9Tsms8a2nerTMimKzNFb5e3sP jo1pGKZuSQsAj5hmNIkqXHgvX+M8u087tIy2gsNT2sJ3qR79PGRLoreD mS6YhXIMWuA/uOXm/l1mJk0uSw4AiyRFpT/d8kQVP47mkBUraSMzvAzb kvWzXMS6e9/2ZUhSo1tV+Zx+Nx9/4lkgYoHe0rebqUazj2jOVnM4NCSb qa8tR5zA6yk61p02QZJS2LCdchfywxlUQcaK0VNW/n768GyeJkFU59Zy e9cqpmIxrzKQsSmMqbxVYJQLkGLtsrQR36/A

[...]
```

### Internet Test Setup

**Note: Not yet completely implemented!**

To use the Internet Test Setup, a public IP address for the authoritative name server is required, and a name needs to
be delegated to this server. Given a deSEC.io user name and access token, this repository can take care of delegation
itself. To activate the Internet Test Setup, add the following variables to the `.env` file:

```
PUBLIC_IP4_ADDRESSES=10.1.1.1,10.2.2.2
PUBLIC_IP6_ADDRESSES=fe80::1337,fe80::4711
DESEC_USER=someuser@example.com
DESEC_TOKEN=123456789abcedfghij
DESEC_DOMAIN=mytest.dedyn.io
```

At least one value for `PUBLIC_IP4_ADDRESSES` or `PUBLIC_IP6_ADDRESSES` is required. Note that if only supplied an IP4
or IP6 address, the server will not be reachable from the other IP space, which may break testing for some clients.

If you do not have a deSEC account, `DESEC_USER` and `DESEC_TOKEN` can be obtained free of charge from desec.io.
Otherwise, use your existing account.

`DESEC_DOMAIN` defines under which name the test setup will be reachable. If this domain does not exist on your deSEC
account, upon startup, it will be created (if your token permissions allow). If the domain is a name under `dedyn.io`,
no further action is necessary. If the domain name is something else, please follow deSEC's instructions to delegate
it to deSEC.

After everything is set up correctly, the following zones will be created under `example.$DESEC_DOMAIN`:

- `classic.example.$DESEC_DOMAIN`: signed with classical DNSSEC
- `falcon.example.$DESEC_DOMAIN`: signed with FALCON

## Tools

To debug queries against the recursor, set up the query trace:

```
docker-compose exec recursor rec_control trace-regex '.*example.*'
```

To export all zone data from the authoritative DNS server, use:

```
docker-compose exec auth bash -c 'echo ".dump" | sqlite3 /var/lib/powerdns/pdns.sqlite3'
```

## Acknowledgements

This work is based on the pdns fork of @gothremote, who worked on this for this Master's thesis.
