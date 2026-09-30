# Discussion of Pubky service delegation

Users need to delegate hosting while keeping control of their identity.  This
document compares three ways to authorize a server's TLS key, shows how each
handles key rotation, and proposes a small first implementation.  The designs
are proposals, not claims of current client or browser support.

The recommendation is to start with explicit TLSA keys in option B. Option C
adds independent control of routing when that separation is needed.  Revocation
through signed Mainline DHT updates is treated as mostly solved in
practice. Browser integration remains a separate design task.

Our [first principles](./first-principles.md) take precedence over [web
compatibility goals](./design-principles.md). See the [terminology
guide](./delegation-terminology.md) for short definitions.

## The problem

Alice wants to publish a website under her public key. She wants to keep the
private key offline, use a hosting provider, and change providers without
changing her identity or URLs. Her provider wants to replace servers and rotate
TLS keys without asking every user to sign an update.

The [delegation requirements](./delegation-motivation.md) call for separate operational
keys, clear permission limits, and the ability to replace a provider without its
cooperation. Publishing a new signed DHT version provides the basis for
withdrawing an old delegation.

Four questions need separate answers:

| Question                               | Example answer                     |
|----------------------------------------|------------------------------------|
| Who owns the identity?                 | Alice controls key K.              |
| Where should the client connect?       | An IP address on TCP port 443.     |
| Which server key may serve the origin? | TLS key T, authorized by K.        |
| Who approved these response bytes?     | Content signer C, authorized by K. |

An origin is the scheme, hostname, and port that browsers use to separate
website permissions, such as `https://K:443`.

TLS protects a connection and authenticates its peer. Permission to serve a
website gives that peer substantial power: it can serve scripts and receive
requests and cookies for that origin. It does not prove that Alice approved each
response, or let the provider sign records as Alice.

In the examples, K is Alice's identity key, K2 is her operational key, S is the
provider's management key, and T is an online TLS key. These are placeholders,
not valid key labels. A PKARR packet holds DNS records signed by its owning
key. A client must verify those signatures; ordinary DNS answers alone do not
prove delegation. C denotes a separate content-signing key when response
authenticity is discussed.

## Technologies in brief

- **PKARR and the Mainline DHT.** PKARR publishes signed DNS records under
  public keys. The DHT is a distributed system for finding those records.  Pubky
  uses this for discovery; [pkdns](../README.md) exposes records through
  DNS. The proposed delegation rules build on that foundation.
- **HTTPS and SVCB records.** These DNS records describe service endpoints and
  connection settings. HTTPS is the web-specific form of SVCB. They help clients
  discover options such as HTTP/3 before connecting; they do not normally
  transfer certificate identity. See [MDN's overview][https-rr].
- **CNAME records.** A CNAME makes one DNS name an alias of another. DNS uses
  them to follow names to their records. They can also delegate publication of
  TLSA records, as described in [DANE's hosting guidance][dane-provider].
- **TLSA and DANE.** TLSA records bind services to certificates or keys.  DANE
  authenticates those bindings through DNSSEC, which signs DNS data.  [Exchange
  Online uses DANE][dane-email] for email delivery. The Pubky proposals instead
  authenticate bindings through PKARR signatures.
- **TLS certificates and raw public keys.** Ordinary browser HTTPS uses
  certificates backed by trusted certificate authorities, called WebPKI.
  Raw-key TLS sends a public key without that certificate chain and needs
  another way to trust it. [Rustls supports raw keys][rustls-features]; this
  alone does not supply Pubky delegation checks or browser support.
- **HTTP Message Signatures and Content-Digest.** The first signs selected parts
  of an HTTP message; the second carries a hash of its content.  [Cloudflare
  uses message signatures][bot-auth] to authenticate bot requests. The content
  proposal applies signatures to website responses and signs the digest too; a
  digest alone does not authenticate a sender.
- **Subresource Integrity or SRI.** A page supplies expected hashes for scripts
  or stylesheets, often loaded from another provider. The browser rejects
  mismatching files. A signed page could protect those expected hashes, but SRI
  does not authenticate the page itself.  See the [W3C examples][sri].

## What changes between the options

All three options preserve the original URL and HTTP origin. They differ in how
a verified delegation tells the client which TLS key to accept.

| Option | Who authorizes TLS keys?                             | Does a routing alias change that authority? |
|--------|------------------------------------------------------|---------------------------------------------|
| A      | The final delegate uses its own key for TLS.         | Yes, for Pubky HTTPS aliases.               |
| B      | The final Pubky delegate publishes a TLSA key set.   | Yes, for Pubky HTTPS aliases.               |
| C      | An independent TLSA chain selects the key publisher. | No.                                         |

Two record forms appear in the examples. `HTTPS 0 target` follows the target's
HTTPS records. `HTTPS 1 target` selects an endpoint and resolves its addresses;
it does not follow the target's HTTPS records. A target of `.` in the latter
form uses the record owner's addresses. The proposed security meaning of these
records depends on the option.

Keep three values separate when reading a connection example:

- **SNI** is sent by the client during TLS to select server configuration.
- **The server's key** is verified by the client against its authorization.
- **HTTP authority** identifies the requested website after TLS succeeds.

SNI does not prove identity or tell the server which key hashes the client
accepts. For `https://K/page`, HTTP authority remains K even if another name is
used for SNI. Standard HTTPS normally retains the original name for both
certificate validation and SNI; these Pubky profiles define their own
verification rules. See [RFC 9460 section 2.3][https-identity] and [section
9.4][https-sni].

## Option A Let HTTPS aliases choose the TLS identity

In option A, each signed alias can pass service authority to another key.  The
last delegate's key authenticates TLS.

```dns
; Signed by K
K.  300 IN HTTPS 0 K2.
; Signed by K2
K2. 300 IN HTTPS 0 S.
; Signed by S
S.  300 IN HTTPS 0 T.
; Signed by T
T.  300 IN HTTPS 1 . port=443
T.  300 IN A 203.0.113.10
```

For `https://K/page`, the client verifies K -> K2 -> S -> T, connects to the
address, and requires T's raw public key in TLS. It sends T as SNI and K as the
HTTP `Host`.

**Advantages.** One chain explains both delegation and server selection.  K2 can
change providers while K stays offline. S can rotate T or authorize two
delegates for failover without changing users' records.

**Costs and risks.** T is both an online TLS key and a PKARR signing key.
Stealing T therefore also permits publishing new records under T, including
further delegation while its parent still authorizes it. The proposal requires
raw-key TLS support and rejects X.509 certificates on Pubky branches. Raw keys
use explicit TLS negotiation, defined in [RFC
7250](https://www.rfc-editor.org/rfc/rfc7250.html#section-4).

This also gives familiar records a new security meaning. `HTTPS 0 T` transfers
authority, while `HTTPS 1 T` only uses T's addresses. Changing that number can
change who is trusted.

**Conflict with the first principles.** An alias to `host.example` switches this
design to ordinary domain certificates, called WebPKI. Even if K signed the
original delegation, later control of that domain and its certificates can
determine who serves K. A delegate can also introduce this dependency through
further delegation. K retains its private key, but service authentication now
depends on the domain system.

For example, after `K -> S -> host.example`, an attacker who gains control of
`host.example` and obtains a valid certificate could serve K without K or S
signing another update. To preserve the first principles, remove this transition
or require a separate authorization rooted in K for the actual TLS key. The TLSA
options provide that separation from WebPKI.

## Option B Let HTTPS aliases choose a TLSA publisher

Option B keeps the alias chain, but its final Pubky authority publishes the
accepted TLS keys explicitly.

```dns
; Signed by K
K.           300 IN HTTPS 0 K2.
; Signed by K2
K2.          300 IN HTTPS 0 S.
; Signed by S
S.           300 IN HTTPS 1 edge.example. port=443
_443._tcp.S. 300 IN TLSA 3 1 1 <hash-of-T-spki>
; Ordinary DNS
edge.example. 300 IN A 203.0.113.10
```

The hash is a placeholder. `3 1 1` selects direct server-key authorization using
SHA-256 over the complete DER-encoded SubjectPublicKeyInfo, which contains the
public key and its algorithm information. This expected hash is often called a
key pin. T needs no PKARR packet. The client accepts T in a raw-key handshake or
an X.509 certificate and checks proof of possession during TLS. The field
definitions come from [RFC 6698 section 2][tlsa-fields].

The client sends S as SNI and K as HTTP authority. Ordinary DNS can change the
destination address, but a certificate for `edge.example` alone is
insufficient. Its key must match the signed TLSA set.  DNS blocking can still
cause an outage. Avoiding that dependency requires another reachable route; a
key pin alone does not provide one.

**Advantages.** Online TLS keys cannot change the authorization records unless
they separately hold the publisher's signing key. Certificate renewal with the
same public key does not require a pin update. S can authorize multiple TLS keys
without making each one a Pubky identity.

**Costs and risks.** Routing and authorization remain linked: changing a Pubky
HTTPS alias changes whose TLSA records are trusted. This option also needs
separate records for each connection port and transport. Its certificate support
still requires a custom verifier; it does not make the design ordinary browser
HTTPS.

Multiple hashes form one accepted set. If S lists T1 and T2 for TCP port 443,
either key is accepted at either endpoint using that set. Publishing two
endpoints does not pair the first endpoint with the first key. Use distinct
service names when those policies must differ.

Ports also have separate meanings. If `https://K:8443/` delegates to S and the
endpoint uses TCP port 9443, the client checks `_9443._tcp.S`. The HTTP
authority remains `K:8443`; the connection port does not change the origin.

**Standards implication.** DANE uses authenticated TLSA records to verify TLS
peers. In its DANE-EE mode, certificate names and certificate expiry do not
determine authorization. Standard DANE obtains the binding's validity from
DNSSEC signatures. This proposal uses PKARR signatures and newer DHT versions to
update authorization instead. See [RFC 7671 section 5.1][dane-ee].

## Option C Separate routing from TLS authorization

Option C starts two lookups at the original name. HTTPS records select
destinations. CNAME records at TLSA names select who may publish accepted TLS
keys.

```dns
; Signed by K
K.              300 IN HTTPS 0 K2.
_443._tcp.K.    300 IN CNAME _443._tcp.K2.
; Signed by K2
K2.             300 IN HTTPS 0 S.
_443._tcp.K2.   300 IN CNAME _443._tcp.S.
; Signed by S
S.              300 IN HTTPS 1 edge.example. port=443
_443._tcp.S.    300 IN TLSA 3 1 1 <hash-of-T-spki>
```

As above, ordinary DNS supplies the address of `edge.example`. Both chains are
verified from K. Changing the HTTPS chain alone cannot authorize a new TLS
key. The client checks T against the resulting TLSA set, just as in option
B. Separating the lookup chains requires no new TLS key format.

**Advantages.** Routing and key authorization become distinct permissions.  For
example, K2 could direct HTTPS to a routing operator R while keeping the TLSA
delegation at S. A compromised R could misdirect or block connections, but could
not authorize its own TLS key. This limits damage only if R does not also
control the TLSA chain.

**Costs and risks.** More records and lookup rules are required. Migration may
need changes to both chains, and clients can observe different update times
across packets. A mismatch must cause a connection failure, never a switch to a
key trusted only by the routing chain. Using the same keys for both chains
separates record meaning, but does not isolate a stolen signing key.

The sketch still needs exact rules for ports, TCP versus HTTP/3's QUIC
transport, SNI, branching, limits, and caching. It must also decide whether
authorization can enter ordinary DNS. A conservative first version would keep
every authorization link in signed Pubky packets.

**Standards implication.** TLSA delegation through CNAME already has a
provider-hosting precedent in [RFC 7671 section 6][dane-provider]. However, the
requirement to start at the original hostname and follow only explicit TLSA-name
aliases is a Pubky restriction. Standard DANE can derive its TLSA base from a
DNSSEC-validated hostname CNAME chain.  See [RFC 7671 section 7][dane-cname].

## Key rotation

The following examples rotate the provider's online TLS key from T1 to T2. Its
management key S stays the same, so users do not need to change their
delegations. Both approaches allow a transition period, but they represent it
differently.

### Option A Rotate through separate alias branches

S can rotate from T1 to T2 by temporarily publishing two aliases. Each TLS key
has its own signed packet describing its endpoint:

```dns
; Signed by S during rotation
S.  300 IN HTTPS 0 T1.
S.  300 IN HTTPS 0 T2.

; Signed by T1
T1. 300 IN HTTPS 1 . port=443
T1. 300 IN A 203.0.113.10

; Signed by T2
T2. 300 IN HTTPS 1 . port=443
T2. 300 IN A 203.0.113.10
```

Under option A's proposed rules, each branch selects one TLS identity:

| Branch | SNI sent by the client | Key the server must present |
|---------|------------------------|-----------------------------|
| S -> T1 | T1 | T1 |
| S -> T2 | T2 | T2 |

If both branches use the same IP and port, the TLS terminator can select the key
using SNI. That requires support for multiple keys on the listener.
Alternatively, T1 and T2 can use separate endpoints, each serving one key.  Both
must serve the original HTTP authority K.

For a planned rotation:

1. Prepare the T2 endpoint and publish T2's signed records.
2. Publish both aliases in S's packet, keeping T1 available.
3. Allow for DHT propagation and cache refresh, and verify T2 works.
4. Publish a newer S packet that removes the alias to T1.
5. Allow cached delegations to refresh before shutting down T1.

Users keep their delegation to S and their original URLs. A client on the T1
branch must reject T2's key; it can use T2 only through the separately verified
T2 branch. Unlike a TLSA accepted-key set, the two aliases do not make both keys
acceptable within either individual branch.

If T1 is compromised, remove its alias promptly instead of retaining it for a
planned overlap.

### Options B and C Rotate within the TLSA key set

In both TLSA designs, S can authorize multiple TLS keys by publishing one TLSA
record for each key at the same name. These records are alternatives: the client
accepts the server's key if its SPKI hash matches any record in the verified
set.

```dns
; Signed by S; hashes are placeholders
_443._tcp.S. 300 IN TLSA 3 1 1 <hash-of-T1-spki>
_443._tcp.S. 300 IN TLSA 3 1 1 <hash-of-T2-spki>
```

This allows a planned rotation with overlapping authorization:

| Stage            | Published accepted keys | Key the HS presents |
|------------------|-------------------------|---------------------|
| Before rotation  | T1                      | T1                  |
| Prepare rotation | T1 and T2               | T1                  |
| Switch server    | T1 and T2               | T2                  |
| Finish rotation  | T2                      | T2                  |

Publish both hashes and allow for DHT propagation and client cache refresh
before switching the HS to T2. Otherwise a client still accepting only T1 will
reject the new key. Remove T1 after the server transition is complete.

The HS presents one key per handshake, selected by its configuration.  The
client does not send its accepted TLSA hashes to the HS. SNI can stay the same
throughout rotation; it need not identify T1 or T2. The overlap is in the
accepted key set, not a requirement to serve both keys at once.

If T1 is stolen, remove its authorization through a DHT update rather than
keeping it authorized for a routine rotation overlap.

With independent chains, publish the new TLS authorization before sending
clients to an endpoint that requires it. Test clients with old and new versions
of both chains. Never let a mismatch disable key verification.

### Connection reuse during changes

For every option, a client must stop starting requests on an old connection when
its authorization is no longer valid. A cached TLS session must not bypass the
new key policy. Options A and B address this and exclude early data and
cross-origin connection sharing initially.

## Revocation through DHT updates

For this discussion, revocation is mostly solved in practice: publish a newer
signed PKARR packet that removes or replaces the delegation. The old delegate's
cooperation is unnecessary. Mainline DHT nodes holding a newer version reject
older replacements. See [BEP 44 mutable items][bep44].

For example, K2 replaces S1 with S2 in its packet. Clients that resolve the
update stop trusting S1 through that link. If K2 is compromised, K removes K2
instead. The owner retains control through the parent key.

> Updates take effect as clients refresh. Cache lifetimes and DHT access affect
> that timing; the 300-second cache cap is a local refresh rule.  Refreshing
> parent records and invalidating affected connections are implementation
> details, not a separate revocation mechanism to design.

## Signed content adds a different guarantee

The signed-content approach lets K authorize a separate key C to sign
responses. It can accompany any of the service designs. Its purpose is to detect
content changes by a host that is otherwise authorized to serve K.

For example, Alice authorizes C to sign `/pages/`. C signs a response for `GET
https://K/pages/about.html`, covering the request location, response status,
content type, and body digest. A client verifies C's permission, checks the
signature, and recomputes the digest from the received content.  Changing the
body or serving it at another signed path fails verification.

The header formats come from [HTTP Message Signatures][http-signatures] and
[Content-Digest][digest]. The permission format and the policy that requires
signatures are proposed Pubky rules.

**Advantages.** Hosts can serve and copy signed files without gaining the
ability to change them undetected. K can remain offline while C publishes new
content. A signed list of paths and hashes is an alternative when Alice wants to
approve exact files rather than give C ongoing permission.  The host must not
hold C's private key if signatures are meant to protect against that host
changing content.

**Costs and limits.** A signature proves approval by the authorized signer, not
necessarily Alice's personal review. The host can still withhold content or
replay a response while it remains valid. Content signatures do not provide
confidentiality or replace TLS.

The client must know that signatures are required before accepting the
response. Otherwise the host can remove the signature headers. A verifier
downloaded only as JavaScript from that same untrusted host cannot provide an
independent starting point for trust.

Clients obtain the signature requirement and signer permissions from verified
DHT policy and refresh it as usual. Updated policy can revoke a signer. Response
expiry separately limits replay of content signed by a still-trusted key.

The proposed response coverage also needs a complete policy. Sign query
parameters when they affect content and `Location` for redirects. Decide how to
handle unsigned cookies, security headers, and other fields that change browser
behavior. A valid signature over HTML alone does not make all response behavior
trustworthy. RFC 9421 explains the risks of [unsigned components and
replay][signature-risks].

## Deployment and remaining design work

### Packet size limits

PKARR allows 1,000 bytes for the compressed DNS packet. Its signature,
timestamp, and public key add 104 bytes outside that budget. Each signer has its
own packet; all service names under that key share its space.

Measured with full key labels, one HTTPS delegation uses 132 DNS bytes.  Option
C's HTTPS alias and TLSA-name CNAME use 218 bytes. An HTTPS endpoint at
`edge.example` with two TLSA pins uses 202 bytes. These examples fit
comfortably, but many distinct services or keys can fill the packet.  Reserve
room for rotation and extra service parameters.

See [packet size and record capacity](./pkarr-packet-size.md) for the
measurements, signature overhead, and a small DHT boundary caveat.

### Failover needs both security and work limits

Options A and B explore all authorized alias branches and reject fallback to a
previous delegate after a failure. Those rules protect authority
boundaries. They also create an availability tradeoff: requiring complete
traversal before returning a plan lets a slow or excessively large branch
exhaust the shared budget even when another branch works.

For example, S authorizes H1 and H2. H1 returns a usable endpoint; H2 continues
through many aliases. Under options A and B, exhausting the overall traversal
budget discards the plan. Decide whether completeness is required, or whether a
fully verified candidate may be used while bounded background work
continues. This is a policy choice, not permission to use a partial proof.

### Browser compatibility needs its own design

Under standard HTTPS rules, changing DNS routing does not change the identity
TLS must authenticate. Therefore configuring a browser to use pkdns does not by
itself implement any of these delegation profiles.  This follows from the [HTTPS
identity rules][https-identity].

Possible integration paths should be evaluated separately:

| Path | Benefit | Cost or trust change |
|-----------------------|-----------------------------|---------------------------|
| Pubky-aware client | Verifies from K directly | Needs client support |
| Local verifying proxy | May retain browser UI | Needs setup and TLS trust |
| Remote web gateway | Uses ordinary browser HTTPS | Trusts gateway and domain |

A local proxy that terminates browser TLS would need explicit trust
configuration and would be trusted with traffic. It is not a DNS-only
solution. A gateway URL such as `https://gateway.example/K/` changes the browser
origin and puts the gateway between the browser and Pubky proofs.  These are
integration possibilities, not established capabilities of the proposed
profiles. Neither should become a mandatory discovery authority.

### Changing hosts does not move files

All three service designs let an owner publish a new destination without the old
provider signing approval. They do not recover files the provider withholds,
define data export, or make apps interpret data consistently.

For example, Alice can move from S1 to S2 under the same K, but S2 still needs a
copy of her files and relationship data in compatible formats.  Independent
copies, usable export and restore, and affordable hosting are part of practical
exit. Signed content helps verify a copy; it does not create one.

## Proposed starting point

Start with a small version of option B. It separates management keys from TLS
keys without adding a second delegation chain. This proposal narrows the initial
scope; it does not introduce a fourth authorization mechanism.  Choose option C
instead if independent routing authority is a requirement from the start.

### Initial scope

Support HTTPS on TCP port 443 first. Keep the URL and HTTP authority at K, use S
as SNI, and accept only TLS keys explicitly listed by S. Allow an X.509
certificate to carry the key, but authorize it through the TLSA pin.  Every
authorization link must lead back to K through verified signatures.  Ordinary
DNS may supply addresses, but cannot introduce trusted keys.

Use exact record names to scope delegation to the requested origin.  Delegating
`K` does not also delegate `app.K` or `_pubky.K`. Within that origin, management
delegation permits endpoint selection, TLS key selection, and further
delegation. Content signing needs separate authority.  Finer permissions would
need a later extension with an explicit format.

Keep management and TLS keys separate. K authorizes K2 to choose a provider; K2
selects S; S publishes the accepted TLS keys. T only handles TLS and has no
authority to publish management records as S.

### Benefits and costs

This uses the DHT's existing update mechanism and avoids a separate grant
renewal protocol. K and S can remain offline between changes that require new
signatures. Keeping signed packets available on the DHT still needs
republishing, which does not require giving the publisher those private
keys. BEP 44 describes [republishing stored items][bep44-republish].

The cost is TLSA publication and custom client verification, plus normal record
refresh and connection tracking. A native client can demonstrate the trust model
before browser integration is attempted.

### Decisions and validation

Before treating any option as a stable profile, resolve these questions:

1. **Permission boundaries.** Is service delegation intentionally broad, or must
   routing and TLS authorization belong to different operators?
2. **Exact connection rules.** Specify ports, transports, SNI, independent
   chains, connection reuse, and failure behavior with executable examples.
3. **Deployment.** Demonstrate one client verifying the complete chain and TLS
   handshake. Assess browser integration separately from DNS support.
4. **Content and exit.** Decide which content needs signatures and how users
   obtain and restore independent copies without their old host's help.

Validate the first implementation with a stolen TLS key that cannot change
management records, rotation with mixed caches, parent delegation updates, and a
failed alias branch. Measure packet size and lookup cost.  For option C, also
show that a routing-only change cannot authorize a new TLS key. If content
signatures are added, test a host that strips them.

This direction preserves identity under K and keeps authorization rooted in
signatures. It can retain DHT discovery and replaceable hosts. Practical exit
still requires usable data export and restore; browser convenience must not
weaken those requirements.

[https-identity]: https://www.rfc-editor.org/rfc/rfc9460.html#section-2.3
[https-sni]: https://www.rfc-editor.org/rfc/rfc9460.html#section-9.4
[dane-ee]: https://www.rfc-editor.org/rfc/rfc7671.html#section-5.1
[dane-provider]: https://www.rfc-editor.org/rfc/rfc7671.html#section-6
[dane-cname]: https://www.rfc-editor.org/rfc/rfc7671.html#section-7
[http-signatures]: https://www.rfc-editor.org/rfc/rfc9421.html
[signature-risks]: https://www.rfc-editor.org/rfc/rfc9421.html#section-7.2
[digest]: https://www.rfc-editor.org/rfc/rfc9530.html#section-2
[tlsa-fields]: https://www.rfc-editor.org/rfc/rfc6698.html#section-2
[https-rr]: https://developer.mozilla.org/en-US/docs/Glossary/HTTPS_RR [dane-email]: https://learn.microsoft.com/en-us/purview/how-smtp-dane-works [rustls-features]: https://rustls.dev/docs/rustls/manual/_04_features/index.html [bot-auth]: https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth
[sri]: https://www.w3.org/TR/sri/#use-cases-examples
[bep44]: https://www.bittorrent.org/beps/bep_0044.html#mutable-items
[bep44-republish]: https://www.bittorrent.org/beps/bep_0044.html#expiration
