# SOCKS5 authentication producer proposal

Status: the public value facade, independently reproduced transport corpus and
dormant Spider-side decision adapter are implemented and fully covered. No live
producer exists, so `socks5_auth` registration remains fail-closed. This
document does not authorize changes in Smithproxy or another project.

## Goal

Expose mitmproxy-compatible SOCKS5 username/password authentication decisions
without moving SOCKS framing, policy or connection ownership into Spider.
Smithproxy remains the SOCKS5 server. Spider receives one bounded credential
observation, runs one synchronous addon hook in the stable generation worker,
and returns one boolean decision before Smithproxy sends the RFC 1929 reply.

## Verified behavior

The checked-in mitmproxy 12.3.1 black-box corpus exercises real SOCKS5 method
negotiation and username/password authentication. It proves that:

- the server selects method `0x02` when username/password auth is configured;
- `data.valid` enters the hook with the preliminary built-in policy result;
- an addon may change `false` to `true`, producing RFC 1929 success;
- an addon may change `true` to `false`, producing RFC 1929 failure;
- the callback receives the live client connection descriptor;
- non-UTF-8 credential bytes are exposed losslessly as escaped text such as
  `\\xff`, not decoded with replacement characters.

The hook is therefore an override boundary, not merely a notification and not
a write-only result field.

## Producer envelope

After Smithproxy has parsed a complete RFC 1929 authentication request and
evaluated its configured policy, it would publish:

```json
{
  "socks5_auth": {
    "version": 1,
    "event": "authenticate",
    "username": "alice",
    "password": "secret",
    "valid": true
  }
}
```

The callback already owns the live `Client` descriptor established at native
connection setup. Spider does not reconstruct it from the envelope.

Credential bytes are converted with the same reversible escaped-text contract
used by the public compatibility facade. Because RFC 1929 limits each field to
255 bytes, the escaped representation is bounded to 1,020 characters. Raw
control characters and ambiguous decoding are rejected; arbitrary bytes remain
representable through escapes.

## Decision boundary

Spider creates `Socks5AuthData(client_conn, username, password, valid)`, runs
`socks5_auth(data)`, and returns:

```json
{
  "action": "authenticate",
  "valid": true
}
```

Smithproxy awaits this result before sending `0x01 0x00` success or `0x01 0x01`
failure. Only an actual boolean is accepted. A callback timeout, worker failure,
malformed result or generation retirement follows the configured strict policy
and fails authentication; it must never silently turn a rejected client into an
accepted one.

Changing `username`, `password` or `client_conn` inside the addon does not alter
the parsed wire request or native connection identity. Those fields are public
observations; `valid` is the sole decision. The adapter preserves object identity
for the duration of the callback and does not retain credentials afterwards.

## Security and logging

Credentials are secret material:

- no username or password is logged by default;
- callback diagnostics identify only workspace, deployment and connection;
- credential values are not retained in flow history or status endpoints;
- length and type validation occurs before addon dispatch;
- the result is accepted only from the owning generation and callback;
- queued or late results are rejected after connection teardown.

The envelope is applicable only after method `0x02` and a complete RFC 1929
request. It does not synthesize authentication for no-auth SOCKS5, HTTP proxy
authentication or an incomplete handshake.

## Required implementation work

1. **Spider adapter**
   - implemented: validate the versioned bounded credential observation;
   - implemented: reuse the truthful native client descriptor;
   - implemented: dispatch one synchronous `socks5_auth` hook;
   - implemented: accept only the final boolean without retaining credentials;
   - pending producer integration: map native method-2 auth into the envelope
     and apply the returned decision before the RFC 1929 reply.
2. **Smithproxy producer** — separate cross-project approval required
   - publish the preliminary configured-policy result and escaped credentials;
   - await the addon decision before the RFC 1929 reply;
   - treat timeout, malformed output and unavailable worker according to the
     explicit strict authentication policy;
   - retain all SOCKS framing and connection ownership.
3. **Native boundary**
   - use a generic callback-local boolean decision if the current result
     envelope cannot express authentication cleanly;
   - propose that additive helper before adding SOCKS-specific native glue.

## Acceptance gates

- exact reproduction of the checked-in allow-override and reject-override wire
  corpus;
- all 0–255 credential byte values and maximum RFC 1929 lengths;
- empty username/password behavior observed from the reference;
- live client descriptor identity and connection teardown races;
- boolean type enforcement and immutable native connection ownership;
- addon exception, timeout, worker crash and generation retirement;
- multiple simultaneous clients sharing addon state without credential leaks;
- malformed method negotiation and incomplete auth requests never reaching the
  hook;
- packaged-worker, native boundary and end-to-end wire tests;
- proof that no-auth SOCKS5 and HTTP proxy auth are not cross-classified.

Until the producer and wire gates pass, the loader must continue to reject a
live `socks5_auth` callback.
