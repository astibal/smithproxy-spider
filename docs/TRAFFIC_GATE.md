# Traffic gate design note

Spider request handling starts non-blocking. A future forensic hold is an
explicit domain feature, not a mutex accidentally shared by the UI and HTTP
server.

```text
traffic event -> matcher -> gate decision -> pass | hold | reject
                              |
                              +-> bounded hold queue + deadline
```

## Intended scopes

- `global`: hold all matching traffic;
- `new-sessions`: prevent admission of new sessions while existing ones run;
- `session`: hold one connection by stable Smithproxy session ID;
- `direction`: originator, responder, or both;
- `policy`: match a policy/profile/tag without stopping unrelated traffic;
- `content`: hold only payload callbacks that require a forensic decision.

Scopes compose by intersection. The most restrictive matching gate wins.

## Required safety properties

- every hold has a deadline and explicit timeout action;
- queue byte/count limits are independent of UI state;
- disconnecting the UI cannot create an infinite hold;
- gate ownership is represented by an opaque lease ID;
- release/cancel is idempotent and ownership checked;
- audit records distinguish automatic timeout from analyst decisions;
- `fail-open`, `fail-closed`, and `drop` are explicit per gate;
- a global gate may intentionally stop unrelated traffic, but only when it was
  requested as `global`, never because a shared process lock is contended.

No gate is implemented in the first connectivity milestone. Until the protocol
contains lease IDs and deadlines, Spider always returns immediately.
