# Sift

`sx-siftd` is the local payload inspection and decision process. It accepts
the same webhook handshake and `SXBN001` `connection-content` requests as
`spider-server`, keeps per-session bidirectional state, and returns a verdict.

This first extraction deliberately lives beside Spider while Smithproxy keeps
its legacy in-process signature engine. The compiled signature-pack runtime and
the useful state model from the legacy engine will move here incrementally.

```text
Smithproxy -- second webhook/SXBN001 --> sx-siftd
Spider server -- replay/SXBN001 ------> sx-siftd
```

Runtime counters are available as JSON from `GET /api/stats`. The existing
timing section reports both matcher-only `inspection_us` and content request
`engine_delay_us` (request decoded through verdict produced). Network and broker
latency is deliberately not included. Timing medians use a bounded rolling
window of the latest 4096 samples; lifetime minimum, maximum and average remain
available alongside it.
`/api/status` endpoint returns the same snapshot, while `/api/health` remains
available for deployment health checks. The snapshot includes flow lifecycle,
directional traffic, payload sizes, per-signature matches, decisions, uptime,
and inspection latency. End-to-end round-trip latency requires telemetry from
Smithproxy and its communication broker and is therefore reported as pending.

Default endpoint: `http://127.0.0.1:18081/webhook`.
