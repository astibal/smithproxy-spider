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

Default endpoint: `http://127.0.0.1:18081/webhook`.
