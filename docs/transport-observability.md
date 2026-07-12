# Transport observability API

The transport observability API exposes live client-side transport data. It is intentionally process-agnostic: collectors can correlate `transportId` from `/connections` with `/transports`, then filter connections by process name or routing metadata.

## Snapshot endpoint

`GET /transports` returns the currently active observed transports:

```json
{
  "sequence": 42,
  "time": "2026-07-12T12:00:00Z",
  "transports": []
}
```

Use a WebSocket upgrade on the same endpoint for periodic snapshots. The optional `interval` query parameter is expressed in milliseconds, defaults to `1000`, and has a minimum of `100`.

Each TUIC snapshot includes:

- identity: transport ID, adapter name, protocol, local and remote addresses, creation time, active stream count, reconnect count
- path quality: minimum, latest and smoothed RTT, RTT variation, sent and received bytes and packets
- reliability: monotonic lost bytes and packets, loss event count, and cumulative PTO count
- congestion: congestion window and bytes in flight
- application pressure: total writes, writes taking at least 50 ms, total/max/last write duration, and last write time

## Event endpoint

`GET /transports/events` requires a WebSocket upgrade and emits:

- `transport_created`
- `transport_closed`
- `transport_reconnected`
- `packet_loss`
- `pto`
- `cwnd_collapse`
- `heartbeat`

Events have monotonically increasing sequence numbers. A gap indicates that a slow consumer missed events and should reconcile from `/transports`. A `transport_closed` event contains the final transport snapshot so collectors do not lose the last counters between polling intervals.

## Connection correlation

Observed TUIC entries in `GET /connections` additionally contain:

```json
{
  "transportId": "4b50e9ab-76de-4d65-9a31-727d1cd90836",
  "transportStats": {
    "writeCount": 10,
    "writeBlockedCount": 1,
    "writeDurationTotalMicros": 81000,
    "maxWriteDurationMicros": 61000,
    "lastWriteDurationMicros": 2000,
    "lastWriteAtUnixMs": 1783857600000
  }
}
```

Connections and protocols without transport telemetry keep their existing response shape because both fields use `omitempty`.
