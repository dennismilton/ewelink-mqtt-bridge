# Changelog

Versions are retrospective tags over the bridge's actual evolution; the repo
went public at 1.2.0. Dates are commit dates.

## 1.4.0 — 2026-08-12 · live power (the uiActive nudge)

- **Streaming power/V/A.** Measured first: the POWR3 reports power lazily on
  its own cadence to BOTH transports (LAN record and cloud were byte-identical;
  a real 17 W load step moved neither for 2.5 min) — the old "LAN freezes,
  cloud is reliable" rationale blamed the wrong layer and is corrected. The
  vendor app only looks live because it asks the device to STREAM for 120 s at
  a time; the bridge now sends that `uiActive` nudge over the push WebSocket
  every `UIACTIVE_S` (default 110 s), renewed before expiry. Result: watt-level
  updates every few seconds instead of one frozen reading.
- Cloud pushes for a LAN-owned **single** device now pass through (power/V/A
  exist only on the cloud stream); the publisher still withholds the switch,
  so the routes cannot fight over a topic. LAN-owned multis drop pushes as
  before.

## 1.3.0 — 2026-08-12 · the rewrite

- **One publisher, one router.** The LAN and cloud publishing paths had drifted
  into two near-copies; every route (LAN mDNS, cloud poll, cloud push) now
  lands in a single `publish_state`, and every command routes through a single
  `Bridge.control`. 669 → 590 lines with behaviour preserved: topics, env vars
  and the auth flow are unchanged.
- **Fixed: discovery can now UNDISCOVER.** A device that left the network
  stayed LAN-owned forever — state frozen, cloud never resuming. mDNS goodbye
  or 4 consecutive LAN poll misses now hand the device back to the cloud.
- **Fixed: honest `online` for cloud devices.** The flag lives on `itemData`,
  not `params`; it was hardcoded true, so an unplugged device stayed "healthy"
  forever. It now flows from the poll and from WS `sysmsg` events, with an
  offline stamp that preserves last-known channel states.
- WS heartbeat pings no longer drift behind a blocking recv.

## 1.2.0 — 2026-08-12 · cloud push, public release

- **Subscribe, don't poll**: the eWeLink WebSocket (dispatch/app + userOnline
  with the same OAuth token) delivers every state change instantly — including
  eWeLink-app taps and physical buttons. The REST poll is demoted to
  reconciliation. Reconnect with exponential backoff (cap 5 min); without
  `websocket-client` the bridge runs poll-only.
- Renamed `maracaibo-sonoff` → **ewelink-mqtt-bridge**, MIT license, made
  public. History audited: no secret was ever tracked.

## 1.1.0 — 2026-08-12 · the device registry

- **One contract for every device**: if mDNS has discovered a device on the
  bridge's network, LAN owns state and control; otherwise the cloud does. No
  per-operation fallback — a LAN failure on a discovered device is a logged
  failure, so problems surface instead of hiding behind the cloud.
- Second device supported: a 4-channel switch (uiid 4) via `EWE4_*` env —
  state as one retained numeric-JSON topic, control via `cmd/ch1..4`.
- The cloud poll yields any state LAN owns, so two sources never fight over a
  retained topic.

## 1.0.0 — 2026-07 · POWR3 hybrid bridge

- LAN path: mDNS discovery, AES-128-CBC (MD5(devicekey)) decrypt of state,
  encrypted `/zeroconf/switch` control — fully offline.
- Cloud path: power/voltage/current polled from the v2 API (the POWR3 freezes
  those over LAN); retained readings cleared after 10 failed polls so
  dashboards never show frozen numbers as live.
- OAuth2.0 auth with persisted auto-refreshing tokens; manual token fallback.
- Numbers published as JSON so downstream consumers can average them (string
  payloads broke InfluxDB means — learned the hard way).
