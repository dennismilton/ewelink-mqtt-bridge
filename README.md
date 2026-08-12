# maracaibo-sonoff

Bridge between **eWeLink/Sonoff devices** and MQTT — LAN-first, cloud-fallback —
built for the vessel *Maracaibo*'s SignalK dashboard and generic enough for any
MQTT consumer (SignalK via `signalk-mqtt-sensors`, Home Assistant, Node-RED…).

Devices carried today: a **POWR3** shore-power energy meter (relay + power/V/A)
and an optional **4-channel switch** (uiid 4). Adding another eWeLink device is
an env entry, not a fork.

## Routing — discovery decides

Every device follows one contract: **if mDNS has discovered the device on this
bridge's network, LAN owns it** — state comes off the encrypted mDNS records and
control is an AES-encrypted POST straight to the device, no internet in the
path. A device the bridge has *not* discovered (different network, mDNS outage)
routes to the eWeLink cloud API for both. There is no per-operation fallback: a
LAN failure on a discovered device is a logged failure, so problems surface
instead of hiding behind the cloud. The cloud poll yields any state LAN owns,
so two sources never fight over one retained topic.

Move a device onto the bridge's network and it becomes offline-capable the
moment mDNS sees it — no configuration change.

## Architecture — hybrid LAN + cloud

The bridge uses **two paths** because the POWR3 firmware splits its data unevenly
between the local and cloud APIs:

- **LAN path (offline)** — eWeLink LAN protocol over mDNS (`_ewelink._tcp`), params
  AES-128-CBC encrypted with `key = MD5(devicekey)`. Used for:
  - **Switch state** — the POWR3 advertises its relay state reliably over LAN. The
    bridge listens/polls, decrypts, and publishes it.
  - **Relay control** — subscribe to an MQTT command topic, AES-encrypt a
    `{switch: on/off}` payload, and `POST` it to the device's
    `/zeroconf/switch` endpoint (device IP + port discovered via mDNS). Works with
    no internet.

- **Cloud path (poll, ~60s)** — eWeLink/CoolKit v2 cloud API. Used for
  **power / voltage / current** only.
  **Why:** the POWR3 does **not** reliably report live power/voltage/current over the
  eWeLink LAN protocol — Sonoff's firmware only pushes those over LAN on large
  threshold changes, so LAN readings go stale/frozen. The cloud poll is the reliable
  source for those three values.

If no cloud credentials are configured, power/voltage/current are simply not
published; switch state and relay control still work fully offline over LAN.

## Cloud auth — OAuth2.0 (preferred) or manual token (fallback)

**OAuth2.0** (eWeLink app-dev license from [dev.ewelink.cc](https://dev.ewelink.cc)):
set `EWELINK_APPID` + `EWELINK_APPSECRET` + `EWELINK_REDIRECT_URL` (must exactly match
the redirect URL registered with the app), then run the one-time login:

```
python powr3_lan.py auth        # or: docker compose run --rm sonoff-powr3 python powr3_lan.py auth
```

It prints an eWeLink login URL; open it in a browser, log in, and the local callback
server (port from `EWELINK_REDIRECT_URL`) captures the authorization code — note the
code is only valid **30 seconds**, so the exchange happens immediately. Tokens land in
`EWELINK_TOKEN_FILE` (compose mounts `./data:/data`) and the bridge **auto-refreshes**
them (access token 30 days, refresh token 60 days), plus retries a refresh on any
401/402 from the API. If the auth machine isn't the Pi, copy the token file over to
`./data/` afterwards.

**Manual token fallback:** a hand-made access token in `EWELINK_TOKEN` (issued under
`EWELINK_TOKEN_APPID`) is used whenever OAuth tokens are absent or refresh fails. It
is *not* auto-refreshed — it dies when it expires.

## MQTT topics

Published (out):

| MQTT topic | source | SignalK path | unit |
|---|---|---|---|
| `maracaibo/sonoff/powr3/power`   | cloud | `electrical.ac.shore.power`   | W |
| `maracaibo/sonoff/powr3/voltage` | cloud | `electrical.ac.shore.voltage` | V |
| `maracaibo/sonoff/powr3/current` | cloud | `electrical.ac.shore.current` | A |
| `maracaibo/sonoff/powr3/switch`  | LAN + cloud | `electrical.ac.shore.state` | 0/1 |
| `maracaibo/sonoff/powr3/online`  | — | (bridge liveness / LWT) | 0/1 |

Subscribed (in):

| MQTT topic | payload | action |
|---|---|---|
| `maracaibo/sonoff/powr3/cmd/switch` | `on` / `off` (also `1`/`true`) | control the POWR3 relay (LAN when discovered, else cloud) |
| `maracaibo/sonoff/ewe4/cmd/ch1..4` | `on` / `off` | control a 4CH channel (LAN when discovered, else cloud) |

4CH state publishes as one retained JSON topic `<EWE4_PREFIX>/json` —
`{"online":1,"ch1":0,...}` — numeric values so downstream consumers can chart
them (string payloads cannot be averaged; learned the hard way).

All published topics are retained. `online` is `1` while running and `0` via the MQTT
last-will. The topic prefix is configurable (`TOPIC_PREFIX`).

## Configuration (env vars)

Set these in `.env` on the Pi (copy from [`.env.example`](.env.example)).

| Var | Required | Default | Purpose |
|---|---|---|---|
| `DEVICE_ID`       | yes | — | eWeLink device id |
| `DEVICE_KEY`      | yes | — | eWeLink device key — **secret**, LAN AES key = `MD5(DEVICE_KEY)` |
| `MQTT_HOST`       | no  | `127.0.0.1` | MQTT broker host |
| `MQTT_PORT`       | no  | `1883` | MQTT broker port |
| `TOPIC_PREFIX`    | no  | `maracaibo/sonoff/powr3` | MQTT topic prefix |
| `EWELINK_APPID`   | no  | — | OAuth2.0 app id (dev.ewelink.cc) — enables OAuth cloud auth |
| `EWELINK_APPSECRET` | no | — | OAuth2.0 app secret — **secret** |
| `EWELINK_REDIRECT_URL` | no | `http://127.0.0.1:8000/callback` | Redirect URL registered with the OAuth app |
| `EWELINK_TOKEN_FILE` | no | `/data/ewelink_tokens.json` | Where OAuth tokens persist (compose mounts `./data:/data`) |
| `EWELINK_TOKEN`   | no  | — | Manual access token — **secret**; legacy fallback, not auto-refreshed |
| `EWELINK_TOKEN_APPID` | no | `EWELINK_APPID`, else `K0OCDSvIaBWdEaU4zxlKEwk26kmshoXK` | Appid the manual token was issued under |
| `EWELINK_REGION`  | no  | `eu` | CoolKit API region (OAuth stores the real region in the token file) |
| `CLOUD_INTERVAL`  | no  | `60` | Cloud poll interval (seconds) |
| `CLOUD_MAX_FAILS` | no  | `10` | Consecutive failed cloud polls before the retained `power`/`voltage`/`current` topics are cleared (so dashboards don't show frozen readings as live; switch stays — LAN owns it). Publishing resumes automatically when the cloud comes back. |

The bridge exits if `DEVICE_ID` or `DEVICE_KEY` is missing. LAN switch state is polled
every 15s.

## Secrets

`DEVICE_KEY`, `EWELINK_APPSECRET`, `EWELINK_TOKEN` and the token file under `data/`
are secrets — they live only on the Pi and are never committed (`.env` and `data/`
are `.gitignore`d). Do not put them in this repo.

## Deploy (build on Mac, pull on Pi — same model as vfc)

```
./build.sh                       # buildx arm64 -> dmtamsen/privhub:maracaibo-sonoff (push)
# on the Pi: /home/pi/docker/sonoff/{docker-compose.yml,.env}  (.env from .env.example)
./deploy.sh                      # ssh pull + up on pi@192.168.8.9
```

`network_mode: host` is required so mDNS multicast reaches the POWR3 on the boat LAN.

## Why there is a `json` topic as well as the per-key ones

`maracaibo/sonoff/powr3/{power,voltage,current,switch}` carry a **bare** payload
(`134.97`). `signalk-mqtt-sensors` has no numeric conversion for sensor type
`other` — it passes the payload straight through — so those values reached
SignalK as **strings**. They logged to InfluxDB happily and then could not be
read back: the History API answers `unsupported mean iterator type:
*query.stringInterruptIterator`, because a string cannot be averaged. The tank
topics never had this problem precisely because they arrive as JSON, where the
extracted value is already a number.

So `cloud_poll` also publishes `maracaibo/sonoff/powr3/json`
(`{"power":134.97,"voltage":233.37,"current":0.78,"switch":1}`, retained) and
SignalK maps `electrical.ac.shore.*` from **that** topic with `json_path`. The
per-key topics are unchanged and still published, so anything else reading them
keeps working — this adds a typed path, it does not replace the old one.

## Second device: the 4CH

| var | required | default | meaning |
|---|---|---|---|
| `EWE4_ID` | no | — | eWeLink deviceid of a 4-channel switch (uiid 4) |
| `EWE4_KEY` | no | — | its devicekey — **secret**, needed for LAN control |
| `EWE4_PREFIX` | no | `maracaibo/sonoff/ewe4` | MQTT topic prefix |

The devicekey comes from the cloud device list once (`/v2/device/thing`) and is
then a permanent local credential — LAN control works with the WAN down.

## License

MIT.
