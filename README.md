# maracaibo-sonoff

Bridge between a Sonoff **POWR3** shore-power energy meter and MQTT, for the vessel
**Maracaibo**'s SignalK dashboard. Publishes shore-power readings to MQTT, where
`signalk-mqtt-sensors` maps them into SignalK (`electrical.ac.shore.*`) and the
dashboard reads SignalK only.

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

- **Cloud path (poll, ~30s)** — eWeLink/CoolKit v2 cloud API, using a token supplied
  in `EWELINK_TOKEN`. Used for **power / voltage / current** only.
  **Why:** the POWR3 does **not** reliably report live power/voltage/current over the
  eWeLink LAN protocol — Sonoff's firmware only pushes those over LAN on large
  threshold changes, so LAN readings go stale/frozen. The cloud poll is the reliable
  source for those three values.

If `EWELINK_TOKEN` is unset, power/voltage/current are simply not published; switch
state and relay control still work fully offline over LAN.

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
| `maracaibo/sonoff/powr3/cmd/switch` | `on` / `off` (also `1`/`true`) | LAN-control the POWR3 relay |

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
| `EWELINK_TOKEN`   | no  | — | CoolKit v2 access token — **secret**; enables cloud power poll |
| `EWELINK_APPID`   | no  | `K0OCDSvIaBWdEaU4zxlKEwk26kmshoXK` | CoolKit appid |
| `EWELINK_REGION`  | no  | `eu` | CoolKit API region |
| `CLOUD_INTERVAL`  | no  | `30` | Cloud poll interval (seconds) |

The bridge exits if `DEVICE_ID` or `DEVICE_KEY` is missing. LAN switch state is polled
every 15s.

## Secrets

`DEVICE_KEY` and `EWELINK_TOKEN` are secrets — they live only in `.env` on the Pi and
are never committed (`.env` is `.gitignore`d). Do not put them in this repo.

## Deploy (build on Mac, pull on Pi — same model as vfc)

```
./build.sh                       # buildx arm64 -> dmtamsen/privhub:maracaibo-sonoff (push)
# on the Pi: /home/pi/docker/sonoff/{docker-compose.yml,.env}  (.env from .env.example)
./deploy.sh                      # ssh pull + up on pi@192.168.8.9
```

`network_mode: host` is required so mDNS multicast reaches the POWR3 on the boat LAN.
