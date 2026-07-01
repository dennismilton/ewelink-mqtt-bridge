# maracaibo-sonoff

Sonoff **POWR3** (shore-power inlet meter) → MQTT → SignalK, over eWeLink **LAN**
(offline; no cloud, no eWeLink token at runtime).

The POWR3 advertises its state over mDNS (`_ewelink._tcp`) with params AES-encrypted
using the device key. This bridge listens, decrypts, and publishes shore-power
readings to MQTT. `signalk-mqtt-sensors` then maps them into SignalK
(`electrical.ac.shore.*`), and the dashboard reads SignalK only.

## Data
| MQTT topic | SignalK path | unit |
|---|---|---|
| `maracaibo/sonoff/powr3/power`   | `electrical.ac.shore.power`   | W |
| `maracaibo/sonoff/powr3/voltage` | `electrical.ac.shore.voltage` | V |
| `maracaibo/sonoff/powr3/current` | `electrical.ac.shore.current` | A |
| `maracaibo/sonoff/powr3/switch`  | `electrical.ac.shore.state`   | 0/1 |

## Deploy (build on Mac, pull on Pi — same model as vfc)
```
./build.sh                       # buildx arm64 -> dmtamsen/privhub:maracaibo-sonoff
# on the Pi: /home/pi/docker/sonoff/{docker-compose.yml,.env}  (.env from .env.example)
./deploy.sh                      # ssh pull + up
```

`network_mode: host` is required so mDNS multicast reaches the POWR3 on the boat LAN.

## Secrets
`DEVICE_KEY` (eWeLink devicekey) is secret — lives only in `.env` on the Pi, never
committed (`.gitignore`). Fetched once from the eWeLink cloud device list.
