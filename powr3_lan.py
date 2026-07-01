#!/usr/bin/env python3
"""Sonoff POWR3 -> MQTT bridge over eWeLink LAN (offline; no cloud, no eWeLink token).

The POWR3 advertises its state over mDNS (_ewelink._tcp) with the params AES-encrypted
using the device key (fetched once from the cloud). We listen, decrypt, and publish the
shore-power readings to MQTT, where signalk-mqtt-sensors maps them into SignalK
(electrical.ac.shore.*). Same read-only, offline-first model as the other bridges.

Env:
  DEVICE_ID       eWeLink deviceid (e.g. 10013c5fde)
  DEVICE_KEY      eWeLink devicekey (SECRET) — from the cloud API once
  MQTT_HOST       default 127.0.0.1
  MQTT_PORT       default 1883
  TOPIC_PREFIX    default maracaibo/sonoff/powr3
"""
import os, sys, json, time, hashlib, base64, urllib.request
from Crypto.Cipher import AES
from zeroconf import Zeroconf, ServiceBrowser
import paho.mqtt.client as mqtt

DEVICE_ID = os.environ.get("DEVICE_ID", "").strip()
DEVICE_KEY = os.environ.get("DEVICE_KEY", "").strip()
MQTT_HOST = os.environ.get("MQTT_HOST", "127.0.0.1")
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
PREFIX = os.environ.get("TOPIC_PREFIX", "maracaibo/sonoff/powr3").rstrip("/")
if not DEVICE_ID or not DEVICE_KEY:
    sys.exit("DEVICE_ID and DEVICE_KEY are required")

log = lambda *a: print(*a, flush=True)

def decrypt(props):
    """Decrypt eWeLink LAN mDNS TXT params. props: dict of str->str."""
    key = hashlib.md5(DEVICE_KEY.encode()).digest()          # 16-byte AES key
    iv = base64.b64decode(props["iv"])
    data = "".join(props[k] for k in ("data1", "data2", "data3", "data4") if props.get(k))
    ct = base64.b64decode(data)
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    pt = pt[: -pt[-1]]                                        # strip PKCS7 padding
    return json.loads(pt)

def encrypt(params):
    """AES-128-CBC encrypt a params dict with the device key (eWeLink LAN control)."""
    key = hashlib.md5(DEVICE_KEY.encode()).digest()
    iv = os.urandom(16)
    data = json.dumps(params).encode()
    pad = 16 - (len(data) % 16)
    data += bytes([pad]) * pad
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(data)
    return base64.b64encode(iv).decode(), base64.b64encode(ct).decode()


def _props(info):
    out = {}
    for k, v in (info.properties or {}).items():
        try:
            out[k.decode()] = v.decode() if isinstance(v, bytes) else v
        except Exception:
            pass
    return out

class Listener:
    def __init__(self, client, zc):
        self.client = client
        self.zc = zc
        self.name = None          # our device's mDNS instance name, once discovered
        self.addr = None          # device IP + port (for LAN control)
        self.port = None

    def _is_ours(self, info):
        if not info or _props(info).get("id") != DEVICE_ID:
            return False
        try:
            addrs = info.parsed_addresses()
            if addrs: self.addr = addrs[0]; self.port = info.port
        except Exception:
            pass
        return True

    # LAN control: POST an AES-encrypted {switch:on/off} to the device (offline).
    def control(self, on):
        if not self.addr:
            log("control: device address not yet discovered"); return False
        iv_b64, data_b64 = encrypt({"switch": "on" if on else "off"})
        body = json.dumps({
            "sequence": str(int(time.time() * 1000)), "deviceid": DEVICE_ID,
            "selfApikey": "123", "iv": iv_b64, "encrypt": True, "data": data_b64,
        }).encode()
        url = f"http://{self.addr}:{self.port}/zeroconf/switch"
        try:
            req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
            resp = json.loads(urllib.request.urlopen(req, timeout=5).read())
            log(f"control switch={'on' if on else 'off'} -> {resp}")
            self.poll()                                   # publish the confirmed state back
            return resp.get("error") == 0
        except Exception as e:
            log("control failed:", e); return False

    # eWeLink pushes are unreliable; we poll (re-query) instead. But still grab the
    # instance name from discovery so poll() knows what to re-query.
    def add_service(self, zc, type_, name):    self._maybe(zc, type_, name)
    def update_service(self, zc, type_, name): self._maybe(zc, type_, name)
    def remove_service(self, zc, type_, name): pass
    def _maybe(self, zc, type_, name):
        info = zc.get_service_info(type_, name, timeout=2000)
        if self._is_ours(info):
            self.name = name
            self._publish(info)

    # Active poll: re-query the service (fresh mDNS query) and re-publish so SignalK
    # stays live even when the device sends no unsolicited updates.
    def poll(self):
        if not self.name:
            return
        info = self.zc.get_service_info("_ewelink._tcp.local.", self.name, timeout=2000)
        if self._is_ours(info):
            self._publish(info)

    def _publish(self, info):
        props = _props(info)
        try:
            p = decrypt(props) if props.get("encrypt") in ("true", True) else {}
        except Exception as e:
            log("decrypt failed:", e); return
        out = {}
        if "power" in p:   out["power"] = float(p["power"])       # W
        if "voltage" in p: out["voltage"] = float(p["voltage"])   # V
        if "current" in p: out["current"] = float(p["current"])   # A
        if "switch" in p:  out["switch"] = 1 if p["switch"] == "on" else 0
        for k, v in out.items():
            self.client.publish(f"{PREFIX}/{k}", str(v), qos=0, retain=True)
        if out:
            log("published", out)

def main():
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1)
    except Exception:
        client = mqtt.Client()
    client.will_set(f"{PREFIX}/online", "0", retain=True)
    while True:
        try:
            client.connect(MQTT_HOST, MQTT_PORT, 60)
            break
        except Exception as e:
            log("mqtt connect retry:", e); time.sleep(5)
    client.loop_start()
    client.publish(f"{PREFIX}/online", "1", retain=True)
    log(f"listening for POWR3 {DEVICE_ID} over LAN -> {PREFIX}/* on {MQTT_HOST}:{MQTT_PORT}")

    zc = Zeroconf()
    listener = Listener(client, zc)
    ServiceBrowser(zc, "_ewelink._tcp.local.", listener)

    # control: MQTT <prefix>/cmd/switch = on/off -> LAN control the POWR3 relay
    def on_message(cl, ud, msg):
        cmd = msg.payload.decode(errors="ignore").strip().lower()
        log(f"cmd/switch = {cmd}")
        listener.control(cmd in ("on", "1", "true"))
    client.on_message = on_message
    client.subscribe(f"{PREFIX}/cmd/switch")

    try:
        while True:
            time.sleep(15)          # poll cadence — keeps electrical.ac.shore.* live
            listener.poll()
            client.publish(f"{PREFIX}/online", "1", retain=True)
    finally:
        zc.close()

if __name__ == "__main__":
    main()
