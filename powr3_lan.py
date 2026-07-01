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
import os, sys, json, time, hashlib, base64, threading
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

class Listener:
    def __init__(self, client):
        self.client = client
        self.last_seq = None

    def _handle(self, zc, type_, name):
        info = zc.get_service_info(type_, name, timeout=2000)
        if not info:
            return
        props = {}
        for k, v in (info.properties or {}).items():
            try:
                props[k.decode()] = v.decode() if isinstance(v, bytes) else v
            except Exception:
                pass
        if props.get("id") != DEVICE_ID:
            return
        seq = props.get("seq")
        if seq and seq == self.last_seq:
            return
        self.last_seq = seq
        try:
            params = decrypt(props) if props.get("encrypt") in ("true", True) else {}
        except Exception as e:
            log("decrypt failed:", e)
            return
        self.publish(params)

    def publish(self, p):
        out = {}
        if "power" in p:   out["power"] = float(p["power"])       # W
        if "voltage" in p: out["voltage"] = float(p["voltage"])   # V
        if "current" in p: out["current"] = float(p["current"])   # A
        if "switch" in p:  out["switch"] = 1 if p["switch"] == "on" else 0
        for k, v in out.items():
            self.client.publish(f"{PREFIX}/{k}", str(v), qos=0, retain=True)
        if out:
            log("published", out)

    # zeroconf callbacks
    def add_service(self, zc, type_, name):    self._handle(zc, type_, name)
    def update_service(self, zc, type_, name): self._handle(zc, type_, name)
    def remove_service(self, zc, type_, name): pass

def main():
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
    ServiceBrowser(zc, "_ewelink._tcp.local.", Listener(client))
    try:
        while True:
            time.sleep(3600)
    finally:
        zc.close()

if __name__ == "__main__":
    main()
