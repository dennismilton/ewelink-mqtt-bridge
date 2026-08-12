#!/usr/bin/env python3
"""eWeLink/Sonoff <-> MQTT bridge. LAN-first, cloud-fallback, push not poll.

THE CONTRACT (one paragraph): every device in DEVICES follows the same rule —
if mDNS has discovered it on THIS network, LAN owns it: state comes off the
encrypted mDNS records, control is an AES-encrypted POST to the device, and a
LAN failure is a logged failure, never a silent cloud retry. A device the
bridge has NOT discovered routes to the eWeLink cloud for both. Discovery can
UNDISCOVER (mDNS goodbye, or repeated LAN poll misses), at which point the
cloud resumes seamlessly. State is PUSHED on both routes — mDNS updates on LAN,
the eWeLink WebSocket on cloud — with a slow REST poll kept only to reconcile
missed pushes and to fetch POWR3 power/V/A, which nothing streams. All state
leaves through ONE publisher to retained MQTT topics, so downstream (SignalK,
dashboards, Influx) never knows or cares which route delivered.

Config is env-driven; see .env.example and README.md. `python powr3_lan.py auth`
runs the one-time OAuth login.
"""
import os, sys, json, time, hashlib, hmac, base64, secrets, threading
import urllib.request, urllib.parse
from Crypto.Cipher import AES
from zeroconf import Zeroconf, ServiceBrowser
import paho.mqtt.client as mqtt
try:
    import websocket                      # cloud push (websocket-client)
except ImportError:                       # bridge still works poll-only without it
    websocket = None

env = lambda k, d="": os.environ.get(k, d).strip()

MQTT_HOST = env("MQTT_HOST", "127.0.0.1")
MQTT_PORT = int(env("MQTT_PORT", "1883"))
CLOUD_APPID = env("EWELINK_APPID")
CLOUD_APPSECRET = env("EWELINK_APPSECRET")
REDIRECT_URL = env("EWELINK_REDIRECT_URL", "http://127.0.0.1:8000/callback")
TOKEN_FILE = env("EWELINK_TOKEN_FILE", "/data/ewelink_tokens.json")
MANUAL_TOKEN = env("EWELINK_TOKEN")       # legacy fallback, not auto-refreshed
MANUAL_APPID = env("EWELINK_TOKEN_APPID") or CLOUD_APPID or "K0OCDSvIaBWdEaU4zxlKEwk26kmshoXK"
CLOUD_REGION = env("EWELINK_REGION", "eu")
CLOUD_INTERVAL = int(env("CLOUD_INTERVAL", "60"))
CLOUD_MAX_FAILS = int(env("CLOUD_MAX_FAILS", "10"))
LAN_POLL_S = 15                           # LAN re-query cadence
LAN_MISS_LIMIT = 4                        # poll misses before we UNDISCOVER

# ── the device registry ──────────────────────────────────────────────────────
# kind 'single': one relay, {switch:on/off}, state topics <prefix>/<key>,
#                power/V/A from cloud only (LAN readings freeze — firmware).
# kind 'multi':  N relays, {switches:[{switch,outlet}]}, ONE numeric-JSON state
#                topic <prefix>/json (strings cannot be averaged downstream).
DEVICES = {}
if env("DEVICE_ID"):
    DEVICES[env("DEVICE_ID")] = {
        "id": env("DEVICE_ID"), "key": env("DEVICE_KEY"),
        "prefix": env("TOPIC_PREFIX", "maracaibo/sonoff/powr3").rstrip("/"),
        "kind": "single"}
if env("EWE4_ID"):
    DEVICES[env("EWE4_ID")] = {
        "id": env("EWE4_ID"), "key": env("EWE4_KEY"),
        "prefix": env("EWE4_PREFIX", "maracaibo/sonoff/ewe4").rstrip("/"),
        "kind": "multi", "channels": 4}

log = lambda *a: print(*a, flush=True)

# ── cloud: HTTP + auth ───────────────────────────────────────────────────────

def _api_base(region):
    return f"https://{region}-apia.coolkit.{'cn' if region == 'cn' else 'cc'}"

def _cloud_req(url, body=None, bearer=None, appid=None):
    """Signed (Sign, when no bearer) or Bearer request. Returns decoded JSON."""
    data = json.dumps(body).encode() if body is not None else None
    auth = (f"Bearer {bearer}" if bearer else "Sign " + base64.b64encode(
        hmac.new(CLOUD_APPSECRET.encode(), data or b"", hashlib.sha256).digest()).decode())
    req = urllib.request.Request(url, data=data, headers={
        "Content-Type": "application/json", "X-CK-Appid": appid or CLOUD_APPID,
        "X-CK-Nonce": secrets.token_hex(4), "Authorization": auth})
    return json.load(urllib.request.urlopen(req, timeout=10))

class CloudAuth:
    """OAuth token store with auto-refresh; manual EWELINK_TOKEN as fallback.
    Token file: {at, rt, atExpiredTime, rtExpiredTime, region} (ms epoch)."""
    REFRESH_MARGIN_MS = 24 * 3600 * 1000

    def __init__(self):
        self.tok = None
        try:
            with open(TOKEN_FILE) as f:
                self.tok = json.load(f)
            log(f"loaded OAuth tokens from {TOKEN_FILE}")
        except FileNotFoundError:
            pass
        except Exception as e:
            log(f"token file {TOKEN_FILE} unreadable:", e)

    def save(self):
        tmp = TOKEN_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.tok, f)
        os.replace(tmp, TOKEN_FILE)

    @property
    def region(self):
        return (self.tok or {}).get("region") or CLOUD_REGION

    def refresh(self):
        if not (self.tok and self.tok.get("rt") and CLOUD_APPID and CLOUD_APPSECRET):
            return False
        try:
            d = _cloud_req(f"{_api_base(self.region)}/v2/user/refresh", body={"rt": self.tok["rt"]})
        except Exception as e:
            log("token refresh failed:", e); return False
        if d.get("error"):
            log("token refresh error", d.get("error"), d.get("msg", "")); return False
        now = int(time.time() * 1000)
        self.tok.update({"at": d["data"]["at"], "rt": d["data"]["rt"],
                         "atExpiredTime": now + 30 * 86400 * 1000,
                         "rtExpiredTime": now + 60 * 86400 * 1000})
        self.save()
        log("OAuth tokens refreshed")
        return True

    def credentials(self):
        """(access_token, appid, region) or None. Refreshes when near expiry."""
        if self.tok and self.tok.get("at"):
            now = int(time.time() * 1000)
            if now >= self.tok.get("atExpiredTime", 0) - self.REFRESH_MARGIN_MS:
                if not self.refresh() and now >= self.tok.get("atExpiredTime", 0):
                    log("OAuth access token expired and refresh failed")
                    return self._manual()
            return (self.tok["at"], CLOUD_APPID, self.region)
        return self._manual()

    def _manual(self):
        return (MANUAL_TOKEN, MANUAL_APPID, CLOUD_REGION) if MANUAL_TOKEN else None

    def invalidate(self):
        """Force a refresh after a 401/402 from a data call."""
        if self.tok:
            self.tok["atExpiredTime"] = 0
            return self.refresh()
        return False

# ── LAN crypto (eWeLink zeroconf protocol) ───────────────────────────────────

def _aes(key_str):
    return hashlib.md5(key_str.encode()).digest()

def decrypt(props, devkey):
    iv = base64.b64decode(props["iv"])
    ct = base64.b64decode("".join(props.get(f"data{i}") or "" for i in (1, 2, 3, 4)))
    pt = AES.new(_aes(devkey), AES.MODE_CBC, iv).decrypt(ct)
    return json.loads(pt[: -pt[-1]])                       # strip PKCS7

def encrypt(params, devkey):
    iv = os.urandom(16)
    data = json.dumps(params).encode()
    data += bytes([16 - len(data) % 16]) * (16 - len(data) % 16)
    ct = AES.new(_aes(devkey), AES.MODE_CBC, iv).encrypt(data)
    return base64.b64encode(iv).decode(), base64.b64encode(ct).decode()

def _props(info):
    out = {}
    for k, v in (info.properties or {}).items():
        try:
            out[k.decode()] = v.decode() if isinstance(v, bytes) else v
        except Exception:
            pass
    return out

# ── the bridge ───────────────────────────────────────────────────────────────

class Bridge:
    """One publisher, one router. Also the zeroconf ServiceBrowser listener."""

    def __init__(self, client, zc, auth):
        self.client = client
        self.zc = zc
        self.auth = auth
        self.cloud_fails = 0
        self.apikey = None                # account apikey (WS handshake), from device list
        # LAN presence per device: name/addr/port + consecutive poll misses
        self.lan = {d: {"name": None, "addr": None, "port": None, "miss": 0} for d in DEVICES}
        self.last = {}                    # last multi-state, for offline stamps

    # -- discovery ----------------------------------------------------------
    def lan_active(self, did):
        return bool(self.lan[did]["addr"]) if did in self.lan else False

    def _undiscover(self, did, why):
        st = self.lan[did]
        if st["addr"]:
            log(f"LAN lost {DEVICES[did]['prefix']} ({why}) — cloud resumes")
        st.update(addr=None, port=None, miss=0)

    def _match(self, info):
        """Registry entry for an mDNS record (records addr/port), or None."""
        if not info:
            return None
        cfg = DEVICES.get(_props(info).get("id"))
        if cfg:
            try:
                addrs = info.parsed_addresses()
                if addrs:
                    self.lan[cfg["id"]].update(addr=addrs[0], port=info.port, miss=0)
            except Exception:
                pass
        return cfg

    # zeroconf callbacks — mDNS *is* the LAN push channel
    def add_service(self, zc, type_, name):    self._seen(name)
    def update_service(self, zc, type_, name): self._seen(name)

    def remove_service(self, zc, type_, name):
        for did, st in self.lan.items():
            if st["name"] == name:
                self._undiscover(did, "mDNS goodbye")

    def _seen(self, name):
        info = self.zc.get_service_info("_ewelink._tcp.local.", name, timeout=2000)
        cfg = self._match(info)
        if cfg:
            if not self.lan[cfg["id"]]["name"]:
                log(f"LAN discovered {cfg['prefix']} at {self.lan[cfg['id']]['addr']}")
            self.lan[cfg["id"]]["name"] = name
            self._lan_state(info, cfg)

    def lan_poll(self):
        """Re-query known devices so state stays fresh even without pushes — and
        UNDISCOVER after LAN_MISS_LIMIT misses, so a device that left the network
        hands back to the cloud instead of freezing as LAN-owned forever."""
        for did, st in self.lan.items():
            if not st["name"]:
                continue
            info = self.zc.get_service_info("_ewelink._tcp.local.", st["name"], timeout=2000)
            cfg = self._match(info)
            if cfg:
                self._lan_state(info, cfg)
            elif st["addr"]:
                st["miss"] += 1
                if st["miss"] >= LAN_MISS_LIMIT:
                    self._undiscover(did, f"{LAN_MISS_LIMIT} poll misses")

    def _lan_state(self, info, cfg):
        props = _props(info)
        try:
            p = decrypt(props, cfg["key"]) if props.get("encrypt") in ("true", True) else {}
        except Exception as e:
            log("decrypt failed:", e); return
        self.publish_state(cfg, p, online=True, source="LAN")

    # -- the one publisher ----------------------------------------------------
    def publish_state(self, cfg, p, online, source):
        """Every route lands here: identical topics, identical shapes, so
        downstream cannot tell (and need not care) which route delivered."""
        if cfg["kind"] == "multi":
            sws = p.get("switches")
            if sws is None:
                if online is False and cfg["id"] in self.last:
                    out = {**self.last[cfg["id"]], "online": 0}   # offline stamp
                else:
                    return
            else:
                out = {"online": 1 if online else 0}
                for sw in sws:
                    if sw.get("outlet") is not None:
                        out[f"ch{sw['outlet'] + 1}"] = 1 if sw.get("switch") == "on" else 0
            self.last[cfg["id"]] = {k: v for k, v in out.items() if k != "online"}
            self.client.publish(f"{cfg['prefix']}/json", json.dumps(out), qos=0, retain=True)
            log(f"{source} state {cfg['prefix']}", out)
            return
        out = {}
        if source != "LAN":               # power/V/A: cloud only (LAN values freeze)
            for k in ("power", "voltage", "current"):
                if k in p:
                    try: out[k] = float(p[k])
                    except Exception: pass
        # the switch belongs to whichever route owns the device right now
        if "switch" in p and (source == "LAN" or not self.lan_active(cfg["id"])):
            out["switch"] = 1 if p["switch"] == "on" else 0
        for k, v in out.items():
            self.client.publish(f"{cfg['prefix']}/{k}", str(v), qos=0, retain=True)
        if out:
            self.client.publish(f"{cfg['prefix']}/json", json.dumps(out), qos=0, retain=True)
            log(f"{source} state {cfg['prefix']}", out)

    # -- control: discovery decides the route --------------------------------
    def control(self, cfg, params):
        """LAN when discovered — a LAN failure is a FAILURE, logged and surfaced,
        never silently retried via cloud where it would mask problems. Cloud
        when not discovered."""
        if self.lan_active(cfg["id"]):
            st = self.lan[cfg["id"]]
            endpoint = "switches" if cfg["kind"] == "multi" else "switch"
            iv_b64, data_b64 = encrypt(params, cfg["key"])
            body = json.dumps({
                "sequence": str(int(time.time() * 1000)), "deviceid": cfg["id"],
                "selfApikey": "123", "iv": iv_b64, "encrypt": True, "data": data_b64,
            }).encode()
            try:
                req = urllib.request.Request(
                    f"http://{st['addr']}:{st['port']}/zeroconf/{endpoint}",
                    data=body, headers={"Content-Type": "application/json"})
                resp = json.loads(urllib.request.urlopen(req, timeout=5).read())
                ok = resp.get("error") == 0
                log(f"LAN control {cfg['prefix']} {params} -> {'ok' if ok else resp}")
                self.lan_poll()                    # publish the confirmed state
            except Exception as e:
                log(f"LAN control {cfg['prefix']} FAILED:", e)
            return
        creds = self.auth.credentials()
        if not creds:
            log("cloud control impossible — no credentials"); return
        at, appid, region = creds
        try:
            d = _cloud_req(f"{_api_base(region)}/v2/device/thing/status",
                           body={"type": 1, "id": cfg["id"], "params": params},
                           bearer=at, appid=appid)
            ok = not d.get("error")
            log(f"cloud control {cfg['prefix']} {params} -> "
                f"{'ok' if ok else (d.get('error'), d.get('msg', ''))}")
            if ok:
                self.cloud_poll()                  # publish the confirmed state
        except Exception as e:
            log(f"cloud control {cfg['prefix']} FAILED:", e)

    # -- cloud reconciliation poll --------------------------------------------
    def cloud_poll(self, _retry=True):
        creds = self.auth.credentials()
        if not creds:
            return
        at, appid, region = creds
        try:
            d = _cloud_req(f"{_api_base(region)}/v2/device/thing", bearer=at, appid=appid)
        except Exception as e:
            log("cloud poll failed:", e); self._cloud_fail(); return
        if d.get("error"):
            if d["error"] in (401, 402) and _retry and self.auth.invalidate():
                return self.cloud_poll(_retry=False)
            log("cloud error", d.get("error"), d.get("msg", "")); self._cloud_fail(); return
        seen = False
        for t in (d.get("data") or {}).get("thingList") or []:
            it = t.get("itemData", {})
            cfg = DEVICES.get(it.get("deviceid"))
            if not cfg:
                continue
            seen = True
            if it.get("apikey"):
                self.apikey = it["apikey"]        # the WS handshake wants this
            if cfg["kind"] == "multi" and self.lan_active(cfg["id"]):
                continue                          # LAN owns this device's state
            # `online` lives on itemData, NOT params — hardcoding it true once
            # kept an unplugged device "healthy" on the dashboard forever
            self.publish_state(cfg, it.get("params") or {},
                               online=bool(it.get("online")), source="poll")
        if seen:
            if self.cloud_fails >= CLOUD_MAX_FAILS:
                log("cloud data back after outage")
            self.cloud_fails = 0
        else:
            log("cloud poll: no known device in response"); self._cloud_fail()

    def _cloud_fail(self):
        """Clear retained cloud-only readings after repeated failures so
        dashboards do not show frozen numbers as live. LAN state stays."""
        self.cloud_fails += 1
        if self.cloud_fails == CLOUD_MAX_FAILS:
            log(f"cloud stale ({CLOUD_MAX_FAILS} fails) — clearing retained power/V/A")
            for cfg in DEVICES.values():
                if cfg["kind"] == "single":
                    for k in ("power", "voltage", "current"):
                        self.client.publish(f"{cfg['prefix']}/{k}", "", qos=0, retain=True)

# ── cloud push (the WebSocket the vendor app uses) ───────────────────────────

class CloudWS:
    """Instant state for cloud-routed devices: dispatch/app hands out a WS host,
    userOnline authenticates with the same OAuth token, and every change —
    including app taps and the device's physical buttons — arrives as an
    `update` the moment it happens. The REST poll is reconciliation only.
    LAN-owned devices drop their pushes here exactly as the poll drops rows."""

    def __init__(self, auth, bridge):
        self.auth = auth
        self.bridge = bridge

    def start(self):
        if websocket is None:
            log("cloud push disabled (websocket-client not installed)"); return
        threading.Thread(target=self._run, daemon=True).start()

    def _connect(self):
        creds = self.auth.credentials()
        if not creds:
            return None
        at, appid, region = creds
        d = _cloud_req(f"https://{region}-dispa.coolkit.{'cn' if region == 'cn' else 'cc'}/dispatch/app",
                       body={"appid": appid, "nonce": secrets.token_hex(4),
                             "ts": int(time.time()), "version": 8},
                       bearer=at, appid=appid)
        if not d.get("domain"):
            return None
        ws = websocket.create_connection(f"wss://{d['domain']}:{d['port']}/api/ws", timeout=15)
        ws.send(json.dumps({
            "action": "userOnline", "at": at, "apikey": self.bridge.apikey or "",
            "appid": appid, "nonce": secrets.token_hex(4), "ts": int(time.time()),
            "userAgent": "app", "sequence": str(int(time.time() * 1000)), "version": 8}))
        hello = json.loads(ws.recv())
        if hello.get("error") not in (0, None):
            ws.close()
            raise OSError(f"handshake refused: {hello.get('error')}")
        hb = int((hello.get("config") or {}).get("hbInterval", 90))
        log(f"cloud push connected (hb {hb}s)")
        return ws, hb

    def _run(self):
        backoff = 5
        while True:
            ws = None
            try:
                got = self._connect()
                if not got:
                    time.sleep(60); continue
                ws, hb = got
                backoff = 5
                ws.settimeout(20)                  # short, so pings stay on schedule
                last_ping = time.time()
                while True:
                    if time.time() - last_ping >= hb:
                        ws.send("ping"); last_ping = time.time()
                    try:
                        raw = ws.recv()
                    except websocket.WebSocketTimeoutException:
                        continue
                    if not raw or raw == "pong":
                        continue
                    try:
                        msg = json.loads(raw)
                    except ValueError:
                        continue
                    self._handle(msg)
            except Exception as e:
                log("cloud push dropped:", e)
                try:
                    if ws: ws.close()
                except Exception:
                    pass
                time.sleep(backoff)
                backoff = min(backoff * 2, 300)

    def _handle(self, msg):
        cfg = DEVICES.get(msg.get("deviceid"))
        if not cfg or self.bridge.lan_active(cfg["id"]):
            return
        if msg.get("action") == "update":
            self.bridge.publish_state(cfg, msg.get("params") or {}, online=True, source="push")
        elif msg.get("action") == "sysmsg":
            online = (msg.get("params") or {}).get("online")
            if online is not None:
                self.bridge.publish_state(cfg, {}, online=bool(online), source="push")

# ── OAuth one-time login ─────────────────────────────────────────────────────

def oauth_login():
    """Interactive: print login URL, capture the redirect code (30s validity!),
    exchange it, persist tokens to TOKEN_FILE."""
    if not CLOUD_APPID or not CLOUD_APPSECRET:
        sys.exit("EWELINK_APPID and EWELINK_APPSECRET are required for auth")
    seq = str(int(time.time() * 1000))
    url = "https://c2ccdn.coolkit.cc/oauth/index.html?" + urllib.parse.urlencode({
        "clientId": CLOUD_APPID, "seq": seq,
        "authorization": base64.b64encode(hmac.new(
            CLOUD_APPSECRET.encode(), f"{CLOUD_APPID}_{seq}".encode(), hashlib.sha256).digest()).decode(),
        "redirectUrl": REDIRECT_URL, "grantType": "authorization_code",
        "state": secrets.token_hex(8), "nonce": secrets.token_hex(4)})
    print(f"\nOpen this URL in a browser and log in with your eWeLink account:\n\n{url}\n")

    code, region = None, CLOUD_REGION
    port = urllib.parse.urlparse(REDIRECT_URL).port or 80
    try:
        from http.server import HTTPServer, BaseHTTPRequestHandler
        captured = {}
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                captured.update({k: v[0] for k, v in q.items()})
                self.send_response(200); self.end_headers()
                self.wfile.write(b"OK - return to the terminal.")
            def log_message(self, *a): pass
        srv = HTTPServer(("0.0.0.0", port), H)
        srv.timeout = 5
        print(f"waiting up to 5 min for the redirect on port {port} ...")
        deadline = time.time() + 300
        while "code" not in captured and time.time() < deadline:
            srv.handle_request()
        srv.server_close()
        code, region = captured.get("code"), captured.get("region", region)
    except OSError as e:
        print(f"(cannot listen on port {port}: {e})")
        pasted = input("paste the full redirect URL you landed on: ").strip()
        q = urllib.parse.parse_qs(urllib.parse.urlparse(pasted).query)
        code = (q.get("code") or [None])[0]
        region = (q.get("region") or [region])[0]
    if not code:
        sys.exit("no authorization code received")

    d = _cloud_req(f"{_api_base(region)}/v2/user/oauth/token", body={
        "code": code, "redirectUrl": REDIRECT_URL, "grantType": "authorization_code"})
    if d.get("error"):
        sys.exit(f"token exchange failed: {d.get('error')} {d.get('msg', '')}")
    now = int(time.time() * 1000)
    auth = CloudAuth()
    auth.tok = {"at": d["data"]["accessToken"], "rt": d["data"]["refreshToken"],
                "atExpiredTime": d["data"].get("atExpiredTime", now + 30 * 86400 * 1000),
                "rtExpiredTime": d["data"].get("rtExpiredTime", now + 60 * 86400 * 1000),
                "region": region}
    auth.save()
    days = (auth.tok["atExpiredTime"] - now) / 86400000
    print(f"tokens saved to {TOKEN_FILE} (access token valid ~{days:.0f} days, auto-refreshed)")

# ── main ─────────────────────────────────────────────────────────────────────

def main():
    if not DEVICES:
        sys.exit("no devices configured (DEVICE_ID / EWE4_ID)")
    auth = CloudAuth()
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1)
    except Exception:
        client = mqtt.Client()
    lwt = next(iter(DEVICES.values()))["prefix"]   # bridge liveness rides device 0
    client.will_set(f"{lwt}/online", "0", retain=True)
    while True:
        try:
            client.connect(MQTT_HOST, MQTT_PORT, 60)
            break
        except Exception as e:
            log("mqtt connect retry:", e); time.sleep(5)
    client.loop_start()
    client.publish(f"{lwt}/online", "1", retain=True)

    zc = Zeroconf()
    bridge = Bridge(client, zc, auth)
    ServiceBrowser(zc, "_ewelink._tcp.local.", bridge)

    # command topics: <prefix>/cmd/switch (single), <prefix>/cmd/ch<N> (multi)
    def on_message(cl, ud, msg):
        cmd = msg.payload.decode(errors="ignore").strip().lower()
        on = cmd in ("on", "1", "true")
        for cfg in DEVICES.values():
            if cfg["kind"] == "single" and msg.topic == f"{cfg['prefix']}/cmd/switch":
                log(f"cmd {cfg['prefix']} switch = {cmd}")
                bridge.control(cfg, {"switch": "on" if on else "off"})
                return
            if cfg["kind"] == "multi" and msg.topic.startswith(f"{cfg['prefix']}/cmd/ch"):
                try:
                    ch = int(msg.topic.rsplit("ch", 1)[1])
                except ValueError:
                    return
                if 1 <= ch <= cfg.get("channels", 4):
                    log(f"cmd {cfg['prefix']} ch{ch} = {cmd}")
                    bridge.control(cfg, {"switches": [
                        {"switch": "on" if on else "off", "outlet": ch - 1}]})
                return
    client.on_message = on_message
    for cfg in DEVICES.values():
        client.subscribe(f"{cfg['prefix']}/cmd/+")
        log(f"{cfg['prefix']}: {cfg['kind']} device {cfg['id']} — LAN when discovered, else cloud")

    if auth.credentials():
        log(f"cloud: reconciliation poll every {CLOUD_INTERVAL}s + push channel "
            f"({'OAuth' if auth.tok else 'manual token'}, region {auth.region})")
        bridge.cloud_poll()                        # also learns the account apikey
        CloudWS(auth, bridge).start()
    else:
        log("no cloud credentials — LAN-discovered devices only")

    n = 0
    try:
        while True:
            time.sleep(LAN_POLL_S)
            bridge.lan_poll()
            n += 1
            if (n * LAN_POLL_S) % CLOUD_INTERVAL < LAN_POLL_S:
                bridge.cloud_poll()
            client.publish(f"{lwt}/online", "1", retain=True)
    finally:
        zc.close()

if __name__ == "__main__":
    oauth_login() if (len(sys.argv) > 1 and sys.argv[1] == "auth") else main()
