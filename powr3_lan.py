#!/usr/bin/env python3
"""Sonoff POWR3 <-> MQTT bridge — HYBRID (LAN for switch+control, cloud for power).

The POWR3 advertises over mDNS (_ewelink._tcp) with params AES-encrypted using the
device key. Two paths, because the POWR3 does NOT reliably report live power/V/A over
eWeLink LAN (firmware only pushes on large threshold changes):
  • LAN  — switch STATE + relay CONTROL, fully OFFLINE. We decrypt the mDNS state and
           publish it; a cmd topic drives control by POSTing to the device's
           /zeroconf/switch (encrypted) at the IP+port discovered via mDNS.
  • CLOUD— power / voltage / current, polled ~30s from the eWeLink cloud (needs a
           CoolKit v2 access token in EWELINK_TOKEN). Skipped if no token.
signalk-mqtt-sensors maps the published topics into SignalK (electrical.ac.shore.*).

Cloud auth (preferred): eWeLink OAuth2.0 app (dev.ewelink.cc appid+secret). One-time
`python powr3_lan.py auth` obtains access+refresh tokens; the bridge persists them in
EWELINK_TOKEN_FILE and auto-refreshes (at 30d / rt 60d). Fallback: a manually-made
access token in EWELINK_TOKEN (bound to EWELINK_TOKEN_APPID) is used if OAuth tokens
are absent or refresh fails.

Env:
  DEVICE_ID            eWeLink deviceid (e.g. 10013c5fde)
  DEVICE_KEY           eWeLink devicekey (SECRET) — from the cloud API once
  EWELINK_APPID        OAuth2.0 app id from dev.ewelink.cc
  EWELINK_APPSECRET    OAuth2.0 app secret (SECRET)
  EWELINK_REDIRECT_URL redirect URL registered with the OAuth app,
                       default http://127.0.0.1:8000/callback
  EWELINK_TOKEN_FILE   where OAuth tokens persist, default /data/ewelink_tokens.json
  EWELINK_TOKEN        manual access token (SECRET) — legacy fallback
  EWELINK_TOKEN_APPID  appid the manual token was issued under
  EWELINK_REGION       cloud region, default eu
  MQTT_HOST            default 127.0.0.1
  MQTT_PORT            default 1883
  TOPIC_PREFIX         default maracaibo/sonoff/powr3
"""
import os, sys, json, time, hashlib, hmac, base64, secrets, urllib.request, urllib.parse
from Crypto.Cipher import AES
from zeroconf import Zeroconf, ServiceBrowser
import paho.mqtt.client as mqtt

DEVICE_ID = os.environ.get("DEVICE_ID", "").strip()
DEVICE_KEY = os.environ.get("DEVICE_KEY", "").strip()
MQTT_HOST = os.environ.get("MQTT_HOST", "127.0.0.1")
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
PREFIX = os.environ.get("TOPIC_PREFIX", "maracaibo/sonoff/powr3").rstrip("/")
# Cloud read for power/voltage/current — the POWR3 does NOT report these reliably over
# LAN (Sonoff limitation). Switch state + control stay on LAN (offline). If no cloud
# credentials, power just isn't published (switch + control still work).
CLOUD_APPID = os.environ.get("EWELINK_APPID", "").strip()
CLOUD_APPSECRET = os.environ.get("EWELINK_APPSECRET", "").strip()
REDIRECT_URL = os.environ.get("EWELINK_REDIRECT_URL", "http://127.0.0.1:8000/callback").strip()
TOKEN_FILE = os.environ.get("EWELINK_TOKEN_FILE", "/data/ewelink_tokens.json").strip()
# Legacy manual token — access token bound to whatever appid it was issued under.
MANUAL_TOKEN = os.environ.get("EWELINK_TOKEN", "").strip()
MANUAL_APPID = (os.environ.get("EWELINK_TOKEN_APPID", "").strip()
                or CLOUD_APPID or "K0OCDSvIaBWdEaU4zxlKEwk26kmshoXK")
CLOUD_REGION = os.environ.get("EWELINK_REGION", "eu").strip()
CLOUD_INTERVAL = int(os.environ.get("CLOUD_INTERVAL", "30"))

log = lambda *a: print(*a, flush=True)

# ---------------------------------------------------------------- cloud auth

def _api_base(region):
    tld = "cn" if region == "cn" else "cc"
    return f"https://{region}-apia.coolkit.{tld}"

def _sign(data: bytes) -> str:
    """eWeLink v2 'Sign' auth: base64(HMAC-SHA256(appsecret, data))."""
    return base64.b64encode(hmac.new(CLOUD_APPSECRET.encode(), data, hashlib.sha256).digest()).decode()

def _cloud_req(url, body=None, bearer=None, appid=None):
    """Signed (body!=None, Sign) or Bearer request. Returns decoded JSON."""
    data = json.dumps(body).encode() if body is not None else None
    auth = f"Bearer {bearer}" if bearer else f"Sign {_sign(data or b'')}"
    req = urllib.request.Request(url, data=data, headers={
        "Content-Type": "application/json", "X-CK-Appid": appid or CLOUD_APPID,
        "X-CK-Nonce": secrets.token_hex(4), "Authorization": auth,
    })
    return json.load(urllib.request.urlopen(req, timeout=10))

class CloudAuth:
    """OAuth token store with auto-refresh; manual EWELINK_TOKEN as fallback.

    Token file: {at, rt, atExpiredTime, rtExpiredTime, region} (times = ms epoch).
    """
    REFRESH_MARGIN_MS = 24 * 3600 * 1000            # refresh 1 day before at expiry

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
        """Exchange rt for a fresh at/rt. Returns True on success."""
        if not (self.tok and self.tok.get("rt") and CLOUD_APPID and CLOUD_APPSECRET):
            return False
        try:
            d = _cloud_req(f"{_api_base(self.region)}/v2/user/refresh", body={"rt": self.tok["rt"]})
        except Exception as e:
            log("token refresh failed:", e); return False
        if d.get("error"):
            log("token refresh error", d.get("error"), d.get("msg", "")); return False
        now = int(time.time() * 1000)
        self.tok.update({
            "at": d["data"]["at"], "rt": d["data"]["rt"],
            "atExpiredTime": now + 30 * 86400 * 1000,   # at valid 30d, rt 60d
            "rtExpiredTime": now + 60 * 86400 * 1000,
        })
        self.save()
        log("OAuth tokens refreshed")
        return True

    def credentials(self):
        """Return (access_token, appid, region) or None. Refreshes when near expiry."""
        if self.tok and self.tok.get("at"):
            now = int(time.time() * 1000)
            if now >= self.tok.get("atExpiredTime", 0) - self.REFRESH_MARGIN_MS:
                if not self.refresh() and now >= self.tok.get("atExpiredTime", 0):
                    log("OAuth access token expired and refresh failed")
                    return self._manual()
            return (self.tok["at"], CLOUD_APPID, self.region)
        return self._manual()

    def _manual(self):
        if MANUAL_TOKEN:
            return (MANUAL_TOKEN, MANUAL_APPID, CLOUD_REGION)
        return None

    def invalidate(self):
        """Called on 401/402 from a data call — force a refresh attempt."""
        if self.tok:
            self.tok["atExpiredTime"] = 0
            return self.refresh()
        return False

def oauth_login():
    """One-time interactive OAuth2.0 flow: print login URL, capture the redirect
    code (30s validity!), exchange it, persist tokens to TOKEN_FILE."""
    if not CLOUD_APPID or not CLOUD_APPSECRET:
        sys.exit("EWELINK_APPID and EWELINK_APPSECRET are required for auth")
    seq = str(int(time.time() * 1000))
    url = "https://c2ccdn.coolkit.cc/oauth/index.html?" + urllib.parse.urlencode({
        "clientId": CLOUD_APPID, "seq": seq,
        "authorization": base64.b64encode(hmac.new(
            CLOUD_APPSECRET.encode(), f"{CLOUD_APPID}_{seq}".encode(), hashlib.sha256).digest()).decode(),
        "redirectUrl": REDIRECT_URL, "grantType": "authorization_code",
        "state": secrets.token_hex(8), "nonce": secrets.token_hex(4),
    })
    print("\nOpen this URL in a browser and log in with your eWeLink account:\n")
    print(url + "\n")

    code, region = None, CLOUD_REGION
    port = urllib.parse.urlparse(REDIRECT_URL).port or 80
    try:                                # capture redirect on the local port if we can
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
        "code": code, "redirectUrl": REDIRECT_URL, "grantType": "authorization_code",
    })
    if d.get("error"):
        sys.exit(f"token exchange failed: {d.get('error')} {d.get('msg', '')}")
    tok = {
        "at": d["data"]["accessToken"], "rt": d["data"]["refreshToken"],
        "atExpiredTime": d["data"].get("atExpiredTime", int(time.time() * 1000) + 30 * 86400 * 1000),
        "rtExpiredTime": d["data"].get("rtExpiredTime", int(time.time() * 1000) + 60 * 86400 * 1000),
        "region": region,
    }
    auth = CloudAuth(); auth.tok = tok; auth.save()
    days = (tok["atExpiredTime"] - time.time() * 1000) / 86400000
    print(f"tokens saved to {TOKEN_FILE} (access token valid ~{days:.0f} days, auto-refreshed)")

# ------------------------------------------------------------------ LAN path

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
    def __init__(self, client, zc, auth):
        self.client = client
        self.zc = zc
        self.auth = auth
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
        # LAN mDNS carries the SWITCH state reliably; power/V/A over LAN are unreliable
        # (frozen/thresholded) so we take those from the cloud instead.
        props = _props(info)
        try:
            p = decrypt(props) if props.get("encrypt") in ("true", True) else {}
        except Exception as e:
            log("decrypt failed:", e); return
        if "switch" in p:
            self.client.publish(f"{PREFIX}/switch", str(1 if p["switch"] == "on" else 0), qos=0, retain=True)

    # Cloud read of power/voltage/current (the reliable source for those).
    def cloud_poll(self, _retry=True):
        creds = self.auth.credentials()
        if not creds:
            return
        at, appid, region = creds
        try:
            d = _cloud_req(f"{_api_base(region)}/v2/device/thing", bearer=at, appid=appid)
        except Exception as e:
            log("cloud poll failed:", e); return
        if d.get("error"):
            # 401/402 = invalid/expired token -> refresh once and retry
            if d["error"] in (401, 402) and _retry and self.auth.invalidate():
                return self.cloud_poll(_retry=False)
            log("cloud error", d.get("error"), d.get("msg", "")); return
        for t in (d.get("data") or {}).get("thingList") or []:
            it = t.get("itemData", {})
            if it.get("deviceid") != DEVICE_ID:
                continue
            p = it.get("params", {})
            out = {}
            for k in ("power", "voltage", "current"):
                if k in p:
                    try: out[k] = float(p[k])
                    except Exception: pass
            if "switch" in p:
                out["switch"] = 1 if p["switch"] == "on" else 0
            for k, v in out.items():
                self.client.publish(f"{PREFIX}/{k}", str(v), qos=0, retain=True)
            if out:
                log("cloud published", out)

def main():
    if not DEVICE_ID or not DEVICE_KEY:
        sys.exit("DEVICE_ID and DEVICE_KEY are required")
    auth = CloudAuth()
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
    listener = Listener(client, zc, auth)
    ServiceBrowser(zc, "_ewelink._tcp.local.", listener)

    # control: MQTT <prefix>/cmd/switch = on/off -> LAN control the POWR3 relay
    def on_message(cl, ud, msg):
        cmd = msg.payload.decode(errors="ignore").strip().lower()
        log(f"cmd/switch = {cmd}")
        listener.control(cmd in ("on", "1", "true"))
    client.on_message = on_message
    client.subscribe(f"{PREFIX}/cmd/switch")

    cloud = auth.credentials() is not None
    if cloud:
        src = "OAuth" if auth.tok else "manual token"
        log(f"cloud power poll enabled ({src}, region {auth.region}, every {CLOUD_INTERVAL}s)")
        listener.cloud_poll()
    else:
        log("no cloud credentials — power/voltage/current not published (LAN switch+control still work)")
    n = 0
    try:
        while True:
            time.sleep(15)          # LAN switch state cadence
            listener.poll()
            n += 1
            if cloud and (n * 15) % CLOUD_INTERVAL < 15:   # ~every CLOUD_INTERVAL
                listener.cloud_poll()
            client.publish(f"{PREFIX}/online", "1", retain=True)
    finally:
        zc.close()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "auth":
        oauth_login()
    else:
        main()
