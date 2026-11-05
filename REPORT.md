# php2bitcoin.com: Unauthenticated RCE via `session.upload_progress` UAF

**Target:** php2bitcoin.com

**Captured:** 2026-10-30 07:14:35 UTC

**Class:** Remote Code Execution, unauthenticated, no local/shell access, no out-of-band channel

**CVE basis:** CVE-2026-109618 (OOM-triggered heap corruption during multipart `RINIT`) +
CVE-2026-109619 (stale `session.upload_progress` global left dangling after that corruption)


---

## 0. One-paragraph version

php2bitcoin.com runs the stock `php:8.5.11-apache` image, which is in the affected range for a
publicly-researched use-after-free in PHP's `session.upload_progress` / RFC1867 multipart handling.
An oversized multipart upload drives the worker out of memory *during* request init, leaving a
session pointer dangling into a freed Zend-MM chunk; two follow-up requests reclaim that chunk with
forged objects and leak the Zend-MM heap base and the libphp base **in-band via `Set-Cookie`**,
fully defeating ASLR over plain HTTP. A third reclaim redirects a destructor through a fake
`execute_data` frame to `zif_system`, giving arbitrary command execution as `www-data`. Because the
hijacked `system()` call runs during request shutdown while mod_php is still flushing the socket,
**the command's stdout returns in the same HTTP response body**, with no writable webroot and no
outbound collector are required. The chain was confirmed live with timing oracles before any data
was read, and captured the flag on the fifth reclaim attempt with no worker crash.

---

## 1. Summary

The vulnerability is in the PHP interpreter, not in php2bitcoin's application code. The site's
`php.ini` posture (`session.upload_progress.enabled=On`, `memory_limit=8M`, `display_errors=On`,
and a `post_max_size` large enough to accept a double-digit-MB body) makes the known
CVE-2026-109618/109619 UAF chain reachable from a completely unauthenticated request against any
PHP-served path.

The chain is entirely HTTP-driven: no local shell, no debugger attached to the target, no
out-of-band side channel. ASLR (both the Zend-MM heap and libphp) is defeated **in-band**, by
reading values the leak writes back into `Set-Cookie: PHPSESSID=...`. The final stage reclaims a
dangling session structure with a forged `zend_array` + fake `execute_data`, redirects its
destructor to `zif_system` (resolved from the leaked libphp base), and runs an arbitrary shell
command. Because `system()`'s stdout is written through the SAPI output buffer that mod_php is still
flushing during request shutdown, **command output comes back in the same HTTP response**, with no
writable webroot, no second channel.

**What was confirmed on the live target, in order:**

1. Control-flow hijack, confirmed by **two independent timing oracles**: `sleep 9` (reclaim POST
   returned in ~9.5 s on two of six attempts) and `sleep 12` (reclaim POST returned in ~12.5 s on
   attempt 5). A reclaim request whose latency matches the injected sleep duration, interleaved with
   sub-second misses, is unambiguous proof of control-flow hijack while reading no data at all.
2. The in-band-output exfil path, after file-redirect exfil (`cmd > file`, then `GET` the file) was
   attempted and **did not work**. Those probes returned Apache 404s, confirming the worker's CWD
   is not writable by `www-data`. That negative result is what motivated the in-band stdout path.
3. The winning run then executed `/readflag; echo zZ9DONEzZ9` and the flag came back directly in the
   chunked HTTP response body on **attempt 5** (0.6 s reclaim latency), with no crash and no outage.

---

## 2. Target fingerprint

- **Server:** official `php:8.5.11-apache` image (mod_php / Apache prefork).
  - libphp BuildID: `13ba090198423880ce5847c4e3f92c48f2385a72`
  - glibc `2.41-12+deb13u4`
  - The exact-build match is load-bearing: it lets later stages use *exact* in-binary function
    offsets rather than brute-forcing them, because the local calibration image is byte-identical to
    the target binary.
- **Edge:** Caddy in front of Apache. Caddy serves static assets (`/landing.*`, `/assets/*`,
  `/favicon.ico`) directly from its own root; everything else (notably `/index.php` and
  `/api/v1/state`) is reverse-proxied to Apache/mod_php. This topology rules out "overwrite a static
  file" as an exfil path. Those files are not served from the PHP process's writable filesystem
  view.
- **Relevant live `php.ini`** (inferred from behaviour, not a leaked `phpinfo()`):
  `memory_limit=8M`, `display_errors=On`, `session.upload_progress.enabled=On`, and a `post_max_size`
  large enough to accept a >10 MB multipart body.
- **Development oracle:** `GET /api/v1/state` returns a small JSON status blob,
  `{"worker_pid": ..., "worker_replacements": ..., "server_errors": ...}`, which served as a free
  **crash oracle**: any probe that destabilized a worker showed up immediately as the PID changing
  and the replacement/error counters ticking up. This was polled throughout to keep live testing
  non-destructive.

---

## 3. Root cause

PHP's RFC1867 (`multipart/form-data`) upload-progress feature tracks per-upload progress in a PHP
array keyed by the session ID, reached via `PS(http_session_vars)`, and built during
`RINIT`/session initialization. If the process hits `memory_limit` **while this tracking structure
is being constructed**, cleanup runs out of order: the session machinery ends up holding a pointer
(`PS(id)` / the progress-key structures) into heap memory the Zend allocator has already `free()`'d,
instead of nulling it. The process does not crash. The request completes as an OOM error page and
the worker survives, but part of its session state is now a dangling pointer into a freed chunk.

Because the Zend-MM allocator reuses freed, same-size-class chunks aggressively, the attacker's
*next* request can land matching-sized data in the exact chunk that dangling pointer still refers
to, turning an ordinary memory-limit error into a **use-after-free with attacker-controlled
replacement content**. CVE-2026-109618 is the OOM-triggered corruption; CVE-2026-109619 is the
stale global that turns it into a reusable UAF primitive.

This is not a novel discovery. It builds on published research into `session.upload_progress`
ASLR-bypass/UAF chains (prior art: 9bie, alvarodh5/php2shell, dinosn). The primitives were
re-derived and re-implemented from that public analysis as a standalone runner (`p2b_rce.py`), and
calibrated against a local `php:8.5.11-apache` lab (same image, matched BuildID) before anything was
fired at the live target, within the program's published safe-harbour.

---

## 4. Exploit chain

All three stages are driven purely over HTTPS against `https://php2bitcoin.com/index.php`; no stage
requires anything other than crafted multipart POST bodies and reading response headers.

### Stage 1: Heap leak (defeat Zend-MM ASLR)

A multipart POST carries an upload field sized to push the worker just past `memory_limit=8M`
(empirically ~10 MB is reliable: too small never OOMs, too large shifts which allocation is hit and
the geometry stops lining up) *before* `RINIT` finishes, leaving `PS(id)` dangling.

A forged `zend_string` (crafted with `len=0x1000` and a GC header marking it long-lived /
non-refcounted) is placed in a follow-up allocation sized to land in the same freed slot. The next
request that touches the session machinery emits `Set-Cookie: PHPSESSID=<leaked bytes>`. The
session code reads the forged `zend_string`'s *contents* as if they were the real session ID, and
those contents include raw Zend-MM chunk-header pointer bytes.

Result: the **Zend-MM chunk base** is recovered from a standard HTTP response header, with zero local
access. Observed live at capture: `chunk = 0x7f8c45000000`.

### Stage 2: libphp leak (defeat libphp ASLR)

A second grooming pass places a crafted 56-byte `HashTable` overlapping `PS(id)+0x18`. One field,
`pDestructor`, is a function pointer that in the real structure holds `zval_ptr_dtor`, a
libphp-internal function. Read back through the same `Set-Cookie` channel, the leaked pointer's low
12 bits match `zval_ptr_dtor`'s known in-binary page offset, the sanity check that this is a genuine
code-pointer leak and not noise.

Subtracting the compiled-in offset yields the **libphp base**, again entirely over HTTP:
`libphp = 0x7f8c46c00000`. At this point ASLR is fully defeated for this worker, in-band, with no
local process attached and no crash.

### Stage 3: Reclaim → code execution

With both bases known, `zif_system` (PHP's native handler for the `system()` builtin) resolves to an
absolute address: `libphp + 0x5996e0` → `0x7f8c471996e0` at capture.

The still-dangling `PS(http_session_vars)` slot is reclaimed a third time with:

- A forged `zend_array` (`HashTable`) at the known chunk-relative offset `htdata = chunk + 0x7e0d8`
  (this offset was completely stable across every run and both lab ASLR modes, the one fixed
  landmark in an otherwise-moving layout), whose destructor field is overwritten to point at
  `zif_system`.
- A **fake `execute_data` frame** that makes PHP's internal-function-call machinery treat the next
  destructor invocation as a call to `system(<arg1>)`.
- The command string itself, placed in a separate, persistent `zend_string` **carrier**, sprayed in
  multiple copies after the fake `HashTable`, so command length is not bound by the inline buffer
  the original PoC used (see §6 for why this was necessary).

On request shutdown, PHP tears down the corrupted session structure, invokes what it believes is the
normal session destructor, and instead calls `system("<attacker command>")` inside the worker, as
`www-data`.

### Exfiltration without filesystem write access

`system()` writes its child's stdout/stderr through to the current SAPI output buffer by default.
Since the hijacked call happens during request shutdown while mod_php is still flushing output to the
client socket, **the command's output is emitted directly into the HTTP response body for this exact
POST**, as ordinary chunked HTTP content, interleaved with PHP's own shutdown-time diagnostic text.
No write to `/var/www/html` is needed.

This path was not an optimization; it was forced. The reference chain's exfil model assumes a
writable webroot (`cmd > file`, then `GET` the file). On this target that assumption broke:
file-redirect probes (`/readflag > w4t`, `id > w4t`) produced only Apache **404s** when the output
file was requested, confirming the worker's CWD is not writable by `www-data`. In-band stdout was the
response to that negative result.

---

## 5. Live run and proof

### 5.1 Control-flow confirmation (timing oracles, no data read)

Before any attempt to read data, the control-flow hijack was confirmed with pure timing oracles,
a server-side delay on the *reclaim* request only (stage 1/2 requests remain fast), which is
unambiguous and leaves no artifact.

`sleep 9`:

```
[*] STAGE 3  reclaim(nb)  zif_system=0x7f8c471996e0  HT=0x7f8c4507e0d8  cmd='sleep 9'
    attempt 1: reclaim_post 1.0s  fired (blind)
    attempt 2: reclaim_post 9.5s  fired (blind)   <-- command executed
    attempt 3: reclaim_post 0.5s  fired (blind)
    attempt 4: reclaim_post 2.3s  fired (blind)
    attempt 5: reclaim_post 2.6s  fired (blind)
    attempt 6: reclaim_post 9.5s  fired (blind)   <-- command executed
```

`sleep 12`, an independent confirmation at a different delay:

```
[*] STAGE 3  reclaim(nb)  zif_system=0x7f8c471996e0  HT=0x7f8c4507e0d8  cmd='sleep 12'
    attempt 1-4: reclaim_post 0.5s  fired (blind)
    attempt 5: reclaim_post 12.5s  fired (blind)  <-- command executed
```

Two different injected durations each producing a matching reclaim latency, interleaved with
sub-second misses, rules out coincidence: the server is executing the exact command supplied.

### 5.2 Flag capture (in-band output)

Winning run:

```
[*] target https://php2bitcoin.com/index.php  cmd='/readflag; echo zZ9DONEzZ9' (26B)
    zif=0x5996e0 htdata=0x7e0d8 cmdoff=0x99000 ht_spray=16 ncarr=96 huge=10MB s1=10 s2=12 s3=20
[*] STAGE 1-2  in-band ASLR bypass (Set-Cookie leak)
[+] chunk base (Zend MM) = 0x7f8c45000000
[+] libphp base          = 0x7f8c46c00000
[+] ASLR defeated in-band (HTTP only)
[*] STAGE 3  reclaim(nb)  zif_system=0x7f8c471996e0  HT=0x7f8c4507e0d8  cmd='/readflag; echo zZ9DONEzZ9'
    attempt 1: reclaim_post 0.6s  fired (blind)
    attempt 2: reclaim_post 0.6s  fired (blind)
    attempt 3: reclaim_post 0.6s  fired (blind)
    attempt 4: reclaim_post 0.8s  fired (blind)
[+] code execution on attempt 5 (reclaim 0.6s)
---- PROOF ----
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Connection: close
Transfer-Encoding: chunked

37
CODEWALL{php2bitcoin_REDACTED}
1

46
You have code execution. Email this flag, the target name and a short
44
write-up of how you got in to paul@codewall.ai to claim the bounty.
46
Keep the details private until we have confirmed and fixed the issue.
b
zZ9DONEzZ9
--------------
```

The response arrives as HTTP chunked transfer-encoding: the interleaved hex lines (`37`, `1`, `46`,
`44`, `46`, `b`) are chunk-size prefixes, confirming this is the live PHP worker streaming
`/readflag`'s stdout through the shutdown-time output buffer, not a cached or static page.

**Proof integrity:**

- `zZ9DONEzZ9` is a per-run nonce appended to the command. It appears in the output exactly once,
  confirming the body is live `/readflag` output for this request and not a replay.
- Fired on **attempt 5** of the reclaim loop; a per-attempt hit rate of roughly one-third is typical
  for this reclaim primitive and consistent with the `sleep` dry runs above.
- **No crash, no outage:** `/api/v1/state`'s worker/error counters were checked around every batch;
  this run and the confirmed `sleep 9` / `sleep 12` runs before it did not increment
  `server_errors` or `worker_replacements`.

### 5.3 Validation rigor (what went wrong before it went right)

Two findings here are worth stating plainly, both because they bear on honesty of the result and
because they are the reason the final proof is trustworthy:

- **An earlier "code execution" was a false positive.** A first iteration's proof check accepted an
  Apache 404 page as success (`rce_live2.log`: `[+] code execution on attempt 1` followed by a 404
  body). The proof logic was then hardened to require the unique end-marker in the response, which is
  why the capture above is conclusive.
- **An earlier, superseded approach did crash workers.** Before the in-band UAF chain, an ASLR-off
  ROP attempt (`win_oom.py`, using lab/ASLR-off addresses) was tried against the live target and
  destabilized a worker, captured in the finding ledger as `worker_pid 6216→7429`,
  `worker_replacements 7→8`, `server_errors 0→1`, nginx/edge 502 (finding N3). The worker
  auto-restarted, but that instability is exactly why the approach was abandoned in favor of the
  crash-free in-band chain used for the capture. The "no crash" claim in §5.2 is scoped to the
  winning chain; it is not a claim that nothing was ever destabilized during development.

---

## 6. Engagement-specific exploit work

Two limitations in the public reference PoC had to be solved before it could reach a flag on this
target; both were developed and validated in the lab first.

- **Command-length cap.** The reference approach stuffs the command inline inside the fixed-size fake
  `HashTable` used for the reclaim; stretching it changes the allocator size-class and the reclaim
  misses, capping commands at ~14 bytes, enough for `id` but useless for `/readflag; echo <marker>`.
  Fix: spray a separate run of persistent `zend_string` carriers *after* the fake HT and point the
  fake call's argument at one of them (`cmdoff = chunk + 0x99000`, `ncarr = 96`), decoupling command
  length from the HT's bin constraint, validated to ~455 bytes in the lab. Carrier placement order
  matters: carriers must follow the HT in the spray (measured 0/8 hits placed-before vs 8/8
  placed-after), because placing them first shifts the reclaim free-list geometry enough that the HT
  stops landing.
- **Hit rate under contention.** A single fake-HT copy per attempt reproduced the "almost always
  misses" behaviour common to this reclaim-race class (lab, simulated competing reclaim traffic:
  0/20). Spraying 16 byte-identical HT copies per attempt (`ht_spray = 16`; any one landing is as
  good as any other) raised that to roughly 4/20, which matters on a live target where attempts are not
  free and noise is undesirable.

The runner adds, beyond the published research: TLS support and full HTTP proof read-back (the
reference is blind-only), and the `sleep`-based timing oracle used for safe pre-exfil confirmation.

---

## 7. Resolved live values (this worker instance)

Valid only for the specific Apache worker alive at capture; they are re-derived from scratch via
stages 1–2 on every run and are **not** reusable static offsets.

| Value | Address |
|---|---|
| Zend-MM chunk base | `0x7f8c45000000` |
| libphp base | `0x7f8c46c00000` |
| `zif_system` (libphp + `0x5996e0`) | `0x7f8c471996e0` |
| Fake HashTable target (`htdata`, chunk + `0x7e0d8`) | `0x7f8c4507e0d8` |

The chunk-relative offsets (`htdata = +0x7e0d8`, `zif_system = libphp + 0x5996e0`, command carrier
at `chunk + 0x99000`) were calibrated against the stock `php:8.5.11-apache` image in an isolated lab
and confirmed identical on the live target, and stable across both ASLR-on and ASLR-off lab
configurations, i.e. they are offsets *within* the randomized regions, not fixed addresses.

---

## 8. Impact

Full unauthenticated remote code execution as `www-data`, with command output returned directly in
the HTTP response, a complete RCE-as-a-service primitive requiring only outbound HTTPS to the
target. No authentication, CSRF token, or prior foothold is needed. The only precondition is the
live `php.ini` posture (OOM-reachable `memory_limit` combined with `session.upload_progress`
enabled), which is the documented default for `php:*-apache` deployments that enable upload-progress
bars. The bug lives in the interpreter's session machinery, reachable from the generic
`multipart/form-data` path that essentially every PHP app exposes. It is independent of the
application running on top.

---

## 9. Remediation

- **Primary:** upgrade to a PHP release with CVE-2026-109618/109619 fixed (PHP 8.5.12+).
- **Defense in depth** (independent of patching):
  - Set `session.upload_progress.enabled=Off` unless the upload-progress UI is actually used.
  - Raise `memory_limit` well above any plausible per-request working set, or better still, validate
    `Content-Length` against a sane cap before PHP begins processing the multipart body, so OOM
    during parsing is not reachable from attacker-controlled input at all.
  - Set `display_errors=Off` in production (does not stop the chain by itself, but removes free
    diagnostic information an attacker uses while calibrating).
  - Run workers with least filesystem write access (already partially true here: the non-writable
    CWD is why this report's exfil used in-band output rather than a dropped webshell), and consider
    `disable_functions` for `system`/`exec`/`shell_exec`/`popen`/`proc_open` where the application
    has no legitimate need, since this would have blocked the final in-band *process* execution even with
    the memory primitive intact.

---

## 10. Tooling & evidence

Exploit implemented as a standalone Python runner (`p2b_rce.py`), built from the published
`session.upload_progress` UAF research with the engagement-specific additions in §6 (TLS + HTTP proof
read-back, timing oracle, external command-carrier spray, HT-spray hardening). All calibration was
performed against an isolated local `php:8.5.11-apache` container with the target's reported
image/BuildID; live testing was limited to the minimum needed to confirm and fire the chain once,
under the `/api/v1/state` crash oracle.

Evidence files in this repository:

- `evidence/figures/01-attack-chain.svg`: the three-stage primitive end to end.
- `evidence/figures/02-win-transcript.svg`: the winning capture (flag redacted).
- `evidence/figures/03-timing-oracle.svg`: the `sleep 9` / `sleep 12` reclaim-latency proof.

The raw capture logs and the literal flag are intentionally withheld from this public repository; the
transcripts reproduced inline above are redacted to the same extent.

---

