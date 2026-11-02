# Evidence (figures)

Report-ready figures generated from the capture logs. The raw run logs and the literal flag are
intentionally **not** included in this public repository; the transcripts shown in
[`../README.md`](../README.md) and [`../REPORT.md`](../REPORT.md) are redacted to the same extent.

| File | |
|---|---|
| [`figures/01-attack-chain.svg`](figures/01-attack-chain.svg) | The three-stage primitive end to end: OOM → heap leak → libphp leak → reclaim → `system()` → in-band output. |
| [`figures/02-win-transcript.svg`](figures/02-win-transcript.svg) | Styled terminal card of the winning capture (flag redacted). |
| [`figures/03-timing-oracle.svg`](figures/03-timing-oracle.svg) | Reclaim-latency chart for the `sleep 9` and `sleep 12` control-flow oracles. |
