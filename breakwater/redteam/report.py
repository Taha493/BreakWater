"""Run reports in JSON, Markdown, and HTML (spec section 8), built from the stored run.

The HTML report is one self-contained file with no external assets or scripts, and every
value from the run is escaped, so a transcript cannot inject markup.
"""

from __future__ import annotations

import html
import json
import re
from typing import Any

from breakwater.storage.models import RedteamResult, RedteamRun

TOP_FAILING = 10
FORMATS = ("json", "md", "html")


def build_report(run: RedteamRun, results: list[RedteamResult]) -> dict[str, Any]:
    failing = [r for r in results if r.kind == "attack" and r.mode == "protected" and r.success]
    return {
        "run": {
            "id": run.id,
            "target": run.target,
            "status": run.status,
            "started_at": run.started_at.isoformat(),
            "finished_at": run.finished_at.isoformat() if run.finished_at else None,
            "seed": run.seed,
            "previous_run_id": run.previous_run_id,
            "error": run.error,
        },
        "config": run.config_snapshot,
        "summary": run.summary or {},
        "top_failing": [
            {
                "attack_id": r.attack_id,
                "variant": r.variant,
                "category": r.category,
                "transcript": json.loads(r.transcript_redacted),
            }
            for r in failing[:TOP_FAILING]
        ],
        "failing_total": len(failing),
        "results": [
            {
                "kind": r.kind,
                "attack_id": r.attack_id,
                "variant": r.variant,
                "category": r.category,
                "mode": r.mode,
                "success": r.success,
                "blocked": r.blocked,
                "caught_by_layer": r.caught_by_layer,
                "detectors": r.detectors,
                "latency_ms": r.latency_ms,
                "error": r.error,
            }
            for r in results
        ],
    }


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def _ms(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.1f} ms"


def _delta(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:+.1f} pts"


def _category_rows(summary: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    asr = summary.get("asr", {})
    rows = list(asr.get("by_category", {}).items())
    if asr.get("overall"):
        overall = {**asr["overall"], "base": asr.get("base", {}), "mutated": asr.get("mutated", {})}
        rows.append(("all categories", overall))
    return rows


_UP_TO = {1: "rules only", 2: "rules + classifier", 3: "rules + classifier + judge"}


def _layer_table(summary: dict[str, Any], config: dict[str, Any]) -> list[list[str]] | None:
    """Rows for the layer comparison (runs with compare_layers): ASR per category, then the
    false positive rate and latency overhead, for each capped layer and the full gateway."""
    layers: dict[str, Any] = summary.get("layers") or {}
    if not layers:
        return None
    top = max(int(n) for n in layers) + 1
    names = [_UP_TO.get(int(n), f"up to layer {n}") for n in layers]
    header = ["Category", "Without gateway", *names, f"Full gateway ({_UP_TO.get(top, top)})"]
    rows = [header]
    for name, row in _category_rows(summary):
        cells = [name, _pct(row["unprotected"]["rate"])]
        for layer in layers.values():
            asr = layer["asr"]
            cell = asr["overall"] if name == "all categories" else asr["by_category"].get(name)
            cells.append(_pct((cell or {}).get("rate")))
        rows.append([*cells, _pct(row["protected"]["rate"])])
    fp_full = summary.get("false_positives", {}).get("rate")
    p95_full = summary.get("latency_ms", {}).get("overhead", {}).get("p95")
    rows.append(
        ["False positive rate", "", *(_pct(v["false_positives"]["rate"]) for v in layers.values()),
         _pct(fp_full)]
    )  # fmt: skip
    rows.append(
        ["Latency overhead p95", "",
         *(_ms(v["latency_ms"]["overhead"]["p95"]) for v in layers.values()), _ms(p95_full)]
    )  # fmt: skip
    return rows


def _model_note(config: dict[str, Any]) -> str | None:
    if config.get("model_simulated"):
        return (
            f"Model: {config.get('model')}, a simulated model that obeys every instruction it "
            "reads. Unprotected ASR is near 100% by design; protected ASR measures what the "
            "gateway stops when the model can be fully hijacked, not how a real model behaves."
        )
    return None


def _fence(text: str) -> str:
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}json\n{text}\n{fence}"


def render_markdown(report: dict[str, Any]) -> str:
    run, config, summary = report["run"], report["config"], report["summary"]
    out = [
        f"# Red-team report: {run['target']}",
        "",
        f"Run `{run['id']}` · {run['status']} · started {run['started_at']} · seed {run['seed']}",
        "",
    ]
    note = _model_note(config)
    if note:
        out += [f"> {note}", ""]
    if run.get("error"):
        out += [f"**Run failed:** {run['error']}", ""]
    totals = summary.get("totals", {})
    fp = summary.get("false_positives", {})
    latency = summary.get("latency_ms", {})
    out += [
        "## Summary",
        "",
        f"- Attacks: {totals.get('attacks', 0)} ({totals.get('attack_probes', 0)} probes "
        f"with mutations), benign cases: {totals.get('benign', 0)}, errors: "
        f"{totals.get('errors', 0)}",
        f"- False positive rate: {_pct(fp.get('rate'))} ({len(fp.get('flagged', []))} of "
        f"{fp.get('n', 0)} benign cases flagged)",
        f"- Latency overhead: p50 {_ms(latency.get('overhead', {}).get('p50'))}, p95 "
        f"{_ms(latency.get('overhead', {}).get('p95'))} (benign set, {latency.get('n', 0)} pairs)",
        "",
        "## Attack success rate",
        "",
        "| Category | Unprotected | Protected | Block rate | Base (prot.) | Mutated (prot.) | n |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for name, row in _category_rows(summary):
        out.append(
            f"| {name} | {_pct(row['unprotected']['rate'])} | {_pct(row['protected']['rate'])} "
            f"| {_pct(row.get('block_rate'))} "
            f"| {_pct(row.get('base', {}).get('protected', {}).get('rate'))} "
            f"| {_pct(row.get('mutated', {}).get('protected', {}).get('rate'))} "
            f"| {row['protected']['n']} |"
        )
    layer_rows = _layer_table(summary, config)
    if layer_rows:
        out += ["", "## What each detection layer adds", ""]
        out.append("| " + " | ".join(layer_rows[0]) + " |")
        out.append("| " + " | ".join("---" for _ in layer_rows[0]) + " |")
        out += ["| " + " | ".join(row) + " |" for row in layer_rows[1:]]
    caught = summary.get("caught_by", {})
    out += ["", "## What caught the attacks", ""]
    for label, key in (("Layer", "layer"), ("Detector", "detector"), ("Stage", "intervention")):
        counts = caught.get(key, {})
        listed = ", ".join(f"{k}: {v}" for k, v in counts.items()) or "none"
        out.append(f"- {label}: {listed}")
    regression = summary.get("regression", {})
    out += ["", "## Regression", ""]
    if regression.get("previous_run_id"):
        out.append(
            f"Against run `{regression['previous_run_id']}` (tolerance "
            f"{_delta(regression.get('tolerance'))}):"
        )
        out.append("")
        for name, delta in regression.get("deltas", {}).items():
            flag = " **regressed**" if name in regression.get("regressed", []) else ""
            out.append(f"- {name}: {_delta(delta)}{flag}")
    else:
        out.append("No previous comparable run (same target, attack set, seed, and mutations).")
    if fp.get("flagged"):
        out += ["", "## Benign cases the gateway flagged", ""]
        out += [f"- {case}" for case in fp["flagged"]]
    out += ["", f"## Top failing attacks ({report['failing_total']} succeeded through the gateway)"]
    for item in report["top_failing"]:
        out += [
            "",
            f"### {item['attack_id']} ({item['variant']}, {item['category']})",
            "",
            _fence(json.dumps(item["transcript"], indent=2, ensure_ascii=False)),
        ]
    out += [
        "",
        "## Configuration",
        "",
        _fence(json.dumps(config, indent=2, ensure_ascii=False)),
        "",
    ]
    return "\n".join(out)


_CSS = """
:root{--bg:#ffffff;--fg:#1d2330;--muted:#5d6676;--line:#dde2ea;--card:#f6f8fb;
--bad:#c2410c;--good:#15803d;--bar-u:#9aa4b5;--bar-p:#2563eb}
@media (prefers-color-scheme:dark){:root{--bg:#12161d;--fg:#e6e9ef;--muted:#9aa4b5;
--line:#2a313d;--card:#1a2029;--bad:#fb923c;--good:#4ade80;--bar-u:#5d6676;--bar-p:#60a5fa}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:1040px;margin:0 auto;padding:24px 16px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 8px}
.muted{color:var(--muted)}.note{background:var(--card);border-left:3px solid var(--bar-p);
padding:8px 12px;margin:16px 0}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px}
.tile b{display:block;font-size:22px}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
.bar{height:8px;border-radius:4px;margin-top:3px}.u{background:var(--bar-u)}
.p{background:var(--bar-p)}.bad{color:var(--bad);font-weight:600}
.good{color:var(--good)}
pre{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:10px;
overflow-x:auto;font-size:12px;white-space:pre-wrap;word-break:break-word}
.scroll{overflow-x:auto}
"""


def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _bar(rate: float | None, cls: str) -> str:
    width = 0 if rate is None else round(rate * 100, 1)
    return f'<div class="bar {cls}" style="width:{width}%"></div>'


def render_html(report: dict[str, Any]) -> str:
    run, config, summary = report["run"], report["config"], report["summary"]
    totals = summary.get("totals", {})
    fp = summary.get("false_positives", {})
    latency = summary.get("latency_ms", {})
    overall = summary.get("asr", {}).get("overall", {})
    regression = summary.get("regression", {})
    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>Red-team report {_e(run['target'])}</title><style>{_CSS}</style></head>",
        "<body><main>",
        f"<h1>Red-team report: {_e(run['target'])}</h1>",
        f"<div class='muted'>Run {_e(run['id'])} · {_e(run['status'])} · started "
        f"{_e(run['started_at'])} · seed {_e(run['seed'])} · ruleset "
        f"{_e(config.get('ruleset_version'))}</div>",
    ]
    note = _model_note(config)
    if note:
        parts.append(f"<div class='note'>{_e(note)}</div>")
    if run.get("error"):
        parts.append(f"<p class='bad'>Run failed: {_e(run['error'])}</p>")
    tiles = [
        ("ASR without gateway", _pct(overall.get("unprotected", {}).get("rate"))),
        ("ASR with gateway", _pct(overall.get("protected", {}).get("rate"))),
        ("False positive rate", _pct(fp.get("rate"))),
        ("Latency overhead p95", _ms(latency.get("overhead", {}).get("p95"))),
    ]
    parts.append("<div class='tiles'>")
    parts += [f"<div class='tile'><span class='muted'>{_e(k)}</span><b>{_e(v)}</b></div>"
              for k, v in tiles]  # fmt: skip
    parts.append("</div>")
    parts.append(
        f"<p class='muted'>{_e(totals.get('attacks', 0))} attacks "
        f"({_e(totals.get('attack_probes', 0))} probes with mutations), "
        f"{_e(totals.get('benign', 0))} benign cases, {_e(totals.get('errors', 0))} errors.</p>"
    )
    parts += [
        "<h2>Attack success rate per category</h2><div class='scroll'><table>",
        "<tr><th>Category</th><th>Without gateway</th><th>With gateway</th>"
        "<th>Block rate</th><th>Base / mutated (with gateway)</th><th>n</th></tr>",
    ]
    for name, row in _category_rows(summary):
        unprotected, protected = row["unprotected"]["rate"], row["protected"]["rate"]
        base = row.get("base", {}).get("protected", {}).get("rate")
        mutated = row.get("mutated", {}).get("protected", {}).get("rate")
        parts.append(
            f"<tr><td>{_e(name)}</td><td>{_e(_pct(unprotected))}{_bar(unprotected, 'u')}</td>"
            f"<td>{_e(_pct(protected))}{_bar(protected, 'p')}</td>"
            f"<td>{_e(_pct(row.get('block_rate')))}</td>"
            f"<td>{_e(_pct(base))} / {_e(_pct(mutated))}</td>"
            f"<td>{_e(row['protected']['n'])}</td></tr>"
        )
    parts.append("</table></div>")
    layer_rows = _layer_table(summary, config)
    if layer_rows:
        parts.append("<h2>What each detection layer adds</h2><div class='scroll'><table><tr>")
        parts += [f"<th>{_e(cell)}</th>" for cell in layer_rows[0]]
        parts.append("</tr>")
        for cells in layer_rows[1:]:
            parts.append("<tr>" + "".join(f"<td>{_e(cell)}</td>" for cell in cells) + "</tr>")
        parts.append("</table></div>")
    caught = summary.get("caught_by", {})
    parts.append("<h2>What caught the attacks</h2><table>")
    for label, key in (("Layer", "layer"), ("Detector", "detector"), ("Stage", "intervention")):
        listed = ", ".join(f"{k}: {v}" for k, v in caught.get(key, {}).items()) or "none"
        parts.append(f"<tr><th>{_e(label)}</th><td>{_e(listed)}</td></tr>")
    parts.append("</table>")
    parts.append("<h2>Latency (benign set)</h2><table><tr><th></th><th>p50</th><th>p95</th></tr>")
    for label in ("unprotected", "protected", "overhead"):
        values = latency.get(label, {})
        parts.append(
            f"<tr><td>{_e(label)}</td><td>{_e(_ms(values.get('p50')))}</td>"
            f"<td>{_e(_ms(values.get('p95')))}</td></tr>"
        )
    parts.append("</table><h2>Regression</h2>")
    if regression.get("previous_run_id"):
        parts.append(
            f"<p class='muted'>Against run {_e(regression['previous_run_id'])}, tolerance "
            f"{_e(_delta(regression.get('tolerance')))}.</p><table>"
        )
        for name, delta in regression.get("deltas", {}).items():
            regressed = name in regression.get("regressed", [])
            cls = "bad" if regressed else "good"
            label = "regressed" if regressed else "ok"
            parts.append(
                f"<tr><td>{_e(name)}</td><td>{_e(_delta(delta))}</td>"
                f"<td class='{cls}'>{label}</td></tr>"
            )
        parts.append("</table>")
    else:
        parts.append(
            "<p class='muted'>No previous comparable run (same target, attack set, seed, "
            "and mutations).</p>"
        )
    if fp.get("flagged"):
        parts.append("<h2>Benign cases the gateway flagged</h2><ul>")
        parts += [f"<li>{_e(case)}</li>" for case in fp["flagged"]]
        parts.append("</ul>")
    parts.append(
        f"<h2>Top failing attacks</h2><p class='muted'>{_e(report['failing_total'])} attack "
        "probes succeeded through the gateway.</p>"
    )
    for item in report["top_failing"]:
        transcript = json.dumps(item["transcript"], indent=2, ensure_ascii=False)
        parts.append(
            f"<h3>{_e(item['attack_id'])} <span class='muted'>({_e(item['variant'])}, "
            f"{_e(item['category'])})</span></h3><pre>{_e(transcript)}</pre>"
        )
    config_text = json.dumps(config, indent=2, ensure_ascii=False)
    parts.append(f"<h2>Configuration</h2><pre>{_e(config_text)}</pre></main></body></html>")
    return "".join(parts)


def render(report: dict[str, Any], fmt: str) -> str:
    if fmt == "json":
        return json.dumps(report, indent=2, ensure_ascii=False)
    if fmt == "md":
        return render_markdown(report)
    if fmt == "html":
        return render_html(report)
    raise ValueError(f"format must be one of {', '.join(FORMATS)}")
