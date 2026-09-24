"""Reporters for run_detection — one pipeline, two narrations.

`run_detection.main` never prints directly; it calls methods on a reporter.
`PlainReporter` reproduces the original flat output byte-for-byte (stdout and
stderr exactly as before), so anything piping the CLI — tests included — sees
no change. `DemoReporter` renders the same events with rich: numbered phase
banners, a findings table with colour-coded severities, a live session-status
table, and clickable artifact/session links.

The interface both classes implement:

    phase(index, total, title, subtitle=None)
    step(text)
    artifact(label, path, sha=None, nbytes=None)
    kv(label, value)
    session_created(domain, session_id, url)
    session_status(domain, status, acus)
    findings(domain, report)
    equivalences(domain, report)
    remediation(route, domain, session_id, url)
    deferred(domain, field, note)
    summary(run_id, reports, artifacts_dir)
    warn(text) / error(text)
    golden_state(domains, roles, shas, mapping_version)   # phase 1
    fetch_stream()               # cm yielding obj with .add(domain, kind, url)
    artifact_table(rows)         # rows of (name, path, sha256, nbytes)
    fetch(provider, kind, domain, url)   # one line per document pulled
    schema_summary(schema)        # compact contract view (dry-run default)
    schema_block(schema)          # full schema dump (--show-schema)
    prompt_block(domain, prompt)  # dry-run only
    sessions_live()               # context manager wrapping phase 7
    pause(weight=1.0)             # demo pacing; no-op in plain output
"""
import sys
import time
from contextlib import nullcontext
from pathlib import Path


class _NoopFetch:
    def add(self, domain, kind, url):
        pass


class PlainReporter:
    """Byte-for-byte compatible with the original print() calls."""

    def golden_state(self, domains, roles, shas, mapping_version):
        for d in domains:
            print(f"  {d}: golden_sha={shas[d][:12]}")
        print(f"mapping_version={mapping_version}")

    def fetch_stream(self):
        return nullcontext(_NoopFetch())

    def artifact_table(self, rows):
        pass

    def pause(self, weight=1.0):
        pass

    def phase(self, index, total, title, subtitle=None):
        pass

    def step(self, text):
        print(text)

    def artifact(self, label, path, sha=None, nbytes=None):
        pass

    def kv(self, label, value):
        print(f"{label}={value}")

    def fetch(self, provider, kind, domain, url):
        pass

    def session_created(self, domain, session_id, url):
        print(f"  created {domain}: {session_id}")

    def session_status(self, domain, status, acus=None):
        print(f"    {domain}: {status}", file=sys.stderr)

    def findings(self, domain, report):
        print(f"\n== {domain} — verdict: {report['verdict']} "
              f"({report['summary']['findings_total']} findings, "
              f"{report['summary']['fields_compared']} fields compared) ==")
        for f in report["findings"]:
            print(f"  {f['severity']:9s} {f['provider']:10s} {f['field']:36s} "
                  f"{f['equivalence']:22s} -> {f['remediation_route']}")
        if report["verdict"] == "inconclusive":
            print(f"  INCONCLUSIVE: {report.get('notes', '')}")

    def equivalences(self, domain, report, full=False):
        for e in report.get("equivalent_but_different", []):
            print(f"  ~equiv    {e['provider']:10s} {e['field']}")

    def remediation(self, route, domain, session_id, url=None):
        print(f"  remediation {route} for {domain}: {session_id}")

    def deferred(self, domain, field, note):
        print(f"  deferred ({note}): {domain} {field}")

    def coverage_warning(self, domain, missing, unknown, unlisted):
        if missing:
            print(f"  COVERAGE GAP ({domain}): never reviewed: "
                  f"{', '.join(missing)}", file=sys.stderr)
        if unknown:
            print(f"  COVERAGE GAP ({domain}): reviewed ids not in mapping: "
                  f"{', '.join(unknown)}", file=sys.stderr)
        if unlisted:
            print(f"  COVERAGE GAP ({domain}): reported but not in "
                  f"fields_reviewed: {', '.join(unlisted)}",
                  file=sys.stderr)

    def summary(self, run_id, reports, artifacts_dir, coverage=None):
        inc = [d for d, r in reports.items()
               if r["verdict"] == "inconclusive"]
        if inc:
            print(f"  INCONCLUSIVE: {len(inc)} domain(s) could not be "
                  f"compared: {', '.join(inc)}", file=sys.stderr)
        if coverage:
            print(f"  COVERAGE GAPS on {len(coverage)} domain(s): "
                  f"{', '.join(coverage)}", file=sys.stderr)

    def warn(self, text):
        print(text, file=sys.stderr)

    def error(self, text):
        print(text, file=sys.stderr)

    def schema_summary(self, schema):
        # plain output stays byte-identical: the old dump, unchanged
        self.schema_block(schema)

    def schema_block(self, schema):
        import json
        print("\n--- structured output schema ---")
        print(json.dumps(schema, indent=2))

    def prompt_block(self, domain, prompt):
        print(f"\n--- detection prompt: {domain} ---")
        print(prompt)

    def sessions_live(self):
        return nullcontext()


SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
}


class DemoReporter:
    """Rich rendering of the same events — banners, tables, live status."""

    TOTAL_PHASES = 9

    def __init__(self, console=None, pace=0.0):
        from rich.console import Console
        self.console = console or Console()
        self._err = console or Console(stderr=True)
        self.pace = pace
        self._status = {}          # domain -> {"status": str, "acus": ...}
        self._status_order = []    # stable row order
        self._live = None

    def pause(self, weight=1.0):
        if self.pace > 0:
            time.sleep(self.pace * weight)

    # -- generic lines --------------------------------------------------------

    def phase(self, index, total, title, subtitle=None):
        from rich.rule import Rule
        self.console.print()
        self.console.print(Rule(f"[bold cyan][{index}/{total}] {title}",
                                style="cyan"))
        if subtitle:
            self.console.print(f"  [dim]{subtitle}[/]")
        self.pause(1.5)

    def golden_state(self, domains, roles, shas, mapping_version):
        from rich.table import Table
        t = Table(show_lines=False, pad_edge=True)
        t.add_column("domain", style="bold")
        t.add_column("role")
        t.add_column("golden_sha", style="magenta")
        for d in domains:
            t.add_row(d, roles.get(d, ""), shas[d][:12])
        self.console.print(t)
        self.kv("mapping_version", mapping_version)
        self.pause()

    def fetch_stream(self):
        """A live-growing fetch table; .add lands a row, pauses, repaints."""
        from rich.live import Live
        from rich.table import Table
        reporter = self

        class _Stream:
            def __enter__(self):
                reporter._fetch_rows = []
                reporter._fetch_live = Live(
                    _table(), console=reporter.console, refresh_per_second=4)
                reporter._fetch_live.__enter__()
                return self

            def __exit__(self, *exc):
                reporter._fetch_live.__exit__(*exc)
                reporter._fetch_live = None
                return False

            def add(self, domain, kind, url):
                reporter._fetch_rows.append((domain, kind, url))
                reporter._fetch_live.update(_table())
                reporter.pause()

        def _table():
            t = Table(show_lines=False, pad_edge=True)
            t.add_column("domain", style="bold", no_wrap=True)
            t.add_column("document")
            t.add_column("request", style="dim", overflow="ellipsis",
                         no_wrap=True)
            for domain, kind, url in reporter._fetch_rows:
                t.add_row(domain, kind, f"GET {url}" if url else "")
            return t

        return _Stream()

    def artifact_table(self, rows):
        from rich.live import Live
        from rich.table import Table
        t = Table(show_lines=False, pad_edge=True)
        t.add_column("file", no_wrap=True)
        t.add_column("sha256", style="magenta", no_wrap=True)
        t.add_column("size", justify="right", no_wrap=True)
        with Live(t, console=self.console, refresh_per_second=4) as live:
            for name, path, sha, nbytes in rows:
                t.add_row(f"[link=file://{path}]{name}[/link]",
                          str(sha)[:12] if sha else "",
                          f"{nbytes} B" if nbytes is not None else "")
                live.update(t)
                self.pause()

    def step(self, text):
        self.console.print(text)

    def artifact(self, label, path, sha=None, nbytes=None):
        bits = [f"  [bold]{label}[/]  [link=file://{path}]{path}[/link]"]
        extras = []
        if sha:
            extras.append(f"sha256 {str(sha)[:12]}")
        if nbytes is not None:
            extras.append(f"{nbytes} bytes")
        if extras:
            bits.append(f"[dim]({', '.join(extras)})[/]")
        self.console.print("".join(bits))

    def kv(self, label, value):
        self.console.print(f"  [bold]{label}[/]  {value}")

    def fetch(self, provider, kind, domain, url):
        pass  # fetch lines render via fetch_table

    # -- sessions ---------------------------------------------------------------

    def session_created(self, domain, session_id, url):
        self.console.print(
            f"  {domain}  [bold]{session_id}[/]  "
            f"[link={url}][dim underline]{url}[/link][/]")
        self._status_order.append(domain)
        self._status[domain] = {"status": "new", "acus": "—"}

    def session_status(self, domain, status, acus=None):
        if domain not in self._status:
            self._status_order.append(domain)
        self._status[domain] = {"status": status,
                                "acus": acus if acus is not None else "—"}
        if self._live is not None:
            self._live.update(self._status_table())

    def _status_table(self):
        from rich.table import Table
        t = Table(show_lines=False, pad_edge=True, box=None)
        t.add_column("domain", style="bold")
        t.add_column("status")
        t.add_column("ACUs", justify="right")
        style = {"exit": "green", "error": "bold red",
                 "running": "yellow", "claimed": "yellow",
                 "resuming": "yellow", "suspended": "magenta"}
        for d in self._status_order:
            s = self._status[d]
            st = s["status"] or "?"
            acus = (f"{s['acus']:.2f}"
                    if isinstance(s["acus"], (int, float))
                    else str(s["acus"]))  # display rounding only
            t.add_row(d, f"[{style.get(st, 'white')}]{st}[/]", acus)
        return t

    def sessions_live(self):
        from rich.live import Live
        reporter = self

        class _Live:
            def __enter__(self):
                reporter._live = Live(reporter._status_table(),
                                      console=reporter.console,
                                      refresh_per_second=4)
                reporter._live.__enter__()
                return reporter

            def __exit__(self, *exc):
                reporter._live.__exit__(*exc)
                reporter._live = None
                return False

        return _Live()

    # -- reports ----------------------------------------------------------------

    VERDICT_STYLE = {"drift_detected": "bold red", "in_sync": "bold green",
                     "inconclusive": "bold red"}

    def findings(self, domain, report):
        from rich.rule import Rule
        from rich.table import Table
        s = report["summary"]
        verdict = report["verdict"]
        self.console.print()
        self.console.print(
            Rule(f"[bold]{domain}[/] — verdict: "
                 f"[{self.VERDICT_STYLE.get(verdict, 'white')}]{verdict}[/] "
                 f"[dim]({s['findings_total']} findings, "
                 f"{s['fields_compared']} fields compared)[/]",
                 style="dim", align="left"))
        if verdict == "inconclusive":
            self.console.print(
                f"  [bold red]INCONCLUSIVE[/] "
                f"[red]{report.get('notes', '')}[/]")
        if not report["findings"]:
            return
        t = Table(show_lines=False, pad_edge=True)
        for col in ("severity", "provider", "field", "equivalence", "route"):
            t.add_column(col)
        order = {s_: i for i, s_ in enumerate(SEVERITY_STYLE)}
        ranked = sorted(report["findings"],
                        key=lambda f: order.get(f["severity"], 99))
        for f in ranked:
            sev = f["severity"]
            t.add_row(f"[{SEVERITY_STYLE.get(sev, 'white')}]{sev}[/]",
                      f["provider"], f["field"], f["equivalence"],
                      f["remediation_route"])
        self.console.print(t)

    def equivalences(self, domain, report, full=False):
        eq = report.get("equivalent_but_different", [])
        if not eq:
            return
        from rich.table import Table
        self.console.print(
            f"  [bold]{len(eq)} fields equivalent but expressed "
            f"differently — not drift[/]"
            + ("" if full else " [dim](--full-equivalences for reasons)[/]"))
        FW = 42  # longest "field (provider)" is 41
        avail = max(self.console.width - FW - 7, 20)
        t = Table(show_lines=False, pad_edge=True, show_header=False)
        t.add_column("field", no_wrap=True, style="bold", width=FW)
        t.add_column("reason", style="dim", no_wrap=not full,
                     overflow=None if not full else "fold")
        for e in eq:
            reason = e.get("why_equivalent", "")
            if not full and len(reason) > avail:
                reason = reason[:avail - 1].rstrip() + "…"
            t.add_row(f"{e['field']} [dim]({e['provider']})[/]", reason)
        self.console.print(t)

    def remediation(self, route, domain, session_id, url=None):
        self.console.print(f"  [{route}] {domain} → [bold]{session_id}[/]"
                           + (f"  [link={url}][dim underline]{url}[/link][/]"
                              if url else ""))

    def deferred(self, domain, field, note):
        self.console.print(f"  [yellow]deferred[/] {domain} "
                           f"[bold]{field}[/] — [dim]{note}[/]")

    def coverage_warning(self, domain, missing, unknown, unlisted):
        for label, ids in (("never reviewed", missing),
                           ("reviewed ids not in mapping", unknown),
                           ("reported but not in fields_reviewed", unlisted)):
            if ids:
                self.console.print(
                    f"  [bold red]COVERAGE GAP[/] {domain} — "
                    f"{label}: [bold]{', '.join(ids)}[/]")

    def summary(self, run_id, reports, artifacts_dir, coverage=None):
        from rich.table import Table
        self.console.print()
        self.console.rule("[bold cyan]summary", style="cyan")
        t = Table(show_lines=False, pad_edge=True)
        for col in ("domain", "verdict", "findings"):
            t.add_column(col)
        sev_totals = {}
        for d, rep in reports.items():
            t.add_row(d, rep["verdict"],
                      str(rep["summary"]["findings_total"]))
            for sev, n in (rep["summary"].get("by_severity") or {}).items():
                sev_totals[sev] = sev_totals.get(sev, 0) + n
        self.console.print(t)
        inc = [d for d, r in reports.items()
               if r["verdict"] == "inconclusive"]
        if inc:
            self.console.print(
                f"  [bold red]{len(inc)} domain(s) INCONCLUSIVE[/] "
                f"[red]({', '.join(inc)}) — comparison did not complete[/]")
        if coverage:
            self.console.print(
                f"  [bold red]COVERAGE GAPS on {len(coverage)} domain(s)[/] "
                f"[red]({', '.join(coverage)}) — fields were never "
                f"reviewed or ids did not match the mapping[/]")
        if sev_totals:
            line = "  ".join(
                f"[{SEVERITY_STYLE.get(s, 'white')}]{s}: {n}[/]"
                for s, n in sorted(sev_totals.items(),
                                   key=lambda kv: list(SEVERITY_STYLE).index(kv[0])))
            self.console.print("  totals by severity: " + line)
        self.console.print(f"  run {run_id}")
        self.console.print(f"  artifacts → "
                           f"[link=file://{artifacts_dir}]{artifacts_dir}[/link]")

    def warn(self, text):
        self._err.print(f"[yellow]WARN[/] {text}")

    def error(self, text):
        self._err.print(f"[red]ERROR[/] {text}")

    # -- dry-run ----------------------------------------------------------------

    def schema_summary(self, schema):
        """Compact contract view — no 250-line dump in front of an audience."""
        from rich.table import Table
        props = schema["properties"]
        fprops = props["findings"]["items"]["properties"]
        t = Table(show_lines=False, pad_edge=True,
                  title="structured output contract", title_justify="left")
        t.add_column("part", style="bold", no_wrap=True)
        t.add_column("value")
        t.add_row("required", ", ".join(schema["required"]))
        t.add_row("verdict", " | ".join(props["verdict"]["enum"]))
        t.add_row("finding fields",
                  ", ".join(props["findings"]["items"]["required"]))
        t.add_row("severity", " | ".join(fprops["severity"]["enum"]))
        t.add_row("equivalence", " | ".join(fprops["equivalence"]["enum"]))
        t.add_row("route",
                  " | ".join(fprops["remediation_route"]["enum"]))
        self.console.print(t)

    def schema_block(self, schema):
        import json
        from rich.panel import Panel
        from rich.syntax import Syntax
        self.console.print(Panel(
            Syntax(json.dumps(schema, indent=2), "json", word_wrap=True),
            title="structured output schema", border_style="dim"))

    def prompt_block(self, domain, prompt):
        from rich.panel import Panel
        self.console.print(Panel(prompt, title=f"detection prompt: {domain}",
                                 border_style="dim"))


def make_reporter(demo=None, plain=None, console=None, pace=None):
    """--demo forces rich, --plain forces flat; default rich iff tty.

    `pace` is demo-output pacing in seconds; None means the stage default
    0.35s, 0 disables. PlainReporter ignores pacing entirely.
    """
    if plain:
        return PlainReporter()
    if demo or sys.stdout.isatty():
        return DemoReporter(console=console,
                            pace=0.35 if pace is None else pace)
    return PlainReporter()
