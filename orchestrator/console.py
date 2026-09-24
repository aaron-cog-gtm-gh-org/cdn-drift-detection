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
    fetch(provider, kind, domain, url)   # one line per document pulled
    schema_block(schema)          # dry-run only
    prompt_block(domain, prompt)  # dry-run only
    sessions_live()               # context manager wrapping phase 7
"""
import sys
from contextlib import nullcontext
from pathlib import Path


class PlainReporter:
    """Byte-for-byte compatible with the original print() calls."""

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

    def equivalences(self, domain, report):
        for e in report.get("equivalent_but_different", []):
            print(f"  ~equiv    {e['provider']:10s} {e['field']}")

    def remediation(self, route, domain, session_id, url=None):
        print(f"  remediation {route} for {domain}: {session_id}")

    def deferred(self, domain, field, note):
        print(f"  deferred ({note}): {domain} {field}")

    def summary(self, run_id, reports, artifacts_dir):
        pass

    def warn(self, text):
        print(text, file=sys.stderr)

    def error(self, text):
        print(text, file=sys.stderr)

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

    def __init__(self, console=None):
        from rich.console import Console
        self.console = console or Console()
        self._err = console or Console(stderr=True)
        self._status = {}          # domain -> {"status": str, "acus": ...}
        self._status_order = []    # stable row order
        self._live = None

    # -- generic lines --------------------------------------------------------

    def phase(self, index, total, title, subtitle=None):
        from rich.rule import Rule
        self.console.print()
        self.console.print(Rule(f"[bold cyan][{index}/{total}] {title}",
                                style="cyan"))
        if subtitle:
            self.console.print(f"  [dim]{subtitle}[/]")

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
        self.console.print(f"    {domain}  [bold]{kind}[/]  "
                           f"[dim]GET {url}[/]")

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
        t = Table(show_lines=False, pad_edge=False, box=None)
        t.add_column("domain", style="bold")
        t.add_column("status")
        t.add_column("ACUs", justify="right")
        style = {"exit": "green", "error": "bold red",
                 "running": "yellow", "claimed": "yellow",
                 "resuming": "yellow", "suspended": "magenta"}
        for d in self._status_order:
            s = self._status[d]
            st = s["status"] or "?"
            t.add_row(d, f"[{style.get(st, 'white')}]{st}[/]", str(s["acus"]))
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

    def findings(self, domain, report):
        from rich.table import Table
        s = report["summary"]
        self.console.print(
            f"\n[bold]{domain}[/] — verdict: "
            f"[bold]{report['verdict']}[/] "
            f"[dim]({s['findings_total']} findings, "
            f"{s['fields_compared']} fields compared)[/]")
        if not report["findings"]:
            return
        t = Table(show_lines=False, pad_edge=False)
        for col in ("severity", "provider", "field", "equivalence", "route"):
            t.add_column(col)
        for f in report["findings"]:
            sev = f["severity"]
            t.add_row(f"[{SEVERITY_STYLE.get(sev, 'white')}]{sev}[/]",
                      f["provider"], f["field"], f["equivalence"],
                      f["remediation_route"])
        self.console.print(t)

    def equivalences(self, domain, report):
        eq = report.get("equivalent_but_different", [])
        if not eq:
            return
        self.console.print("  [bold]equivalent — same meaning, "
                           "different representation (not drift):[/]")
        for e in eq:
            reason = e.get("why_equivalent")
            line = f"  [dim]·[/] {e['field']} [dim]({e['provider']})[/]"
            if reason:
                line += f" — [dim]{reason}[/]"
            self.console.print(line)

    def remediation(self, route, domain, session_id, url=None):
        self.console.print(f"  [{route}] {domain} → [bold]{session_id}[/]"
                           + (f"  [link={url}][dim underline]{url}[/link][/]"
                              if url else ""))

    def deferred(self, domain, field, note):
        self.console.print(f"  [yellow]deferred[/] {domain} "
                           f"[bold]{field}[/] — [dim]{note}[/]")

    def summary(self, run_id, reports, artifacts_dir):
        from rich.table import Table
        self.console.print()
        self.console.rule("[bold cyan]summary", style="cyan")
        t = Table(show_lines=False, pad_edge=False)
        for col in ("domain", "verdict", "findings"):
            t.add_column(col)
        sev_totals = {}
        for d, rep in reports.items():
            t.add_row(d, rep["verdict"],
                      str(rep["summary"]["findings_total"]))
            for sev, n in (rep["summary"].get("by_severity") or {}).items():
                sev_totals[sev] = sev_totals.get(sev, 0) + n
        self.console.print(t)
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

    def schema_block(self, schema):
        import json
        from rich.panel import Panel
        from rich.syntax import Syntax
        self.console.print(Panel(
            Syntax(json.dumps(schema, indent=2), "json"),
            title="structured output schema", border_style="dim"))

    def prompt_block(self, domain, prompt):
        from rich.panel import Panel
        self.console.print(Panel(prompt, title=f"detection prompt: {domain}",
                                 border_style="dim"))


def make_reporter(demo=None, plain=None, console=None):
    """--demo forces rich, --plain forces flat; default rich iff tty."""
    if plain:
        return PlainReporter()
    if demo or sys.stdout.isatty():
        return DemoReporter(console=console)
    return PlainReporter()
