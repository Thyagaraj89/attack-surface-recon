from pathlib import Path

from rich.console import Console

from recon_pipeline.config import settings
from recon_pipeline.models import ScanResult

console = Console()


def print_summary(result: ScanResult) -> None:
    open_port_total = sum(len(ports) for ports in result.open_ports.values())

    console.print(f"[bold green]Scan complete for:[/bold green] {result.metadata.target}")
    console.print(f"Subdomains discovered: {len(result.subdomains)}")
    console.print(f"Resolved hosts: {len(result.resolved_hosts)}")
    console.print(f"Open port findings: {open_port_total}")
    console.print(f"HTTP findings: {len(result.http_findings)}")


def write_json_report(result: ScanResult, output_name: str) -> Path:
    output_dir = Path(settings.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    output_path = output_dir / output_name
    output_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    return output_path


def write_markdown_report(result: ScanResult, output_name: str) -> Path:
    report_dir = Path(settings.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    report_path = report_dir / output_name
    open_port_total = sum(len(ports) for ports in result.open_ports.values())

    lines = [
        f"# Recon Report: {result.metadata.target}",
        "",
        "## Scan Metadata",
        f"- Started: {result.metadata.started_at}",
        f"- Finished: {result.metadata.finished_at}",
        "",
        "## Summary",
        f"- Subdomains discovered: {len(result.subdomains)}",
        f"- Resolved hosts: {len(result.resolved_hosts)}",
        f"- Open port findings: {open_port_total}",
        f"- HTTP findings: {len(result.http_findings)}",
        "",
        "## Discovered Subdomains",
    ]

    if result.subdomains:
        for subdomain in result.subdomains:
            lines.append(f"- {subdomain}")
    else:
        lines.append("- None")

    lines.extend(["", "## Resolved Hosts"])
    if result.resolved_hosts:
        for hostname, ips in result.resolved_hosts.items():
            lines.append(f"- **{hostname}**: {', '.join(ips)}")
    else:
        lines.append("- None")

    lines.extend(["", "## Open Ports"])
    if result.open_ports:
        for hostname, ports in result.open_ports.items():
            port_text = ", ".join(str(port) for port in ports) if ports else "None"
            lines.append(f"- **{hostname}**: {port_text}")
    else:
        lines.append("- None")

    lines.extend(["", "## HTTP Findings"])
    if result.http_findings:
        for finding in result.http_findings:
            lines.extend(
                [
                    f"### {finding.hostname}",
                    f"- Attempted URL: `{finding.attempted_url}`",
                    f"- Final URL: `{finding.final_url}`",
                    f"- Scheme: `{finding.scheme}`",
                    f"- Port: `{finding.port}`",
                    f"- Status Code: `{finding.status_code}`",
                    f"- Title: `{finding.title or 'N/A'}`",
                    f"- Server: `{finding.server or 'N/A'}`",
                    f"- Content-Type: `{finding.content_type or 'N/A'}`",
                    "",
                ]
            )
    else:
        lines.append("- None")

    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path