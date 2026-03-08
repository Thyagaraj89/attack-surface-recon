import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from recon_pipeline.database import initialize_database
from recon_pipeline.models import ScanMetadata, ScanResult
from recon_pipeline.reporter import print_summary, write_json_report, write_markdown_report
from recon_pipeline.services.dns_resolver import resolve_subdomains
from recon_pipeline.services.fingerprint import enrich_http_findings
from recon_pipeline.services.http_probe import probe_http_services
from recon_pipeline.services.port_scan import scan_common_ports
from recon_pipeline.services.subdomain_enum import enumerate_subdomains
from recon_pipeline.utils.helpers import load_targets_from_file, normalize_domain, sanitize_filename
from recon_pipeline.utils.logger import setup_logger

app = typer.Typer(help="Attack Surface Recon Pipeline CLI")
console = Console()
logger = setup_logger(__name__)


async def run_pipeline(target: str) -> ScanResult:
    logger.info("Starting scan for target: %s", target)

    started_at = datetime.utcnow().isoformat()

    subdomains = await enumerate_subdomains(target)
    hostnames_to_resolve = sorted(set(subdomains + [target]))

    resolved_hosts = await resolve_subdomains(hostnames_to_resolve)
    open_ports = await scan_common_ports(resolved_hosts)
    http_findings = await probe_http_services(resolved_hosts, open_ports)
    http_findings = enrich_http_findings(http_findings)

    finished_at = datetime.utcnow().isoformat()

    return ScanResult(
        metadata=ScanMetadata(
            target=target,
            started_at=started_at,
            finished_at=finished_at,
        ),
        subdomains=subdomains,
        resolved_hosts=resolved_hosts,
        open_ports=open_ports,
        http_findings=http_findings,
    )


@app.command()
def main(
    domain: Optional[str] = typer.Argument(None, help="Single target domain or URL"),
    input_file: Optional[Path] = typer.Option(
        None,
        "--input-file",
        "-i",
        help="File containing target domains",
    ),
) -> None:
    """
    Run reconnaissance pipeline against a single domain or a list of domains.
    """
    if not domain and not input_file:
        raise typer.BadParameter("Provide either a domain or --input-file")

    if domain and input_file:
        raise typer.BadParameter("Provide only one of: domain or --input-file")

    initialize_database()

    if domain:
        targets = [normalize_domain(domain)]
    else:
        targets = load_targets_from_file(str(input_file))

    console.print(f"[bold blue]Targets loaded:[/bold blue] {len(targets)}")

    for target in targets:
        result = asyncio.run(run_pipeline(target))

        print_summary(result)

        safe_name = sanitize_filename(target)
        json_path = write_json_report(result, f"{safe_name}.json")
        md_path = write_markdown_report(result, f"{safe_name}.md")

        console.print(f"[green]JSON report:[/green] {json_path}")
        console.print(f"[green]Markdown report:[/green] {md_path}")


if __name__ == "__main__":
    app()