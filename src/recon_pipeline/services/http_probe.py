import asyncio
import re
from urllib.parse import urlparse

import httpx

from recon_pipeline.config import settings
from recon_pipeline.models import HTTPFinding
from recon_pipeline.utils.logger import setup_logger

logger = setup_logger(__name__)


def _extract_title(html: str) -> str | None:
    match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if match:
        return " ".join(match.group(1).split()).strip()
    return None


def _build_candidate_urls(hostname: str, open_ports: list[int]) -> list[tuple[str, str, int]]:
    candidates: list[tuple[str, str, int]] = []

    if 80 in open_ports:
        candidates.append((f"http://{hostname}", "http", 80))
    if 443 in open_ports:
        candidates.append((f"https://{hostname}", "https", 443))
    if 8080 in open_ports:
        candidates.append((f"http://{hostname}:8080", "http", 8080))
    if 8443 in open_ports:
        candidates.append((f"https://{hostname}:8443", "https", 8443))

    return candidates


async def _probe_url(
    client: httpx.AsyncClient,
    hostname: str,
    url: str,
    scheme: str,
    port: int,
    semaphore: asyncio.Semaphore,
) -> HTTPFinding | None:
    async with semaphore:
        try:
            response = await client.get(url)

            title = None
            content_type = response.headers.get("content-type")
            if content_type and "text/html" in content_type.lower():
                title = _extract_title(response.text)

            finding = HTTPFinding(
                hostname=hostname,
                attempted_url=url,
                final_url=str(response.url),
                scheme=scheme,
                port=port,
                status_code=response.status_code,
                title=title,
                server=response.headers.get("server"),
                content_type=content_type,
            )

            logger.info("HTTP probe success %s -> %s (%s)", url, response.url, response.status_code)
            return finding

        except httpx.RequestError:
            return None
        except Exception as exc:
            logger.warning("HTTP probe error for %s -> %r", url, exc)
            return None


def _deduplicate_findings(findings: list[HTTPFinding]) -> list[HTTPFinding]:
    unique: dict[tuple[str, str, int, str | None], HTTPFinding] = {}

    for finding in findings:
        key = (
            finding.hostname,
            finding.final_url.rstrip("/"),
            finding.status_code,
            finding.title,
        )
        if key not in unique:
            unique[key] = finding

    return sorted(
        unique.values(),
        key=lambda item: (item.hostname, item.port, item.final_url),
    )


async def probe_http_services(
    resolved_hosts: dict[str, list[str]],
    open_ports: dict[str, list[int]],
) -> list[HTTPFinding]:
    if not resolved_hosts:
        logger.info("No hosts available for HTTP probing")
        return []

    logger.info("Starting HTTP probing for %d hosts", len(resolved_hosts))

    findings: list[HTTPFinding] = []
    semaphore = asyncio.Semaphore(settings.http_concurrency)

    async with httpx.AsyncClient(
        timeout=settings.http_timeout,
        follow_redirects=True,
        headers={"User-Agent": settings.user_agent},
    ) as client:
        tasks = []

        for hostname in sorted(resolved_hosts.keys()):
            ports = open_ports.get(hostname, [])
            for url, scheme, port in _build_candidate_urls(hostname, ports):
                tasks.append(_probe_url(client, hostname, url, scheme, port, semaphore))

        results = await asyncio.gather(*tasks)

    for result in results:
        if result is not None:
            findings.append(result)

    deduplicated = _deduplicate_findings(findings)
    logger.info("HTTP probing complete: %d unique services discovered", len(deduplicated))

    return deduplicated