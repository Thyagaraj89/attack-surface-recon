import asyncio

import dns.asyncresolver
import dns.exception

from recon_pipeline.config import settings
from recon_pipeline.utils.logger import setup_logger

logger = setup_logger(__name__)


async def _resolve_record(
    resolver: dns.asyncresolver.Resolver,
    hostname: str,
    record_type: str,
) -> list[str]:
    try:
        answers = await resolver.resolve(hostname, record_type)
        return sorted({answer.to_text() for answer in answers})
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        logger.warning("DNS timeout resolving %s record for %s", record_type, hostname)
        return []
    except Exception as exc:
        logger.warning("Unexpected DNS error for %s (%s): %s", hostname, record_type, exc)
        return []


async def _resolve_hostname(
    hostname: str,
    semaphore: asyncio.Semaphore,
) -> tuple[str, list[str]]:
    async with semaphore:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = settings.dns_timeout
        resolver.timeout = settings.dns_timeout

        a_records = await _resolve_record(resolver, hostname, "A")
        aaaa_records = await _resolve_record(resolver, hostname, "AAAA")

        ips = sorted(set(a_records + aaaa_records))

        if ips:
            logger.info("Resolved %s -> %s", hostname, ", ".join(ips))
        else:
            logger.info("No DNS resolution for %s", hostname)

        return hostname, ips


async def resolve_subdomains(subdomains: list[str]) -> dict[str, list[str]]:
    if not subdomains:
        logger.info("No hostnames provided for DNS resolution")
        return {}

    logger.info("Starting DNS resolution for %d hostnames", len(subdomains))

    semaphore = asyncio.Semaphore(settings.dns_concurrency)
    tasks = [_resolve_hostname(hostname, semaphore) for hostname in sorted(set(subdomains))]
    results = await asyncio.gather(*tasks)

    resolved_hosts = {hostname: ips for hostname, ips in results if ips}

    logger.info("Resolved %d/%d hostnames", len(resolved_hosts), len(set(subdomains)))
    return resolved_hosts