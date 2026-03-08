import asyncio
import json
from typing import Any

import httpx

from recon_pipeline.config import settings
from recon_pipeline.utils.logger import setup_logger

logger = setup_logger(__name__)

CRTSH_URL = "https://crt.sh/"


def _normalize_subdomain(name: str, root_domain: str) -> str | None:
    candidate = name.strip().lower().rstrip(".")

    if not candidate:
        return None

    if candidate.startswith("*."):
        candidate = candidate[2:]

    if candidate.endswith(f".{root_domain}"):
        return candidate

    return None


def _extract_subdomains_from_entry(entry: dict[str, Any], root_domain: str) -> set[str]:
    results: set[str] = set()
    raw_name = entry.get("name_value")

    if not raw_name:
        return results

    for line in str(raw_name).splitlines():
        normalized = _normalize_subdomain(line, root_domain)
        if normalized:
            results.add(normalized)

    return results


async def _fetch_crtsh_json(
    client: httpx.AsyncClient,
    query: str,
    retries: int = 3,
    backoff_seconds: float = 1.5,
) -> list[dict[str, Any]]:
    params = {
        "q": query,
        "output": "json",
    }

    headers = {
        "User-Agent": settings.user_agent,
    }

    last_error: Exception | None = None

    for attempt in range(1, retries + 1):
        try:
            response = await client.get(CRTSH_URL, params=params, headers=headers)

            if response.status_code >= 500:
                raise httpx.HTTPStatusError(
                    f"crt.sh server error: {response.status_code}",
                    request=response.request,
                    response=response,
                )

            response.raise_for_status()

            try:
                data = response.json()
            except json.JSONDecodeError as exc:
                logger.warning("Failed to decode crt.sh JSON for query %s: %r", query, exc)
                return []

            if not isinstance(data, list):
                logger.warning("Unexpected crt.sh response format for query: %s", query)
                return []

            return [entry for entry in data if isinstance(entry, dict)]

        except (httpx.HTTPError, httpx.TimeoutException) as exc:
            last_error = exc
            logger.warning(
                "crt.sh request attempt %d/%d failed for query %s: %r",
                attempt,
                retries,
                query,
                exc,
            )
            if attempt < retries:
                await asyncio.sleep(backoff_seconds * attempt)

    logger.warning("All crt.sh attempts failed for query %s: %r", query, last_error)
    return []


async def enumerate_subdomains(domain: str) -> list[str]:
    logger.info("Starting passive subdomain enumeration for domain: %s", domain)

    discovered: set[str] = set()

    queries = [
        f"%.{domain}",
        domain,
    ]

    async with httpx.AsyncClient(
        timeout=settings.http_timeout,
        follow_redirects=True,
    ) as client:
        for query in queries:
            logger.info("Querying crt.sh with pattern: %s", query)
            entries = await _fetch_crtsh_json(client, query=query)

            for entry in entries:
                discovered.update(_extract_subdomains_from_entry(entry, domain))

    results = sorted(discovered)
    logger.info("Discovered %d unique subdomains for domain: %s", len(results), domain)
    return results