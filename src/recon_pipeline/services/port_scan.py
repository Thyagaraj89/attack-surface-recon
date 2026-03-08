import asyncio

from recon_pipeline.config import settings
from recon_pipeline.utils.logger import setup_logger

logger = setup_logger(__name__)


async def _scan_port(ip: str, port: int, semaphore: asyncio.Semaphore) -> tuple[int, bool]:
    async with semaphore:
        try:
            connect_coro = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(
                connect_coro,
                timeout=settings.port_scan_timeout,
            )

            writer.close()
            await writer.wait_closed()

            logger.info("Open port detected on %s:%d", ip, port)
            return port, True

        except (TimeoutError, asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return port, False
        except Exception as exc:
            logger.warning("Unexpected port scan error for %s:%d -> %r", ip, port, exc)
            return port, False


async def _scan_ip_ports(ip: str, ports: list[int], semaphore: asyncio.Semaphore) -> list[int]:
    tasks = [_scan_port(ip, port, semaphore) for port in ports]
    results = await asyncio.gather(*tasks)

    open_ports = sorted([port for port, is_open in results if is_open])

    if open_ports:
        logger.info("Open ports for %s: %s", ip, ", ".join(map(str, open_ports)))
    else:
        logger.info("No open common ports found for %s", ip)

    return open_ports


async def scan_common_ports(resolved_hosts: dict[str, list[str]]) -> dict[str, list[int]]:
    if not resolved_hosts:
        logger.info("No resolved hosts provided for port scanning")
        return {}

    logger.info(
        "Starting port scan for %d resolved hosts across %d common ports",
        len(resolved_hosts),
        len(settings.common_ports),
    )

    semaphore = asyncio.Semaphore(settings.port_scan_concurrency)
    results: dict[str, list[int]] = {}

    for hostname, ips in resolved_hosts.items():
        host_open_ports: set[int] = set()

        for ip in sorted(set(ips)):
            ip_open_ports = await _scan_ip_ports(ip, settings.common_ports, semaphore)
            host_open_ports.update(ip_open_ports)

        results[hostname] = sorted(host_open_ports)

    hosts_with_open_ports = sum(1 for ports in results.values() if ports)
    logger.info("Port scanning complete: %d/%d hosts with open ports", hosts_with_open_ports, len(results))

    return results