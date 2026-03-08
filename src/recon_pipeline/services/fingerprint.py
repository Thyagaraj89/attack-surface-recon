from recon_pipeline.models import HTTPFinding
from recon_pipeline.utils.logger import setup_logger

logger = setup_logger(__name__)


def enrich_http_findings(http_findings: list[HTTPFinding]) -> list[HTTPFinding]:
    logger.info("Fingerprint enrichment placeholder for %d HTTP findings", len(http_findings))
    return http_findings