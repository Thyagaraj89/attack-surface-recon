import re
from pathlib import Path
from urllib.parse import urlparse


def normalize_domain(domain: str) -> str:
    candidate = domain.strip()

    if not candidate:
        raise ValueError("Domain cannot be empty")

    if "://" in candidate:
        parsed = urlparse(candidate)
        candidate = parsed.netloc or parsed.path

    candidate = candidate.strip().lower().rstrip(".").rstrip("/")

    if "/" in candidate:
        candidate = candidate.split("/", 1)[0]

    if ":" in candidate:
        candidate = candidate.split(":", 1)[0]

    return candidate


def sanitize_filename(value: str) -> str:
    normalized = normalize_domain(value)
    sanitized = re.sub(r"[^a-zA-Z0-9._-]+", "_", normalized)
    return sanitized.replace(".", "_").strip("_")


def load_targets_from_file(file_path: str) -> list[str]:
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Target file not found: {file_path}")

    lines = path.read_text(encoding="utf-8").splitlines()
    return [normalize_domain(line) for line in lines if line.strip()]