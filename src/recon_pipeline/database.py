from pathlib import Path

from recon_pipeline.config import settings


def initialize_database() -> None:
    """
    Ensure the SQLite database parent directory exists.

    Full SQLAlchemy table setup will be added in the storage phase.
    """
    db_path = Path(settings.database_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)