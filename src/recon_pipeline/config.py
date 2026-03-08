from pydantic import BaseModel, Field


class Settings(BaseModel):
    app_name: str = "Attack Surface Recon Pipeline"
    version: str = "0.1.0"

    dns_timeout: float = 3.0
    http_timeout: float = 10.0
    port_scan_timeout: float = 1.5

    dns_concurrency: int = 100
    http_concurrency: int = 50
    port_scan_concurrency: int = 200

    common_ports: list[int] = Field(
        default_factory=lambda: [80, 443, 8080, 8443, 22, 21, 25]
    )

    output_dir: str = "output"
    report_dir: str = "reports"
    database_path: str = "data/recon_pipeline.db"

    user_agent: str = "AttackSurfaceRecon/0.1.0"


settings = Settings()