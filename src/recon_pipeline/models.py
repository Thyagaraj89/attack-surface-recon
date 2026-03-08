from typing import Optional

from pydantic import BaseModel, Field


class TargetInput(BaseModel):
    domain: str = Field(..., description="Root domain to scan")


class ScanMetadata(BaseModel):
    target: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None


class HTTPFinding(BaseModel):
    hostname: str
    attempted_url: str
    final_url: str
    scheme: str
    port: int
    status_code: int
    title: Optional[str] = None
    server: Optional[str] = None
    content_type: Optional[str] = None


class ScanResult(BaseModel):
    metadata: ScanMetadata
    subdomains: list[str] = Field(default_factory=list)
    resolved_hosts: dict[str, list[str]] = Field(default_factory=dict)
    open_ports: dict[str, list[int]] = Field(default_factory=dict)
    http_findings: list[HTTPFinding] = Field(default_factory=list)