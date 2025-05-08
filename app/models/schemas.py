# Pydantic models from section 7.1
from pydantic import BaseModel, ConfigDict
from typing import Optional, List
from datetime import datetime

class ContainerBase(BaseModel):
    id: str # container short_id
    name: str
    image_id: str # image short_id from docker
    image_name: str # usually name:tag from docker
    status: str
    created_at: datetime # container created_at
    
    model_config = ConfigDict(from_attributes=True)

# New model for more detailed info from Docker
class DockerImageInfo(BaseModel):
    id: str # Full Docker Image ID (sha256:...)
    short_id: str # Short Docker Image ID
    tags: List[str] = []
    size: Optional[int] = None
    created_at: Optional[datetime] = None

class DockerContainerInfo(ContainerBase):
    # Inherits id, name, status, created_at from ContainerBase
    # image_id from ContainerBase will be the DockerImageInfo.short_id
    # image_name from ContainerBase will be the primary tag or short_id
    image_details: DockerImageInfo

class ContainerWithVulns(ContainerBase):
    # image_id here is the Docker short image ID, inherited from ContainerBase
    # This will be used by the template for the scan button, and should match Image.id in DB
    last_scanned: Optional[datetime] = None
    latest_scan_id: Optional[int] = None # Added for linking to details page
    critical_count: Optional[int] = None
    high_count: Optional[int] = None
    medium_count: Optional[int] = None
    low_count: Optional[int] = None
    negligible_count: Optional[int] = None
    unknown_count: Optional[int] = None

    # Fields for image analysis
    is_rootless: Optional[bool] = None
    is_shellless: Optional[bool] = None
    is_distroless: Optional[bool] = None
    analysis_error: Optional[str] = None # To store any error message from image analysis

    # No model_config here, will inherit from ContainerBase if it was to be ORM mapped
    # but this is for display, so it's fine.

class VulnerabilityModel(BaseModel):
    vulnerability_id: str
    severity: str
    package_name: str
    installed_version: str
    fixed_version: Optional[str] = None
    description: Optional[str] = None
    
    model_config = ConfigDict(from_attributes=True)

class ScanResult(BaseModel):
    scan_id: int
    image_id: str
    scan_time: datetime
    scan_status: str
    vulnerabilities: List[VulnerabilityModel]
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    negligible_count: int
    unknown_count: int

    # Add image analysis details relevant to the scan details page
    image_name: Optional[str] = None # Add image name/tag for context
    is_rootless: Optional[bool] = None
    is_shellless: Optional[bool] = None
    is_distroless: Optional[bool] = None
    analysis_error: Optional[str] = None
    found_shell_path: Optional[str] = None
    found_package_manager_path: Optional[str] = None
    distribution_info: Optional[str] = None # Added distribution info

# New schema for vulnerability counts
class VulnerabilityCountsSchema(BaseModel):
    scan_id: int
    critical: int
    high: int
    medium: int
    low: int
    negligible: int
    unknown: int

    model_config = ConfigDict(from_attributes=True) 