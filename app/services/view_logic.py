from sqlalchemy.orm import Session, joinedload
from services.docker import get_running_containers
from models.schemas import ContainerWithVulns, DockerContainerInfo, DockerImageInfo, ScanResult, VulnerabilityModel
from models.database import Image as DBImage, Scan as DBScan, VulnerabilityCounts as DBVulnerabilityCounts, Vulnerability as DBVulnerability
from datetime import datetime

def get_container_display_data(db: Session) -> list[ContainerWithVulns]:
    """
    Fetches running Docker containers, upserts their image information into the DB,
    and enriches them with the latest scan status and image analysis results from the DB.
    """
    raw_docker_containers: list[DockerContainerInfo] = get_running_containers(db)
    display_data_list: list[ContainerWithVulns] = []

    for dc_info in raw_docker_containers:
        image_detail: DockerImageInfo = dc_info.image_details
        db_image_id = image_detail.short_id

        # 1. Upsert Image to DB (or fetch existing)
        db_image = db.query(DBImage).filter(DBImage.id == db_image_id).first()
        if not db_image:
            image_name_parts = dc_info.image_name.split(':', 1)
            image_repo = image_name_parts[0]
            image_tag = image_name_parts[1] if len(image_name_parts) > 1 else 'latest'
            if '@sha256:' in image_repo:
                image_tag = dc_info.image_name.split('@sha256:')[1][:12]
                if image_detail.tags:
                    first_tag_parts = image_detail.tags[0].split(':',1)
                    image_repo = first_tag_parts[0]
                    image_tag = first_tag_parts[1] if len(first_tag_parts) > 1 else 'latest'
            
            db_image = DBImage(
                id=db_image_id, 
                name=image_repo,
                tag=image_tag,
                size=image_detail.size,
                created_at=image_detail.created_at
                # Analysis fields will be populated by the API scan endpoint when a scan is triggered
            )
            db.add(db_image)
            try:
                db.commit()
                db.refresh(db_image)
            except Exception as e: 
                db.rollback()
                print(f"Error committing new image {db_image_id}: {e}. Fetching existing.")
                db_image = db.query(DBImage).filter(DBImage.id == db_image_id).first()
                if not db_image: 
                    print(f"Failed to upsert image {db_image_id}. Skipping container {dc_info.id}")
                    continue 
        
        # 2. Fetch Latest Scan Info for this image (existing logic)
        latest_scan = (
            db.query(DBScan)
            .options(joinedload(DBScan.counts))
            .filter(DBScan.image_id == db_image_id)
            .filter(DBScan.scan_status == "completed")
            .order_by(DBScan.scan_time.desc())
            .first()
        )

        vuln_counts_data = {}
        last_scanned_time = None
        current_latest_scan_id = None

        if latest_scan:
            last_scanned_time = latest_scan.scan_time
            current_latest_scan_id = latest_scan.id
            if latest_scan.counts:
                counts_record: DBVulnerabilityCounts = latest_scan.counts
                vuln_counts_data = {
                    "critical_count": counts_record.critical,
                    "high_count": counts_record.high,
                    "medium_count": counts_record.medium,
                    "low_count": counts_record.low,
                    "negligible_count": counts_record.negligible,
                    "unknown_count": counts_record.unknown,
                }

        # 3. Construct ContainerWithVulns for display, including analysis results from db_image
        container_display = ContainerWithVulns(
            id=dc_info.id, 
            name=dc_info.name,
            image_id=db_image_id, 
            image_name=dc_info.image_name, 
            status=dc_info.status,
            created_at=dc_info.created_at, 
            last_scanned=last_scanned_time,
            latest_scan_id=current_latest_scan_id,
            # Get analysis results from the db_image object
            is_rootless=db_image.is_rootless if db_image else None,
            is_shellless=db_image.is_shellless if db_image else None,
            is_distroless=db_image.is_distroless if db_image else None,
            analysis_error=db_image.image_analysis_error if db_image else None,
            **vuln_counts_data
        )
        display_data_list.append(container_display)
    
    return display_data_list 

def get_full_scan_details(db: Session, scan_id: int) -> ScanResult:
    """Retrieves detailed information for a specific scan, including vulnerabilities, counts, and image analysis results."""
    db_scan = (
        db.query(DBScan)
        .options(
            joinedload(DBScan.image), # Eager load image details
            joinedload(DBScan.vulnerabilities),
            joinedload(DBScan.counts)
        )
        .filter(DBScan.id == scan_id)
        .first()
    )

    if not db_scan:
        return None 

    if not db_scan.image:
        # Handle case where image might be missing (though unlikely)
        print(f"Warning: Image data missing for scan ID {scan_id}")
        # Return minimal scan result or raise error? For now, return with Nones
        pydantic_vulnerabilities = [VulnerabilityModel.from_orm(v) for v in db_scan.vulnerabilities]
        counts = db_scan.counts
        return ScanResult(
            scan_id=db_scan.id, image_id=db_scan.image_id, scan_time=db_scan.scan_time, scan_status=db_scan.scan_status,
            vulnerabilities=pydantic_vulnerabilities,
            critical_count=counts.critical if counts else 0, high_count=counts.high if counts else 0,
            medium_count=counts.medium if counts else 0, low_count=counts.low if counts else 0,
            negligible_count=counts.negligible if counts else 0, unknown_count=counts.unknown if counts else 0
            # Image details will be None
        )

    db_image = db_scan.image
    pydantic_vulnerabilities = [
        VulnerabilityModel.from_orm(v) for v in db_scan.vulnerabilities
    ]

    counts = db_scan.counts
    critical_count = counts.critical if counts else 0
    high_count = counts.high if counts else 0
    medium_count = counts.medium if counts else 0
    low_count = counts.low if counts else 0
    negligible_count = counts.negligible if counts else 0
    unknown_count = counts.unknown if counts else 0

    image_name_tag = f"{db_image.name}:{db_image.tag}" if db_image.tag else db_image.name

    return ScanResult(
        scan_id=db_scan.id,
        image_id=db_scan.image_id,
        scan_time=db_scan.scan_time,
        scan_status=db_scan.scan_status,
        vulnerabilities=pydantic_vulnerabilities,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        negligible_count=negligible_count,
        unknown_count=unknown_count,
        # Add analysis details from the image
        image_name=image_name_tag,
        is_rootless=db_image.is_rootless,
        is_shellless=db_image.is_shellless,
        is_distroless=db_image.is_distroless,
        analysis_error=db_image.image_analysis_error,
        found_shell_path=db_image.found_shell_path,
        found_package_manager_path=db_image.found_package_manager_path,
        distribution_info=db_image.distribution_info
    ) 