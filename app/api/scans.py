from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, joinedload
from typing import List
from datetime import datetime # Added datetime

from database import get_db
from models.schemas import ScanResult, VulnerabilityModel, VulnerabilityCountsSchema # Added VulnerabilityCountsSchema
from models.database import Image as DBImage, Scan as DBScan, Vulnerability as DBVulnerability, VulnerabilityCounts as DBVulnerabilityCounts # Added DB models
from services.scanner import scan_image as service_scan_image # Renamed to avoid conflict
from services.image_analyzer import ContainerAnalyzer # Added ContainerAnalyzer import
# from app.models.database import Image as DBImage, Scan as DBScan # SQLAlchemy models
# from app.services.scanner import scan_image as service_scan_image
# Schemas for listing scans, vulnerabilities, counts will be needed

router = APIRouter()

@router.post("/scan/{image_id}", response_model=ScanResult)
def trigger_image_scan(image_id: str, db: Session = Depends(get_db)):
    """Triggers a new vulnerability scan and image analysis for the given image ID."""
    db_image = db.query(DBImage).filter(DBImage.id == image_id).first()
    if not db_image:
        raise HTTPException(status_code=404, detail=f"Image with ID '{image_id}' not found in database.")
    
    image_name_for_analysis_and_grype = f"{db_image.name}:{db_image.tag}" if db_image.tag else db_image.name

    # 1. Perform Image Analysis (Rootless, Shellless, Distroless)
    try:
        print(f"Attempting to analyze image characteristics: {image_name_for_analysis_and_grype} (DB ID: {image_id})")
        analyzer = ContainerAnalyzer()
        analysis_results = analyzer.analyze_image(image_name_for_analysis_and_grype)
        
        # Save boolean results
        db_image.is_rootless = analysis_results.get("is_rootless")
        db_image.is_shellless = analysis_results.get("is_shellless")
        db_image.is_distroless = analysis_results.get("is_distroless")
        db_image.image_analysis_error = analysis_results.get("error")
        db_image.last_analyzed_at = datetime.utcnow()
        # Save specific paths found (or None)
        db_image.found_shell_path = analysis_results.get("details", {}).get("found_shell_path")
        db_image.found_package_manager_path = analysis_results.get("details", {}).get("found_package_manager_path")
        # Save distribution info
        db_image.distribution_info = analysis_results.get("details", {}).get("distribution_info")
        
        db.commit()
        print(f"Image analysis results for {image_id} saved to DB.")
    except Exception as e_analyze:
        db.rollback() # Rollback analysis changes if error occurs
        print(f"Error during image analysis for {image_id} ({image_name_for_analysis_and_grype}): {e_analyze}")
        db_image.image_analysis_error = f"Analyzer failed: {str(e_analyze)}" 
        db_image.last_analyzed_at = datetime.utcnow() 
        db_image.found_shell_path = None 
        db_image.found_package_manager_path = None
        db_image.distribution_info = None # Ensure distro info is None on error
        try:
            db.commit()
        except Exception as e_commit_err:
            db.rollback()
            print(f"Failed to commit analysis error to DB: {e_commit_err}")

    # 2. Perform Vulnerability Scan (Grype)
    try:
        print(f"Attempting to scan image with Grype: {image_name_for_analysis_and_grype} (DB ID: {image_id})")
        scan_result_data = service_scan_image(image_name_with_tag=image_name_for_analysis_and_grype, image_id=db_image.id, db=db)
        # service_scan_image is expected to commit its own transaction for scan, vulnerabilities, counts.
        return scan_result_data
    except FileNotFoundError as e_grype_fnf: 
        print(f"Grype command not found during scan trigger: {e_grype_fnf}")
        raise HTTPException(status_code=500, detail="Scanner tool (Grype) not found on server.")
    except Exception as e_grype:
        print(f"Error during Grype scan for image {image_id} ({image_name_for_analysis_and_grype}): {e_grype}")
        # The Grype scan failed, but image analysis might have succeeded.
        # The page will reload, and view_logic will pick up whatever data is available.
        # We need to return something that matches ScanResult or raise an appropriate HTTP error for the Grype part.
        # If Grype fails, we don't have a ScanResult to return. 
        # It's better to raise HTTPException as the primary purpose of this endpoint was the scan.
        raise HTTPException(status_code=500, detail=f"Failed to scan image {image_name_for_analysis_and_grype} with Grype. Error: {str(e_grype)}")

@router.get("/scans") # Add response_model for List[ScanOverviewSchema] or similar
def list_all_scans(db: Session = Depends(get_db)):
    # scans = db.query(DBScan).options(joinedload(DBScan.image)).order_by(DBScan.scan_time.desc()).all()
    # return scans # Convert to Pydantic models
    raise HTTPException(status_code=501, detail="Endpoint not fully implemented")

@router.get("/scans/{scan_id}", response_model=ScanResult)
def get_scan_details(scan_id: int, db: Session = Depends(get_db)):
    """Retrieves detailed information for a specific scan, including vulnerabilities and counts."""
    db_scan = (
        db.query(DBScan)
        .options(
            joinedload(DBScan.image), # Eager load image details
            joinedload(DBScan.vulnerabilities), # Eager load vulnerabilities
            joinedload(DBScan.counts) # Eager load vulnerability counts
        )
        .filter(DBScan.id == scan_id)
        .first()
    )

    if not db_scan:
        raise HTTPException(status_code=404, detail=f"Scan with ID {scan_id} not found.")

    if not db_scan.image:
        # This case should ideally not happen if DB integrity is maintained
        raise HTTPException(status_code=500, detail=f"Image data missing for scan ID {scan_id}.")

    # Convert SQLAlchemy Vulnerability models to Pydantic VulnerabilityModel
    pydantic_vulnerabilities = [
        VulnerabilityModel.from_orm(v) for v in db_scan.vulnerabilities
    ]

    # Prepare counts
    critical_count = db_scan.counts.critical if db_scan.counts else 0
    high_count = db_scan.counts.high if db_scan.counts else 0
    medium_count = db_scan.counts.medium if db_scan.counts else 0
    low_count = db_scan.counts.low if db_scan.counts else 0
    negligible_count = db_scan.counts.negligible if db_scan.counts else 0
    unknown_count = db_scan.counts.unknown if db_scan.counts else 0

    return ScanResult(
        scan_id=db_scan.id,
        image_id=db_scan.image_id, # This is the short image ID from DBImage.id
        scan_time=db_scan.scan_time,
        scan_status=db_scan.scan_status,
        vulnerabilities=pydantic_vulnerabilities,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        negligible_count=negligible_count,
        unknown_count=unknown_count,
    )

@router.get("/vulnerabilities/{scan_id}", response_model=List[VulnerabilityModel])
def get_vulnerabilities_for_scan(scan_id: int, db: Session = Depends(get_db)):
    """Retrieves a list of vulnerabilities for a specific scan."""
    # Check if scan exists first to give a 404 if scan_id is invalid
    db_scan = db.query(DBScan).filter(DBScan.id == scan_id).first()
    if not db_scan:
        raise HTTPException(status_code=404, detail=f"Scan with ID {scan_id} not found.")

    # Fetch vulnerabilities associated with the scan
    vulnerabilities = (
        db.query(DBVulnerability)
        .filter(DBVulnerability.scan_id == scan_id)
        .all()
    )
    
    # Convert to Pydantic models
    return [VulnerabilityModel.from_orm(v) for v in vulnerabilities]

@router.get("/vulnerability-counts/{scan_id}", response_model=VulnerabilityCountsSchema)
def get_vulnerability_counts(scan_id: int, db: Session = Depends(get_db)):
    """Retrieves the vulnerability counts for a specific scan."""
    counts = (
        db.query(DBVulnerabilityCounts)
        .filter(DBVulnerabilityCounts.scan_id == scan_id)
        .first()
    )

    if not counts:
        # Before raising 404, check if the scan itself exists to provide a more accurate error
        db_scan = db.query(DBScan.id).filter(DBScan.id == scan_id).first()
        if not db_scan:
            raise HTTPException(status_code=404, detail=f"Scan with ID {scan_id} not found.")
        # If scan exists but counts don't, it might be an issue or scan not fully processed.
        # For now, we can return all zeros if the user expects a counts object for any valid scan ID.
        # However, the schema requires scan_id, so returning a default with the given scan_id is better.
        # Or, if counts are integral to a scan, this situation could be a 500 error.
        # Let's assume a scan might legitimately have no counts row if it failed before counts were made.
        # The `ScanResult` model returns 0 if counts don't exist, so we can be consistent.
        # But this endpoint is specifically for the counts object.
        # A strict interpretation means if the DBVulnerabilityCounts row doesn't exist, it's a 404 for *counts*.
        raise HTTPException(status_code=404, detail=f"Vulnerability counts for scan ID {scan_id} not found. The scan might exist but has no associated counts record.")

    return VulnerabilityCountsSchema.from_orm(counts)

# Placeholder: The main.py already has a /api/scan/{image_id} POST endpoint.
# This file should define the router that main.py will include.
# The one in main.py should be removed and this router used. 