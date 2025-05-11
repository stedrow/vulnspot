import subprocess
import json
from datetime import datetime
# Adjusting import paths based on the new structure
from models.database import Scan, Vulnerability, VulnerabilityCounts 
from models.schemas import ScanResult, VulnerabilityModel
from sqlalchemy.orm import Session # For type hinting
from logger import logger

# The spec defines get_db_session() but it's not standard FastAPI `Depends` pattern.
# For now, assuming it provides a SQLAlchemy session directly.
# If it's meant to be used with `Depends(get_db_session)`, 
# then scanner functions might need to be API endpoints or refactored.

def scan_image(image_id: str, db: Session, image_tar_path: str, image_name_with_tag: str = None):
    """
    Scans an image using Grype from a tarball and processes the results.
    The image_name_with_tag is optional and used for logging/context if provided.
    """
    scan_target = f"docker-archive:{image_tar_path}"
    log_name = image_name_with_tag if image_name_with_tag else image_tar_path

    # print(f"Executing Grype scan for target: {scan_target} (Image ID: {image_id}, Original name: {log_name})")
    logger.debug(f"Executing Grype scan for target: {scan_target} (Image ID: {image_id}, Original name: {log_name})")
    cmd = ["grype", scan_target, "-o", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except FileNotFoundError:
        print(f"Error: Grype command not found. Ensure Grype is installed and in PATH. Attempted to scan: {log_name}")
        raise Exception(f"Grype command not found. Could not scan {log_name}") # Re-raise for handling upstream
    except subprocess.CalledProcessError as e:
        print(f"Grype scan failed for {log_name} with exit code {e.returncode}: {e.stderr}")
        # Attempt to save a failed scan status if possible
        try:
            existing_scan = db.query(Scan).filter(Scan.image_id == image_id).order_by(Scan.scan_time.desc()).first()
            if existing_scan and existing_scan.scan_status != "failed":
                existing_scan.scan_status = "failed"
                existing_scan.scan_details = f"Grype failed: {e.stderr[:1024]}" # Store some error detail
                db.commit()
            elif not existing_scan:
                # Create a new scan record indicating failure if one doesn't exist from a previous step
                failed_scan = Scan(
                    image_id=image_id,
                    scan_time=datetime.utcnow(),
                    scan_status="failed",
                    scan_details=f"Grype failed: {e.stderr[:1024]}"
                )
                db.add(failed_scan)
                db.commit()
        except Exception as db_error:
            print(f"Additionally, failed to update/create scan status in DB for {log_name} after Grype failure: {db_error}")
            db.rollback()
        raise Exception(f"Grype scan failed for {log_name}: {e.stderr}")

    scan_data = json.loads(result.stdout)
    
    # Create new scan
    new_scan = Scan(
        image_id=image_id,
        scan_time=datetime.utcnow(),
        scan_status="processing" # Initial status
    )
    db.add(new_scan)
    db.flush()  # To get the scan_id for associations
    
    # Process vulnerabilities and counts
    vulnerabilities_db_models, counts = process_scan_result(scan_data, new_scan.id)
    
    # Add vulnerability counts
    vuln_counts_db_model = VulnerabilityCounts(
        scan_id=new_scan.id,
        critical=counts['critical'],
        high=counts['high'],
        medium=counts['medium'],
        low=counts['low'],
        negligible=counts['negligible'],
        unknown=counts['unknown']
    )
    db.add(vuln_counts_db_model)
    
    # Add vulnerabilities
    for vuln_db_model in vulnerabilities_db_models:
        db.add(vuln_db_model)
    
    new_scan.scan_status = "completed" # Update status after processing
    db.commit()
    
    # Prepare Pydantic models for the response
    vulnerabilities_pydantic_models = [VulnerabilityModel.from_orm(v) for v in vulnerabilities_db_models]
    
    return ScanResult(
        scan_id=new_scan.id,
        image_id=image_id,
        scan_time=new_scan.scan_time,
        scan_status=new_scan.scan_status,
        vulnerabilities=vulnerabilities_pydantic_models,
        critical_count=counts['critical'],
        high_count=counts['high'],
        medium_count=counts['medium'],
        low_count=counts['low'],
        negligible_count=counts['negligible'],
        unknown_count=counts['unknown']
    )

def process_scan_result(scan_data, scan_id):
    vulnerabilities_db_models = []
    counts = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'negligible': 0,
        'unknown': 0
    }
    
    for match in scan_data.get('matches', []):
        vuln_info = match.get('vulnerability', {})
        # Grype severity can be title case or lowercase, normalize to lowercase
        severity = vuln_info.get('severity', 'Unknown').lower()
        
        # Ensure severity is one of the expected keys, otherwise map to 'unknown'
        if severity not in counts:
            counts['unknown'] += 1
        else:
            counts[severity] += 1
        
        description_parts = [] 
        if vuln_info.get('description'):
            description_parts.append(vuln_info.get('description'))

        fixed_version = None
        if "fix" in vuln_info and "versions" in vuln_info["fix"] and vuln_info["fix"]["versions"]:
            fixed_version = vuln_info["fix"]["versions"][0]
            # The spec had remediation in description, separating it to fixed_version as per DB model
            # remediation_text = f"Update to version {fixed_version} or later."
            # description_parts.append(remediation_text)
        
        vulnerabilities_db_models.append(Vulnerability(
            scan_id=scan_id,
            vulnerability_id=vuln_info.get('id', 'N/A'), # Provide default if ID missing
            severity=severity if severity in counts else 'unknown', # ensure stored severity is valid
            package_name=match.get('artifact', {}).get('name', 'N/A'),
            installed_version=match.get('artifact', {}).get('version', 'N/A'),
            fixed_version=fixed_version,
            description=" ".join(description_parts).strip() or None # Ensure description is not empty string
        ))
    
    return vulnerabilities_db_models, counts 

# Severity levels for sorting
SEVERITY_ORDER = {
    'critical': 0,
    'high': 1,
    'medium': 2,
    'low': 3,
    'negligible': 4,
    'unknown': 5
} 