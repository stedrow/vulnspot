import subprocess
import json
from datetime import datetime
# Adjusting import paths based on the new structure
from models.database import Scan, Vulnerability, VulnerabilityCounts 
from models.schemas import ScanResult, VulnerabilityModel
from sqlalchemy.orm import Session # For type hinting

# The spec defines get_db_session() but it's not standard FastAPI `Depends` pattern.
# For now, assuming it provides a SQLAlchemy session directly.
# If it's meant to be used with `Depends(get_db_session)`, 
# then scanner functions might need to be API endpoints or refactored.

def scan_image(image_name_with_tag: str, image_id: str, db: Session):
    cmd = ["grype", image_name_with_tag, "-o", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True) # Added check=True
    except FileNotFoundError:
        # Grype not found, log and raise or return error status
        print("Error: Grype command not found. Ensure Grype is installed and in PATH.")
        # Consider how to report this: raise specific exception or return an error ScanResult
        # For now, re-raising to make it explicit that scan failed fundamentally.
        raise Exception("Grype command not found")
    except subprocess.CalledProcessError as e:
        # Grype executed but returned a non-zero exit code (scan error, or other grype issue)
        print(f"Grype scan failed with exit code {e.returncode}: {e.stderr}")
        # Update scan status to failed in DB if a scan record was started
        # For now, directly raising an exception
        raise Exception(f"Grype scan failed: {e.stderr}")

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