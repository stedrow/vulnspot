from pathlib import Path
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from database import get_db, init_db
# ScanResult schema no longer needed here as view_logic returns it or None
import uvicorn
from datetime import datetime

# Import API routers
from api import containers as containers_router
from api import images as images_router
from api import scans as scans_router

# Import new service for view logic
from services.view_logic import get_container_display_data, get_full_scan_details

app = FastAPI(title="VulnSpot Docker Container Vulnerability Scanner")

# Determine paths relative to this main.py file
MAIN_PY_DIR = Path(__file__).resolve().parent
PROJECT_ROOT_DIR = MAIN_PY_DIR.parent

# Mount static files and templates
app.mount("/static", StaticFiles(directory=MAIN_PY_DIR / "static"), name="static")
templates = Jinja2Templates(directory=MAIN_PY_DIR / "templates")

# Initialize database
@app.on_event("startup")
def startup_event():
    init_db()

# Include API routers
app.include_router(containers_router.router, prefix="/api", tags=["containers"])
app.include_router(images_router.router, prefix="/api", tags=["images"])
app.include_router(scans_router.router, prefix="/api", tags=["scans"])

# UI Endpoints
@app.get("/", name="root")
async def root(request: Request, db: Session = Depends(get_db)):
    """
    Serves the main dashboard page.
    Fetches running containers, processes their image info, and gets scan status.
    """
    try:
        container_data_for_template = get_container_display_data(db)
    except Exception as e:
        print(f"Error getting container display data: {e}")
        # Optionally, pass an error message to the template or raise HTTPException
        container_data_for_template = [] 
        # Could add a message to request: `request.state.error_message = str(e)`
        # and display it in index.html

    return templates.TemplateResponse("index.html", {"request": request, "containers": container_data_for_template})

@app.get("/scan-details/{scan_id}", name="view_scan_details")
async def view_scan_details(request: Request, scan_id: int, db: Session = Depends(get_db)):
    """
    Serves the scan details page for a given scan ID.
    """
    scan_result_data = get_full_scan_details(db, scan_id)
    if not scan_result_data:
        raise HTTPException(status_code=404, detail=f"Scan details for scan ID {scan_id} not found.")
    
    return templates.TemplateResponse("scan_details.html", {"request": request, "scan_result": scan_result_data})

# Main function
if __name__ == "__main__":
    # When running `python app/main.py` (e.g. via Makefile's old local dev target if it existed),
    # Python adds project root to sys.path (because app/ is a child).
    # Uvicorn's `app.main:app` when run from project root (e.g. docker CMD) is also fine.
    # The direct `python app/main.py` execution in Makefile for run-dev will run this block.
    # Uvicorn should be able to find "main:app" relative to `app/main.py` location.
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True) 