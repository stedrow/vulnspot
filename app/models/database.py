# SQLAlchemy models from section 7.1
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, create_engine, Boolean
from sqlalchemy.orm import declarative_base, relationship, sessionmaker # Corrected import
from datetime import datetime

Base = declarative_base()

class Container(Base):
    __tablename__ = "containers"
    
    id = Column(String, primary_key=True)
    name = Column(String)
    image_id = Column(String)
    image_name = Column(String)
    created_at = Column(DateTime)
    status = Column(String)
    last_scanned = Column(DateTime, nullable=True)

class Image(Base):
    __tablename__ = "images"
    
    id = Column(String, primary_key=True)
    name = Column(String)
    tag = Column(String)
    size = Column(Integer, nullable=True)
    created_at = Column(DateTime, nullable=True)
    scans = relationship("Scan", back_populates="image")

    # New fields for image analysis results
    is_rootless = Column(Boolean, nullable=True)
    is_shellless = Column(Boolean, nullable=True)
    is_distroless = Column(Boolean, nullable=True)
    image_analysis_error = Column(String, nullable=True)
    last_analyzed_at = Column(DateTime, nullable=True)

    # New fields for specific paths found
    found_shell_path = Column(String, nullable=True)
    found_package_manager_path = Column(String, nullable=True)
    distribution_info = Column(String, nullable=True)

class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    image_id = Column(String, ForeignKey("images.id"))
    scan_time = Column(DateTime, default=datetime.utcnow)
    scan_status = Column(String)
    
    image = relationship("Image", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan")
    counts = relationship("VulnerabilityCounts", back_populates="scan", uselist=False)

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    vulnerability_id = Column(String)
    severity = Column(String)
    package_name = Column(String)
    installed_version = Column(String)
    fixed_version = Column(String, nullable=True) # Added nullable=True as per Pydantic model
    description = Column(String, nullable=True) # Added nullable=True as per Pydantic model
    
    scan = relationship("Scan", back_populates="vulnerabilities")

class VulnerabilityCounts(Base):
    __tablename__ = "vulnerability_counts"
    
    scan_id = Column(Integer, ForeignKey("scans.id"), primary_key=True)
    critical = Column(Integer, default=0)
    high = Column(Integer, default=0)
    medium = Column(Integer, default=0)
    low = Column(Integer, default=0)
    negligible = Column(Integer, default=0)
    unknown = Column(Integer, default=0)
    
    scan = relationship("Scan", back_populates="counts") 