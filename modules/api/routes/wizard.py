"""
Scan Wizard API routes.
Multi-step guided workflow for creating security scans.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Dict, List
from sqlalchemy.orm import Session

from modules.api.auth import get_current_user
from modules.api.models import User, Scan
from modules.api.database import get_db
from modules.api.scan_wizard import (
    TargetDetector,
    ScanTemplates,
    ScanWizardValidator,
    ScanWizardBuilder,
    TargetType,
)
from modules.infra import get_queue

router = APIRouter(prefix="/api/wizard", tags=["wizard"])


# Request/Response models

class TargetDetectionRequest(BaseModel):
    """Request model for target detection."""
    target: str = Field(..., min_length=1, max_length=1000, description="Target to analyze")


class TargetDetectionResponse(BaseModel):
    """Response model for target detection."""
    target: str
    type: str  # TargetType
    normalized: str
    confidence: float
    metadata: Dict


class TemplateListResponse(BaseModel):
    """Single template in list."""
    id: str
    name: str
    description: str
    duration: str
    modules_count: int
    depth: str


class TemplateDetailsResponse(BaseModel):
    """Detailed template information."""
    id: str
    name: str
    description: str
    duration: str
    enabled_modules: List[str]
    depth: str
    timeout_minutes: int
    parallelization: int
    default_config: Dict


class ValidateWizardRequest(BaseModel):
    """Request model for wizard validation."""
    target: str = Field(..., description="Target to validate")
    template: str = Field(..., description="Template name")
    custom_config: Optional[Dict] = None


class ValidateWizardResponse(BaseModel):
    """Response model for wizard validation."""
    is_valid: bool
    errors: Dict[str, str]
    target_info: Optional[TargetDetectionResponse] = None
    template_info: Optional[TemplateDetailsResponse] = None


class CreateScanWizardRequest(BaseModel):
    """Request model for creating scan from wizard."""
    target: str = Field(..., description="Target to scan")
    template: str = Field(..., description="Template name")
    custom_config: Optional[Dict] = None


class CreateScanWizardResponse(BaseModel):
    """Response model for created scan."""
    scan_id: str
    target: str
    template: str
    scan_type: str
    status: str
    config: Dict


# Endpoints

@router.post("/detect-target", response_model=TargetDetectionResponse)
async def detect_target(request: TargetDetectionRequest):
    """
    Detect target type from input string.
    
    Analyzes the input and determines if it's a domain, IP, URL, etc.
    Returns normalized form and confidence score.
    
    ## Example
    
    Request:
    ```json
    {"target": "example.com"}
    ```
    
    Response:
    ```json
    {
      "target": "example.com",
      "type": "domain",
      "normalized": "example.com",
      "confidence": 0.95,
      "metadata": {"dot_count": 1}
    }
    ```
    """
    detection = TargetDetector.detect(request.target)
    
    return {
        "target": detection.target,
        "type": detection.type.value,
        "normalized": detection.normalized,
        "confidence": detection.confidence,
        "metadata": detection.metadata,
    }


@router.get("/templates", response_model=List[TemplateListResponse])
async def list_templates(user: User = Depends(get_current_user)):
    """
    List all available scan templates.
    
    Returns brief information about each template for selection.
    """
    return ScanTemplates.list_templates()


@router.get("/templates/{template_name}", response_model=TemplateDetailsResponse)
async def get_template_details(
    template_name: str,
    user: User = Depends(get_current_user)
):
    """
    Get detailed information about a specific template.
    
    Includes module list, config defaults, and recommendations.
    """
    template = ScanTemplates.get_template(template_name)
    
    if not template:
        raise HTTPException(
            status_code=404,
            detail=f"Template '{template_name}' not found"
        )
    
    return {
        "id": template_name,
        "name": template.name,
        "description": template.description,
        "duration": template.duration_estimate,
        "enabled_modules": template.enabled_modules,
        "depth": template.depth,
        "timeout_minutes": template.timeout_minutes,
        "parallelization": template.parallelization,
        "default_config": template.config,
    }


@router.post("/recommend-template", response_model=Dict)
async def recommend_template(
    request: TargetDetectionRequest,
    user: User = Depends(get_current_user)
):
    """
    Get recommended scan template for target type.
    
    Analyzes target type and recommends best template.
    """
    detection = TargetDetector.detect(request.target)
    recommended = ScanTemplates.recommend_template(detection.type)
    template = ScanTemplates.get_template(recommended)
    
    return {
        "target": request.target,
        "target_type": detection.type.value,
        "recommended_template": recommended,
        "template_name": template.name,
        "reason": f"Best for {detection.type.value} targets",
    }


@router.post("/validate", response_model=ValidateWizardResponse)
async def validate_wizard(
    request: ValidateWizardRequest,
    user: User = Depends(get_current_user)
):
    """
    Validate wizard input before creating scan.
    
    Checks target validity, template existence, and configuration.
    Returns errors if validation fails.
    """
    # Validate
    is_valid, errors = ScanWizardValidator.validate_wizard_input(
        request.target,
        request.template,
        request.custom_config
    )
    
    # Detect target for response
    detection = TargetDetector.detect(request.target)
    target_info = {
        "target": detection.target,
        "type": detection.type.value,
        "normalized": detection.normalized,
        "confidence": detection.confidence,
        "metadata": detection.metadata,
    }
    
    # Get template info
    template = ScanTemplates.get_template(request.template)
    template_info = None
    if template:
        template_info = {
            "id": request.template,
            "name": template.name,
            "description": template.description,
            "duration": template.duration_estimate,
            "enabled_modules": template.enabled_modules,
            "depth": template.depth,
            "timeout_minutes": template.timeout_minutes,
            "parallelization": template.parallelization,
            "default_config": template.config,
        }
    
    return {
        "is_valid": is_valid,
        "errors": errors,
        "target_info": target_info if is_valid else None,
        "template_info": template_info if is_valid else None,
    }


@router.post("/create", response_model=CreateScanWizardResponse)
async def create_scan_from_wizard(
    request: CreateScanWizardRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create scan from wizard input.
    
    Validates input, builds configuration, creates scan, and queues it.
    
    ## Steps
    
    1. Validate target and template
    2. Detect target type
    3. Build scan configuration
    4. Create scan in database
    5. Queue for processing
    
    Returns created scan with status.
    """
    # Validate
    is_valid, errors = ScanWizardValidator.validate_wizard_input(
        request.target,
        request.template,
        request.custom_config
    )
    
    if not is_valid:
        error_msg = "; ".join([f"{k}: {v}" for k, v in errors.items()])
        raise HTTPException(status_code=400, detail=error_msg)
    
    # Build configuration
    config = ScanWizardBuilder.build(
        request.target,
        request.template,
        request.custom_config
    )
    
    # Create scan
    scan = Scan(
        user_id=user.id,
        target=config["target"],
        scan_type=config.get("scan_type", "security"),
        config=config,
        status="queued"
    )
    
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    # Queue for processing
    get_queue().send("scan-jobs", {
        "scan_id": scan.id,
        "target": scan.target,
        "scan_type": scan.scan_type,
        "config": config,
    })
    
    return {
        "scan_id": scan.id,
        "target": config["target"],
        "template": request.template,
        "scan_type": config.get("scan_type", "security"),
        "status": scan.status,
        "config": config,
    }


@router.post("/batch-create", response_model=Dict)
async def create_batch_scans_from_wizard(
    request: Dict,  # List of CreateScanWizardRequest
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create multiple scans from wizard input (batch mode).
    
    Useful for scanning multiple targets with same template.
    
    Request:
    ```json
    {
      "targets": ["example.com", "test.com", "192.168.1.1"],
      "template": "thorough",
      "custom_config": {}
    }
    ```
    """
    targets = request.get("targets", [])
    template = request.get("template", "quick")
    custom_config = request.get("custom_config", {})
    
    if not targets:
        raise HTTPException(status_code=400, detail="No targets provided")
    
    if len(targets) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 targets per batch")
    
    created_scans = []
    failed_targets = []
    
    for target in targets:
        try:
            # Build configuration
            config = ScanWizardBuilder.build(target, template, custom_config)
            
            # Create scan
            scan = Scan(
                user_id=user.id,
                target=config["target"],
                scan_type=config.get("scan_type", "security"),
                config=config,
                status="queued"
            )
            
            db.add(scan)
            db.commit()
            db.refresh(scan)
            
            # Queue for processing
            get_queue().send("scan-jobs", {
                "scan_id": scan.id,
                "target": scan.target,
                "scan_type": scan.scan_type,
                "config": config,
            })
            
            created_scans.append({
                "scan_id": scan.id,
                "target": config["target"],
                "status": "queued",
            })
        
        except Exception as e:
            failed_targets.append({
                "target": target,
                "error": str(e),
            })
    
    return {
        "created": len(created_scans),
        "failed": len(failed_targets),
        "scans": created_scans,
        "failed_targets": failed_targets,
    }
