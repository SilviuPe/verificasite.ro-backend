from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional
from datetime import date

class CreateLeadRequest(BaseModel):
    website: str
    company_name: str

class AnalyzeRequest(BaseModel):
    url: str = Field(..., description="URL in orice forma: domain, www.domain, http(s)://...")
    device: int = Field(1, ge=1, le=2)

class AnalyzeResponse(BaseModel):
    input_url: str
    normalized_candidates: List[str]
    fetched_url: str
    final_url: str
    redirect_chain: List[str]
    status_code: int
    ip_address: Optional[str]

    seo: Dict[str, Any]
    structured_data: Dict[str, Any]
    social: Dict[str, Any]
    tech: Dict[str, Any]
    checks: Dict[str, Any]
    screenshots: Dict[str, str]
    plugins: Dict[str, Any]

    vulnerabilities: Dict[str, Any] = {}
    favicon: Optional[str] = None
    score: Dict[str, Any]



class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"