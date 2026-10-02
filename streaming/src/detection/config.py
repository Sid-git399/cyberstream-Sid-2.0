"""
Detection rule configuration.

Every threshold/window/enabled flag a rule uses comes from here, loaded
from infrastructure/spark/detection_rules.yaml (see .env.example's
DETECTION_RULES_CONFIG_PATH) - never hardcoded inside a rule's `apply()`.
`severity`/`risk_points` are also config, not code, per the requirement
that rules "provide risk contribution information without hardcoding
everything into the rule": the *initial* scoring model (cahier des
charges §27) is expressed as config defaults here, not as a second
hardcoded copy inside each rule.

Validation is strict (`extra="forbid"`): a typo'd key in the YAML file
(e.g. `faild_attempts`) raises a clear config error at startup rather
than silently being ignored and the rule running with its default.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field

from common.errors import AppError


class DetectionConfigError(AppError):
    code = "DETECTION_CONFIG_ERROR"
    http_status = 500


class BaseRuleConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    severity: str = Field(default="MEDIUM", pattern="^(INFO|LOW|MEDIUM|HIGH|CRITICAL)$")
    risk_points: int = Field(default=10, ge=0, le=100)


class BruteForceConfig(BaseRuleConfig):
    failed_attempts: int = Field(default=10, ge=1)
    window_seconds: int = Field(default=300, ge=1)
    severity: str = Field(default="HIGH", pattern="^(INFO|LOW|MEDIUM|HIGH|CRITICAL)$")
    risk_points: int = Field(default=25, ge=0, le=100)  # cahier des charges §27


class PasswordSprayingConfig(BaseRuleConfig):
    unique_users: int = Field(default=8, ge=1)
    window_seconds: int = Field(default=300, ge=1)
    severity: str = Field(default="HIGH", pattern="^(INFO|LOW|MEDIUM|HIGH|CRITICAL)$")
    risk_points: int = Field(default=25, ge=0, le=100)


class PortScanConfig(BaseRuleConfig):
    unique_ports: int = Field(default=20, ge=1)
    window_seconds: int = Field(default=60, ge=1)
    severity: str = Field(default="MEDIUM", pattern="^(INFO|LOW|MEDIUM|HIGH|CRITICAL)$")
    risk_points: int = Field(default=15, ge=0, le=100)


class SuspiciousAuthenticationConfig(BaseRuleConfig):
    severity: str = Field(default="MEDIUM", pattern="^(INFO|LOW|MEDIUM|HIGH|CRITICAL)$")
    risk_points: int = Field(default=15, ge=0, le=100)


class PrivilegeEscalationConfig(BaseRuleConfig):
    severity: str = Field(default="HIGH", pattern="^(INFO|LOW|MEDIUM|HIGH|CRITICAL)$")
    risk_points: int = Field(default=20, ge=0, le=100)  # cahier des charges §27


class SuspiciousProcessConfig(BaseRuleConfig):
    severity: str = Field(default="HIGH", pattern="^(INFO|LOW|MEDIUM|HIGH|CRITICAL)$")
    risk_points: int = Field(default=20, ge=0, le=100)  # cahier des charges §27


class LargeDataTransferConfig(BaseRuleConfig):
    bytes_out_threshold: int = Field(default=5_000_000, ge=1)
    severity: str = Field(default="MEDIUM", pattern="^(INFO|LOW|MEDIUM|HIGH|CRITICAL)$")
    risk_points: int = Field(default=15, ge=0, le=100)  # cahier des charges §27


class DNSAnomalyConfig(BaseRuleConfig):
    query_count_threshold: int = Field(default=50, ge=1)
    window_seconds: int = Field(default=60, ge=1)
    severity: str = Field(default="LOW", pattern="^(INFO|LOW|MEDIUM|HIGH|CRITICAL)$")
    risk_points: int = Field(default=10, ge=0, le=100)


class DetectionEngineConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    brute_force: BruteForceConfig = Field(default_factory=BruteForceConfig)
    password_spraying: PasswordSprayingConfig = Field(default_factory=PasswordSprayingConfig)
    port_scan: PortScanConfig = Field(default_factory=PortScanConfig)
    suspicious_authentication: SuspiciousAuthenticationConfig = Field(default_factory=SuspiciousAuthenticationConfig)
    privilege_escalation: PrivilegeEscalationConfig = Field(default_factory=PrivilegeEscalationConfig)
    suspicious_process: SuspiciousProcessConfig = Field(default_factory=SuspiciousProcessConfig)
    large_data_transfer: LargeDataTransferConfig = Field(default_factory=LargeDataTransferConfig)
    dns_anomaly: DNSAnomalyConfig = Field(default_factory=DNSAnomalyConfig)


_CANDIDATE_CONFIG_PATHS = [
    # Local dev layout: streaming/src/detection/config.py -> repo root is parents[3]
    Path(__file__).resolve().parents[3] / "infrastructure" / "spark" / "detection_rules.yaml",
    # Docker layout: /app/src/detection/config.py, infra not copied into the
    # image today (config is env/volume-driven there) - kept for parity/testing.
    Path(__file__).resolve().parents[2] / "infrastructure" / "spark" / "detection_rules.yaml",
    Path("/app/infrastructure/spark/detection_rules.yaml"),
]


def _find_default_config_path() -> Optional[Path]:
    for candidate in _CANDIDATE_CONFIG_PATHS:
        if candidate.exists():
            return candidate
    return None


def load_detection_config(path: str | Path | None = None) -> DetectionEngineConfig:
    """
    Resolution order: explicit `path` argument, then the first candidate
    repo-relative location that exists, then pure Pydantic defaults (with
    every rule enabled) if no YAML file is found anywhere - so a missing
    config file degrades to "every rule runs with the documented default
    thresholds", never to "the engine silently does nothing".

    An explicit `path` that doesn't exist is a caller error (e.g. a typo
    in a deployment's config path) and raises DetectionConfigError rather
    than silently falling back to defaults - silently ignoring a wrong
    path a caller explicitly asked for would be far more dangerous than a
    missing default. Only the *auto-discovery* case (no path given, and
    none of the candidate locations exist) falls back quietly. Found by
    writing a test for the wrong behavior and getting a real
    FileNotFoundError instead - see tests/detection/test_config.py.
    """
    if path is not None:
        resolved = Path(path)
        if not resolved.exists():
            raise DetectionConfigError(f"Detection rules config file not found: {resolved}")
    else:
        resolved = _find_default_config_path()
        if resolved is None:
            return DetectionEngineConfig()

    try:
        raw = yaml.safe_load(resolved.read_text()) or {}
    except yaml.YAMLError as exc:
        raise DetectionConfigError(f"Could not parse detection rules YAML at {resolved}: {exc}") from exc

    try:
        return DetectionEngineConfig(**raw)
    except Exception as exc:  # pydantic.ValidationError, primarily
        raise DetectionConfigError(f"Invalid detection rules config at {resolved}: {exc}") from exc
