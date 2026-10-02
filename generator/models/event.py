"""
Canonical SecurityEvent model.

Mirrors docs/event-schema.json exactly. tests/test_event_contract.py
validates that instances of this model pass validation against the JSON
Schema, so the two never silently drift.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class Category(str, Enum):
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    ENDPOINT = "endpoint"
    PRIVILEGE = "privilege"
    CLOUD = "cloud"
    WEB = "web"


class EventType(str, Enum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    ACCOUNT_LOCKED = "account_locked"
    CONNECTION = "connection"
    DNS_QUERY = "dns_query"
    FIREWALL_ALLOW = "firewall_allow"
    FIREWALL_DENY = "firewall_deny"
    PORT_SCAN = "port_scan"
    PROCESS_CREATED = "process_created"
    PROCESS_TERMINATED = "process_terminated"
    FILE_CREATED = "file_created"
    FILE_MODIFIED = "file_modified"
    FILE_DELETED = "file_deleted"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    GROUP_MODIFIED = "group_modified"
    ACCOUNT_CREATED = "account_created"
    ACCOUNT_DELETED = "account_deleted"
    CLOUD_LOGIN = "cloud_login"
    API_CALL = "api_call"
    PERMISSION_CHANGE = "permission_change"
    HTTP_REQUEST = "http_request"
    HTTP_ERROR = "http_error"
    SUSPICIOUS_REQUEST = "suspicious_request"


EVENT_TYPE_CATEGORY: dict[EventType, Category] = {
    EventType.LOGIN_SUCCESS: Category.AUTHENTICATION,
    EventType.LOGIN_FAILED: Category.AUTHENTICATION,
    EventType.LOGOUT: Category.AUTHENTICATION,
    EventType.PASSWORD_CHANGE: Category.AUTHENTICATION,
    EventType.ACCOUNT_LOCKED: Category.AUTHENTICATION,
    EventType.CONNECTION: Category.NETWORK,
    EventType.DNS_QUERY: Category.NETWORK,
    EventType.FIREWALL_ALLOW: Category.NETWORK,
    EventType.FIREWALL_DENY: Category.NETWORK,
    EventType.PORT_SCAN: Category.NETWORK,
    EventType.PROCESS_CREATED: Category.ENDPOINT,
    EventType.PROCESS_TERMINATED: Category.ENDPOINT,
    EventType.FILE_CREATED: Category.ENDPOINT,
    EventType.FILE_MODIFIED: Category.ENDPOINT,
    EventType.FILE_DELETED: Category.ENDPOINT,
    EventType.PRIVILEGE_ESCALATION: Category.PRIVILEGE,
    EventType.GROUP_MODIFIED: Category.PRIVILEGE,
    EventType.ACCOUNT_CREATED: Category.PRIVILEGE,
    EventType.ACCOUNT_DELETED: Category.PRIVILEGE,
    EventType.CLOUD_LOGIN: Category.CLOUD,
    EventType.API_CALL: Category.CLOUD,
    EventType.PERMISSION_CHANGE: Category.CLOUD,
    EventType.HTTP_REQUEST: Category.WEB,
    EventType.HTTP_ERROR: Category.WEB,
    EventType.SUSPICIOUS_REQUEST: Category.WEB,
}

CATEGORY_TOPIC: dict[Category, str] = {
    Category.AUTHENTICATION: "security-authentication",
    Category.NETWORK: "security-network",
    Category.ENDPOINT: "security-endpoint",
    Category.PRIVILEGE: "security-privilege",
    Category.CLOUD: "security-cloud",
    Category.WEB: "security-web",
}

_EVENT_ID_RE = re.compile(r"^evt-[A-Za-z0-9]{10,32}$")


def new_event_id() -> str:
    return f"evt-{uuid.uuid4().hex[:20]}"


class SecurityEvent(BaseModel):
    event_id: str = Field(default_factory=new_event_id)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: EventType
    category: Category
    source_ip: str
    destination_ip: str
    source_port: int = Field(ge=0, le=65535)
    destination_port: int = Field(ge=0, le=65535)
    protocol: str
    username: Optional[str] = None
    hostname: str
    action: str
    status: str
    bytes_in: int = Field(ge=0, default=0)
    bytes_out: int = Field(ge=0, default=0)
    country: str = Field(min_length=2, max_length=2)
    metadata: dict = Field(default_factory=dict)

    @field_validator("event_id")
    @classmethod
    def _validate_event_id(cls, v: str) -> str:
        if not _EVENT_ID_RE.match(v):
            raise ValueError(f"event_id '{v}' does not match required pattern evt-<10-32 alnum>")
        return v

    @field_validator("protocol")
    @classmethod
    def _validate_protocol(cls, v: str) -> str:
        allowed = {"TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"}
        if v not in allowed:
            raise ValueError(f"protocol must be one of {allowed}")
        return v

    @field_validator("status")
    @classmethod
    def _validate_status(cls, v: str) -> str:
        allowed = {"success", "failure", "unknown"}
        if v not in allowed:
            raise ValueError(f"status must be one of {allowed}")
        return v

    def model_post_init(self, __context) -> None:
        expected = EVENT_TYPE_CATEGORY[self.event_type]
        if self.category != expected:
            object.__setattr__(self, "category", expected)

    def to_kafka_json(self) -> dict:
        return self.model_dump(mode="json")

    def kafka_topic(self) -> str:
        """
        Routes purely by category, per the cahier des charges' per-category
        topic list (security-authentication, security-network, etc). This
        is the ONLY routing rule in the project - do not add a second,
        incompatible one elsewhere (e.g. by event_type or scenario).
        """
        return CATEGORY_TOPIC[self.category]

    def partition_key(self) -> str:
        """
        Kafka partition key, using the fallback chain hostname -> username
        -> source_ip (cahier des charges §12). hostname is a required,
        non-empty field in this schema, so the username/source_ip branches
        are defensive (e.g. a future schema relaxation) rather than
        commonly exercised today - covered by
        tests/test_event_contract.py regardless.
        """
        if self.hostname:
            return self.hostname
        if self.username:
            return self.username
        return self.source_ip
