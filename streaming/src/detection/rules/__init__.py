from src.detection.rules.brute_force import BruteForceRule
from src.detection.rules.dns_anomaly import DNSAnomalyRule
from src.detection.rules.large_data_transfer import LargeDataTransferRule
from src.detection.rules.password_spraying import PasswordSprayingRule
from src.detection.rules.port_scan import PortScanRule
from src.detection.rules.privilege_escalation import PrivilegeEscalationRule
from src.detection.rules.suspicious_authentication import SuspiciousAuthenticationRule
from src.detection.rules.suspicious_process import SuspiciousProcessRule

# config attribute name (on DetectionEngineConfig) -> Rule class.
# The key must match both the YAML top-level key and the
# DetectionEngineConfig field name - engine.py relies on this.
ALL_RULES = {
    "brute_force": BruteForceRule,
    "password_spraying": PasswordSprayingRule,
    "port_scan": PortScanRule,
    "suspicious_authentication": SuspiciousAuthenticationRule,
    "privilege_escalation": PrivilegeEscalationRule,
    "suspicious_process": SuspiciousProcessRule,
    "large_data_transfer": LargeDataTransferRule,
    "dns_anomaly": DNSAnomalyRule,
}
