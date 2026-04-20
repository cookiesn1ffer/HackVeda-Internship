"""
Rule registry initialization.
Import all rule modules and build the unified RuleRegistry.
"""
from detection_engine.rules.base_rule import RuleRegistry
from detection_engine.rules.powershell_rules import ALL_RULES as PS_RULES
from detection_engine.rules.network_rules import ALL_RULES as NET_RULES
from detection_engine.rules.persistence_rules import ALL_RULES as PER_RULES
from detection_engine.rules.credential_rules import ALL_RULES as CRED_RULES
from detection_engine.rules.injection_rules import ALL_RULES as INJ_RULES


def build_registry() -> RuleRegistry:
    """Create and populate the rule registry with all available rules."""
    registry = RuleRegistry()
    all_rule_classes = PS_RULES + NET_RULES + PER_RULES + CRED_RULES + INJ_RULES
    registry.register_all(all_rule_classes)
    return registry


TOTAL_RULES = len(PS_RULES + NET_RULES + PER_RULES + CRED_RULES + INJ_RULES)
