"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CUSTOM EDR — BASE RULE CLASS                                               ║
║                                                                              ║
║  Every detection rule inherits from BaseRule and implements evaluate().     ║
║  This gives us a consistent interface and makes adding new rules trivial.   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from abc import ABC, abstractmethod
from typing import Optional, Type, List
from detection_engine.event_schema import BaseEvent, DetectionAlert


class BaseRule(ABC):
    """
    Abstract base class for all detection rules.

    To add a new rule:
    1. Create a subclass of BaseRule
    2. Set class-level attributes (rule_id, rule_name, etc.)
    3. Implement the evaluate() method
    4. Add the class to the appropriate rules module's __all__ list
    """

    # ── Required class attributes ──────────────────────────────────────────
    rule_id: str = "BASE000"
    rule_name: str = "Base Rule"
    description: str = "Base detection rule — override me"
    mitre_tactic: str = ""
    mitre_technique_id: str = ""
    mitre_technique_name: str = ""
    severity: int = 5  # 1-10

    # ── Which event types this rule handles ───────────────────────────────
    # Override to restrict rule to specific event classes
    event_types: tuple = ()

    def can_handle(self, event: BaseEvent) -> bool:
        """Check if this rule is relevant for the given event type."""
        if not self.event_types:
            return True
        return isinstance(event, self.event_types)

    @abstractmethod
    def evaluate(self, event: BaseEvent) -> Optional[DetectionAlert]:
        """
        Evaluate an event against this rule.

        Args:
            event: A normalized Sysmon event dataclass

        Returns:
            DetectionAlert if the event is malicious/suspicious, None otherwise.
        """
        pass

    def _make_alert(self, event: BaseEvent, description: str = None) -> DetectionAlert:
        """Helper to create a DetectionAlert from this rule's metadata."""
        return DetectionAlert(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            description=description or self.description,
            mitre_tactic=self.mitre_tactic,
            mitre_technique_id=self.mitre_technique_id,
            mitre_technique_name=self.mitre_technique_name,
            severity=self.severity,
            event=event,
        )


class RuleRegistry:
    """
    Central registry of all active detection rules.
    Rules are auto-registered when rule modules are imported.
    """

    def __init__(self):
        self._rules: List[BaseRule] = []

    def register(self, rule: BaseRule):
        self._rules.append(rule)

    def register_all(self, rule_classes: List[Type[BaseRule]]):
        for cls in rule_classes:
            self._rules.append(cls())

    def evaluate_all(self, event: BaseEvent) -> List[DetectionAlert]:
        """Run all applicable rules against an event. Returns all alerts fired."""
        alerts = []
        for rule in self._rules:
            if not rule.can_handle(event):
                continue
            try:
                result = rule.evaluate(event)
                if result:
                    alerts.append(result)
            except Exception as e:
                import logging
                logging.getLogger("edr.rules").error(
                    f"Rule {rule.rule_id} threw an exception: {e}", exc_info=True
                )
        return alerts

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def list_rules(self) -> List[dict]:
        return [
            {
                "rule_id": r.rule_id,
                "rule_name": r.rule_name,
                "severity": r.severity,
                "mitre_technique_id": r.mitre_technique_id,
            }
            for r in self._rules
        ]
