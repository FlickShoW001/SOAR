"""
Decision Engine: Evaluates enrichment data and produces explainable decisions.
Implements rule-based risk scoring with configurable thresholds.
"""

import json
import logging
from dataclasses import dataclass
from typing import Any

import yaml

from models import Decision, EnrichmentResult, Event

logger = logging.getLogger(__name__)

# Global config loaded on startup
_config: dict[str, Any] | None = None


@dataclass
class DecisionResult:
    """
    Output of the decision engine.
    """

    action: str  # "block", "monitor", "ignore"
    confidence: float  # 0.0-1.0
    risk_score: float  # 0-100
    requires_approval: bool
    reasoning: dict[str, Any]  # Detailed breakdown of decision logic


def load_config(config_path: str = "config.yaml"):
    """Load configuration from YAML file."""
    global _config
    with open(config_path, "r") as f:
        _config = yaml.safe_load(f)
    logger.info(f"Decision engine config loaded from {config_path}")


def decide(event: Event, enrichment: EnrichmentResult) -> DecisionResult:
    """
    Make a security decision based on event + enrichment data.

    Decision process:
      1. Calculate risk_score as weighted combination of:
         - Abuse score (reputation)
         - Event severity
         - Report count (frequency)
      2. Determine confidence based on enrichment quality
      3. Map risk_score to action (block/monitor/ignore)
      4. Decide if approval is required based on impact rules

    Args:
        event: Detected security event
        enrichment: Enrichment data (abuse_score, country, isp, etc.)

    Returns:
        DecisionResult with action, confidence, risk_score, and reasoning
    """
    if not _config:
        raise RuntimeError("Config not loaded; call load_config() first")

    cfg = _config["decision_engine"]
    reasoning = {}

    # Step 1: Calculate risk_score
    risk_score = _calculate_risk_score(event, enrichment, cfg, reasoning)

    # Step 2: Determine confidence
    confidence = _determine_confidence(enrichment, event, cfg, reasoning)

    # Step 3: Map risk_score to action
    action = _map_risk_to_action(risk_score, cfg)

    # Step 4: Determine if approval is needed
    requires_approval = _requires_approval(
        action, risk_score, event, enrichment, cfg, reasoning
    )

    decision_result = DecisionResult(
        action=action,
        confidence=confidence,
        risk_score=risk_score,
        requires_approval=requires_approval,
        reasoning=reasoning,
    )

    logger.info(
        f"Decision for event {event.id} (IP {event.source_ip}): "
        f"action={action}, risk_score={risk_score:.1f}, confidence={confidence:.2f}, "
        f"requires_approval={requires_approval}"
    )

    return decision_result


def _calculate_risk_score(
    event: Event,
    enrichment: EnrichmentResult,
    cfg: dict[str, Any],
    reasoning: dict[str, Any],
) -> float:
    """
    Calculate composite risk_score (0-100) from weighted factors.

    Factors:
      - abuse_score: IP's reputation from AbuseIPDB (0-100)
      - event_severity: raw event severity (1-5 -> normalized to 0-100)
      - report_count: how many reports on this IP (0-∞ -> normalized 0-100)

    Weights are defined in config.yaml -> decision_engine.risk_score_weights
    This keeps thresholds out of code and editable without redeployment.
    """
    weights = cfg["risk_score_weights"]

    # If enrichment failed, use conservative estimates
    abuse_score = enrichment.abuse_score if not enrichment.error else 0.0
    report_count = enrichment.report_count if not enrichment.error else 0

    # Normalize abuse_score (already 0-100)
    norm_abuse = abuse_score / 100.0

    # Normalize event severity (1-5 -> 0-1)
    norm_severity = event.severity / 5.0

    # Normalize report count (capped at 200 for saturation)
    norm_reports = min(report_count / 200.0, 1.0)

    # Weighted sum -> 0-100
    risk_score = (
        norm_abuse * weights["abuse_score"]
        + norm_severity * weights["event_severity"]
        + norm_reports * weights["report_count"]
    ) * 100.0

    reasoning["risk_calculation"] = {
        "abuse_score": abuse_score,
        "event_severity": event.severity,
        "report_count": report_count,
        "norm_abuse": norm_abuse,
        "norm_severity": norm_severity,
        "norm_reports": norm_reports,
        "weights": weights,
        "final_risk_score": risk_score,
    }

    return risk_score


def _determine_confidence(
    enrichment: EnrichmentResult,
    event: Event,
    cfg: dict[str, Any],
    reasoning: dict[str, Any],
) -> float:
    """
    Determine confidence (0.0-1.0) in the decision.

    Higher confidence if:
      - Enrichment succeeded (no error)
      - High report count (data-backed)
      - Cached result is fresh (multiple sources agree)

    Lower confidence if:
      - Enrichment failed
      - First report for this IP (no historical data)
      - Event source is noisy/unreliable
    """
    confidence = 0.5  # Base confidence

    if enrichment.error:
        # Enrichment failed; lower confidence
        confidence = 0.4
        reasoning["confidence_factors"] = ["enrichment_failed"]
    else:
        # Enrichment succeeded
        factors = []

        if enrichment.report_count > 10:
            confidence += 0.3  # Well-established reputation
            factors.append("high_report_count")
        elif enrichment.report_count > 0:
            confidence += 0.15  # Some history
            factors.append("some_reports")

        # Fresh enrichment data
        if enrichment.cache_ttl_minutes and enrichment.cache_ttl_minutes < 5:
            confidence += 0.1
            factors.append("fresh_data")

        reasoning["confidence_factors"] = factors

    # Cap at 0.99 (never 100% certain)
    confidence = min(confidence, 0.99)
    return confidence


def _map_risk_to_action(risk_score: float, cfg: dict[str, Any]) -> str:
    """
    Map risk_score (0-100) to action recommendation.

    Thresholds are in config.yaml -> decision_engine.action_thresholds
    Example:
      - risk >= 75: block
      - risk >= 50: monitor
      - risk >= 0: ignore
    """
    thresholds = cfg["action_thresholds"]

    if risk_score >= thresholds["block_min_risk"]:
        return "block"
    elif risk_score >= thresholds["monitor_min_risk"]:
        return "monitor"
    else:
        return "ignore"


def _requires_approval(
    action: str,
    risk_score: float,
    event: Event,
    enrichment: EnrichmentResult,
    cfg: dict[str, Any],
    reasoning: dict[str, Any],
) -> bool:
    """
    Determine if this decision requires human approval.

    Rules (from config.yaml -> decision_engine.approval_rules):
      - block_requires_approval: Any BLOCK needs approval (high impact)
      - monitor_auto_approve_max_risk: MONITOR auto-approves if risk < threshold
      - ignore_requires_approval: IGNORE actions never need approval (low impact)
      - high_severity_requires_approval: Critical events always require approval
      - uncached_ip_requires_approval: First-time IPs require approval
    """
    rules = cfg["approval_rules"]
    approval_reasons = []

    # Rule 1: BLOCK always requires approval
    if action == "block" and rules["block_requires_approval"]:
        approval_reasons.append("action_is_block")
        reasoning["approval_reasons"] = approval_reasons
        return True

    # Rule 2: IGNORE never requires approval
    if action == "ignore" and not rules["ignore_requires_approval"]:
        reasoning["approval_reasons"] = ["action_is_ignore"]
        return False

    # Rule 3: High-severity events require approval
    if event.severity >= 4 and rules["high_severity_requires_approval"]:
        approval_reasons.append("high_severity_event")

    # Rule 4: MONITOR actions auto-approve if risk is low enough
    if action == "monitor":
        if risk_score < rules["monitor_auto_approve_max_risk"]:
            reasoning["approval_reasons"] = ["monitor_low_risk"]
            return False
        else:
            approval_reasons.append("monitor_high_risk")

    # Rule 5: Uncached IPs (no enrichment data) require approval
    if enrichment.error or enrichment.report_count == 0:
        approval_reasons.append("uncached_or_unknown_ip")

    reasoning["approval_reasons"] = approval_reasons
    return len(approval_reasons) > 0


def persist_decision(
    event: Event, enrichment: EnrichmentResult, decision: DecisionResult, session
) -> Decision:
    """
    Persist decision to database.
    """
    db_decision = Decision(
        event_id=event.id,
        enrichment_id=enrichment.id,
        action=decision.action,
        confidence=decision.confidence,
        risk_score=decision.risk_score,
        requires_approval=decision.requires_approval,
        reasoning=json.dumps(decision.reasoning),
    )
    session.add(db_decision)
    session.commit()
    return db_decision
