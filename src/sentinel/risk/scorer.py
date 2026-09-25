"""Risk scoring engine for Sentinel."""

from dataclasses import dataclass

from sentinel.models import Alert, AlertSeverity


@dataclass(frozen=True)
class RiskFactors:
    """Factors contributing to a risk score."""

    base_score: int = 0
    repetition_bonus: int = 0
    privileged_account_bonus: int = 0
    known_malicious_ip_bonus: int = 0


class RiskScorer:
    """Calculate deterministic and explainable security risk scores."""

    SEVERITY_BONUS = {
        AlertSeverity.LOW: 0,
        AlertSeverity.MEDIUM: 10,
        AlertSeverity.HIGH: 20,
        AlertSeverity.CRITICAL: 30,
    }

    def calculate(self, alert: Alert, factors: RiskFactors | None = None) -> int:
        """Calculate a final risk score between 0 and 100."""

        if factors is None:
            factors = RiskFactors(base_score=alert.risk_score)

        score = (
            factors.base_score
            + factors.repetition_bonus
            + factors.privileged_account_bonus
            + factors.known_malicious_ip_bonus
            + self.SEVERITY_BONUS[alert.severity]
        )

        return min(100, max(0, score))

    def explain(
        self,
        alert: Alert,
        factors: RiskFactors | None = None,
    ) -> dict[str, int]:
        """Return the individual contributions to the risk score."""

        if factors is None:
            factors = RiskFactors(base_score=alert.risk_score)

        return {
            "base_score": factors.base_score,
            "repetition_bonus": factors.repetition_bonus,
            "privileged_account_bonus": factors.privileged_account_bonus,
            "known_malicious_ip_bonus": factors.known_malicious_ip_bonus,
            "severity_bonus": self.SEVERITY_BONUS[alert.severity],
        }
