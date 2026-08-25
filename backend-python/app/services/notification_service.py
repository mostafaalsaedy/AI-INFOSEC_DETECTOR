"""
Alert notification fan-out.

Routes security alerts to email, Slack and generic webhooks (SIEM). Every
channel is optional and independently toggled through settings, and a failure
in one channel never prevents the others from firing.

Notification content is deliberately metadata-only: titles, severities, counts
and links. Prompt or response content never leaves the system through this path.
"""

import asyncio
import hashlib
import hmac
import json
import smtplib
from dataclasses import dataclass, field
from datetime import datetime
from email.message import EmailMessage
from typing import Any, Dict, List, Optional

import httpx

from app.core.config import NOTIFICATION_TEMPLATES, settings
from app.core.database import RiskLevel, SecurityAlert, record_audit_event
from app.core.logging import logger
from app.core.timeutils import utcnow

SEVERITY_COLOURS = {
    RiskLevel.CRITICAL: "#d63031",
    RiskLevel.HIGH: "#ff6b35",
    RiskLevel.MEDIUM: "#fdcb6e",
    RiskLevel.LOW: "#00b894",
}

SEVERITY_EMOJI = {
    RiskLevel.CRITICAL: ":rotating_light:",
    RiskLevel.HIGH: ":warning:",
    RiskLevel.MEDIUM: ":large_orange_diamond:",
    RiskLevel.LOW: ":information_source:",
}


@dataclass
class NotificationResult:
    """Per-alert delivery outcome, one entry per attempted channel."""

    alert_id: Optional[int]
    channels: Dict[str, bool] = field(default_factory=dict)
    errors: Dict[str, str] = field(default_factory=dict)

    @property
    def delivered(self) -> bool:
        return any(self.channels.values())

    def as_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "channels": self.channels,
            "errors": self.errors,
            "delivered": self.delivered,
        }


class NotificationService:
    """Delivers alert notifications across the configured channels."""

    def __init__(self, http_timeout: float = 10.0) -> None:
        self.http_timeout = http_timeout

    # -- Public API ---------------------------------------------------------

    async def send_alert_notifications(self, alert: SecurityAlert) -> Dict[str, Any]:
        """Notify every enabled channel about a newly raised alert."""
        severity = (
            alert.severity if isinstance(alert.severity, RiskLevel) else RiskLevel.LOW
        )
        result = NotificationResult(alert_id=alert.id)

        if not self._should_notify(severity):
            logger.info(
                f"Alert {alert.id} ({severity.value}) suppressed by notification policy"
            )
            return result.as_dict()

        tasks = []
        if settings.ALERT_EMAIL_ENABLED:
            tasks.append(("email", self._send_email(alert, severity)))
        if settings.ALERT_SLACK_ENABLED and settings.SLACK_WEBHOOK_URL:
            tasks.append(("slack", self._send_slack(alert, severity)))
        if settings.ALERT_WEBHOOK_ENABLED and settings.WEBHOOK_URL:
            tasks.append(("webhook", self._send_webhook(alert, severity)))

        if not tasks:
            logger.warning("No notification channels are enabled")
            return result.as_dict()

        outcomes = await asyncio.gather(
            *(task for _, task in tasks), return_exceptions=True
        )

        for (channel, _), outcome in zip(tasks, outcomes, strict=False):
            if isinstance(outcome, Exception):
                result.channels[channel] = False
                result.errors[channel] = str(outcome)
                logger.error(
                    f"{channel} notification failed for alert {alert.id}: {outcome}"
                )
            else:
                result.channels[channel] = bool(outcome)

        await record_audit_event(
            event_type="alert_notification_sent",
            event_category="security",
            description=f"Alert {alert.id} dispatched to {list(result.channels)}",
            event_data=result.as_dict(),
            risk_level=severity,
        )

        return result.as_dict()

    async def send_alert_update_notification(
        self,
        alert_id: int,
        old_status: Optional[str],
        new_status: Any,
        updated_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Announce a status transition on an existing alert."""
        new_status_value = getattr(new_status, "value", new_status)
        summary = (
            f"Alert #{alert_id} moved from '{old_status or 'unknown'}' "
            f"to '{new_status_value}' by {updated_by or 'an operator'}"
        )

        result = NotificationResult(alert_id=alert_id)

        if settings.ALERT_SLACK_ENABLED and settings.SLACK_WEBHOOK_URL:
            payload = {
                "text": f":arrows_counterclockwise: {summary}",
                "attachments": [
                    {
                        "color": "#0984e3",
                        "fields": [
                            {"title": "Alert", "value": f"#{alert_id}", "short": True},
                            {
                                "title": "New status",
                                "value": str(new_status_value),
                                "short": True,
                            },
                            {
                                "title": "Updated by",
                                "value": updated_by or "unknown",
                                "short": True,
                            },
                        ],
                    }
                ],
            }
            result.channels["slack"] = await self._post_json(
                settings.SLACK_WEBHOOK_URL, payload
            )

        if settings.ALERT_WEBHOOK_ENABLED and settings.WEBHOOK_URL:
            payload = {
                "event": "alert.status_changed",
                "alert_id": alert_id,
                "old_status": old_status,
                "new_status": new_status_value,
                "updated_by": updated_by,
                "timestamp": utcnow().isoformat(),
            }
            result.channels["webhook"] = await self._post_signed_webhook(payload)

        logger.info(summary)
        return result.as_dict()

    async def send_bulk_alert_notification(
        self,
        action: str,
        alert_count: int,
        updated_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Announce that a bulk action was applied to a batch of alerts."""
        summary = (
            f"{alert_count} alerts processed with action '{action}' "
            f"by {updated_by or 'an operator'}"
        )
        result = NotificationResult(alert_id=None)

        if settings.ALERT_SLACK_ENABLED and settings.SLACK_WEBHOOK_URL:
            result.channels["slack"] = await self._post_json(
                settings.SLACK_WEBHOOK_URL,
                {"text": f":package: {summary}"},
            )

        if settings.ALERT_WEBHOOK_ENABLED and settings.WEBHOOK_URL:
            result.channels["webhook"] = await self._post_signed_webhook(
                {
                    "event": "alert.bulk_action",
                    "action": action,
                    "alert_count": alert_count,
                    "updated_by": updated_by,
                    "timestamp": utcnow().isoformat(),
                }
            )

        logger.info(summary)
        return result.as_dict()

    async def send_system_notification(
        self, subject: str, body: str, severity: RiskLevel = RiskLevel.MEDIUM
    ) -> Dict[str, Any]:
        """Send an operational (non-alert) notice, e.g. degraded health."""
        result = NotificationResult(alert_id=None)

        if settings.ALERT_EMAIL_ENABLED:
            recipients = self._recipients_for(severity)
            result.channels["email"] = await asyncio.to_thread(
                self._deliver_email, recipients, subject, body, None
            )

        if settings.ALERT_SLACK_ENABLED and settings.SLACK_WEBHOOK_URL:
            result.channels["slack"] = await self._post_json(
                settings.SLACK_WEBHOOK_URL,
                {"text": f"{SEVERITY_EMOJI.get(severity, '')} *{subject}*\n{body}"},
            )

        return result.as_dict()

    # -- Channels -----------------------------------------------------------

    async def _send_email(self, alert: SecurityAlert, severity: RiskLevel) -> bool:
        """Render and send the alert email off the event loop."""
        recipients = self._recipients_for(severity)
        if not recipients:
            logger.warning("Email notifications enabled but no recipients configured")
            return False

        template = NOTIFICATION_TEMPLATES.get("email", {}).get(
            "critical_risk" if severity == RiskLevel.CRITICAL else "high_risk", {}
        )
        subject_template = template.get(
            "subject", "[{severity}] AI Security Alert - {platform}"
        )
        platform = (
            alert.interaction.platform
            if getattr(alert, "interaction", None)
            else "unknown platform"
        )
        subject = subject_template.format(
            severity=severity.value.upper(), platform=platform
        )

        text_body = self._render_text_email(alert, severity, platform)
        html_body = self._render_html_email(alert, severity, platform)

        return await asyncio.to_thread(
            self._deliver_email, recipients, subject, text_body, html_body
        )

    def _deliver_email(
        self,
        recipients: List[str],
        subject: str,
        text_body: str,
        html_body: Optional[str],
    ) -> bool:
        """Blocking SMTP send. Always called through `asyncio.to_thread`."""
        if not settings.EMAIL_USER or not settings.EMAIL_PASSWORD:
            logger.warning("SMTP credentials are not configured; skipping email")
            return False

        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = str(settings.EMAIL_FROM)
        message["To"] = ", ".join(recipients)
        message.set_content(text_body)
        if html_body:
            message.add_alternative(html_body, subtype="html")

        try:
            with smtplib.SMTP(
                settings.EMAIL_HOST, settings.EMAIL_PORT, timeout=20
            ) as smtp:
                if settings.EMAIL_USE_TLS:
                    smtp.starttls()
                smtp.login(settings.EMAIL_USER, settings.EMAIL_PASSWORD)
                smtp.send_message(message)
            logger.info(f"Alert email delivered to {len(recipients)} recipient(s)")
            return True
        except (smtplib.SMTPException, OSError) as exc:
            logger.error(f"SMTP delivery failed: {exc}")
            return False

    async def _send_slack(self, alert: SecurityAlert, severity: RiskLevel) -> bool:
        """Post a Slack attachment summarising the alert."""
        platform = (
            alert.interaction.platform
            if getattr(alert, "interaction", None)
            else "unknown"
        )
        payload = {
            "text": f"{SEVERITY_EMOJI.get(severity, '')} *{alert.title}*",
            "attachments": [
                {
                    "color": SEVERITY_COLOURS.get(severity, "#636e72"),
                    "fields": [
                        {
                            "title": "Severity",
                            "value": severity.value.upper(),
                            "short": True,
                        },
                        {"title": "Platform", "value": platform, "short": True},
                        {
                            "title": "Alert type",
                            "value": alert.alert_type or "unknown",
                            "short": True,
                        },
                        {
                            "title": "Confidence",
                            "value": f"{alert.confidence_score or 0:.0f}%",
                            "short": True,
                        },
                        {
                            "title": "Description",
                            "value": (alert.description or "No description")[:500],
                            "short": False,
                        },
                    ],
                    "footer": settings.APP_NAME,
                    "ts": int(utcnow().timestamp()),
                }
            ],
        }
        return await self._post_json(settings.SLACK_WEBHOOK_URL, payload)

    async def _send_webhook(self, alert: SecurityAlert, severity: RiskLevel) -> bool:
        """Emit the alert to a SIEM/webhook endpoint with an HMAC signature."""
        payload = {
            "event": "alert.created",
            "alert_id": alert.id,
            "alert_type": alert.alert_type,
            "severity": severity.value,
            "title": alert.title,
            "description": alert.description,
            "confidence_score": alert.confidence_score,
            "ml_confidence": alert.ml_confidence,
            "detection_rules": alert.detection_rules,
            "platform": (
                alert.interaction.platform
                if getattr(alert, "interaction", None)
                else None
            ),
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
            "timestamp": utcnow().isoformat(),
        }
        return await self._post_signed_webhook(payload)

    # -- Transport helpers --------------------------------------------------

    async def _post_json(self, url: str, payload: Dict[str, Any]) -> bool:
        try:
            async with httpx.AsyncClient(timeout=self.http_timeout) as client:
                response = await client.post(url, json=payload)
                response.raise_for_status()
            return True
        except httpx.HTTPError as exc:
            logger.error(f"Webhook POST to {self._safe_url(url)} failed: {exc}")
            return False

    async def _post_signed_webhook(self, payload: Dict[str, Any]) -> bool:
        """POST with an `X-Signature` header so the receiver can verify origin."""
        if not settings.WEBHOOK_URL:
            return False

        body = json.dumps(payload, default=str, separators=(",", ":"))
        headers = {"Content-Type": "application/json"}

        if settings.WEBHOOK_SECRET:
            signature = hmac.new(
                settings.WEBHOOK_SECRET.encode("utf-8"),
                body.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            headers["X-Signature"] = f"sha256={signature}"

        try:
            async with httpx.AsyncClient(timeout=self.http_timeout) as client:
                response = await client.post(
                    settings.WEBHOOK_URL, content=body, headers=headers
                )
                response.raise_for_status()
            return True
        except httpx.HTTPError as exc:
            logger.error(
                f"Signed webhook to {self._safe_url(settings.WEBHOOK_URL)} failed: {exc}"
            )
            return False

    # -- Policy and rendering ----------------------------------------------

    @staticmethod
    def _should_notify(severity: RiskLevel) -> bool:
        """Critical alerts always page; lower severities respect business hours."""
        if severity == RiskLevel.CRITICAL:
            return True
        if severity == RiskLevel.LOW:
            return False

        now = datetime.now()
        if now.weekday() not in settings.BUSINESS_DAYS:
            return severity == RiskLevel.HIGH
        return (
            settings.BUSINESS_HOURS_START <= now.hour < settings.BUSINESS_HOURS_END
            or (severity == RiskLevel.HIGH)
        )

    @staticmethod
    def _recipients_for(severity: RiskLevel) -> List[str]:
        """Escalate the recipient list with severity, de-duplicated."""
        recipients: List[str] = [str(r) for r in settings.ALERT_RECIPIENTS_DEFAULT]

        if severity in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            recipients += [str(r) for r in settings.ALERT_RECIPIENTS_HIGH]
        if severity == RiskLevel.CRITICAL:
            recipients += [str(r) for r in settings.ALERT_RECIPIENTS_CRITICAL]

        return list(dict.fromkeys(recipients))

    @staticmethod
    def _safe_url(url: Optional[str]) -> str:
        """Log only the host of a webhook URL - the path often carries a token."""
        if not url:
            return "unset"
        without_scheme = url.split("://", 1)[-1]
        return without_scheme.split("/", 1)[0]

    @staticmethod
    def _render_text_email(
        alert: SecurityAlert, severity: RiskLevel, platform: str
    ) -> str:
        created = alert.created_at.isoformat() if alert.created_at else "unknown"
        return (
            f"{settings.APP_NAME} security alert\n"
            f"{'=' * 60}\n\n"
            f"Severity   : {severity.value.upper()}\n"
            f"Alert ID   : {alert.id}\n"
            f"Type       : {alert.alert_type or 'unknown'}\n"
            f"Platform   : {platform}\n"
            f"Confidence : {alert.confidence_score or 0:.0f}%\n"
            f"Raised at  : {created}\n\n"
            f"{alert.title}\n\n"
            f"{alert.description or 'No description provided.'}\n\n"
            f"{'-' * 60}\n"
            "This notification contains metadata only. No prompt or response\n"
            "content is transmitted. Review the full alert in the dashboard.\n"
        )

    @staticmethod
    def _render_html_email(
        alert: SecurityAlert, severity: RiskLevel, platform: str
    ) -> str:
        colour = SEVERITY_COLOURS.get(severity, "#636e72")
        created = alert.created_at.isoformat() if alert.created_at else "unknown"
        return f"""<!doctype html>
<html>
  <body style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#f5f6fa;padding:24px;">
    <div style="max-width:640px;margin:0 auto;background:#fff;border-radius:8px;overflow:hidden;border:1px solid #dfe4ea;">
      <div style="background:{colour};color:#fff;padding:16px 24px;">
        <div style="font-size:12px;letter-spacing:.08em;text-transform:uppercase;opacity:.85;">
          {severity.value} severity
        </div>
        <div style="font-size:20px;font-weight:600;margin-top:4px;">{alert.title}</div>
      </div>
      <table style="width:100%;border-collapse:collapse;font-size:14px;">
        <tr><td style="padding:10px 24px;color:#57606f;">Alert ID</td><td style="padding:10px 24px;">{alert.id}</td></tr>
        <tr><td style="padding:10px 24px;color:#57606f;">Type</td><td style="padding:10px 24px;">{alert.alert_type or 'unknown'}</td></tr>
        <tr><td style="padding:10px 24px;color:#57606f;">Platform</td><td style="padding:10px 24px;">{platform}</td></tr>
        <tr><td style="padding:10px 24px;color:#57606f;">Confidence</td><td style="padding:10px 24px;">{alert.confidence_score or 0:.0f}%</td></tr>
        <tr><td style="padding:10px 24px;color:#57606f;">Raised at</td><td style="padding:10px 24px;">{created}</td></tr>
      </table>
      <div style="padding:16px 24px;border-top:1px solid #dfe4ea;color:#2f3542;">
        {alert.description or 'No description provided.'}
      </div>
      <div style="padding:12px 24px;background:#f1f2f6;color:#747d8c;font-size:12px;">
        Metadata only - no prompt or response content is included in this message.
      </div>
    </div>
  </body>
</html>"""
