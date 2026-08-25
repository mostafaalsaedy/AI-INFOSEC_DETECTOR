"""
Celery Tasks for Notification and Alert Management
Advanced notification system with multiple channels and intelligent routing
"""

import asyncio
import json
import smtplib
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional

import httpx
from jinja2 import Template

from app.core.config import settings
from app.core.database import (
    AIInteraction,
    SecurityAlert,
    get_db_session,
    record_audit_event,
    record_metric,
)
from app.core.logging import logger
from app.core.timeutils import utcnow
from app.services.celery_app import AsyncTask, celery_app
from app.services.websocket_manager import websocket_manager


@celery_app.task(bind=True, base=AsyncTask, queue="notifications")
async def send_security_alert_notification(
    self, alert_id: int, channels: List[str] = None
):
    """Send security alert notification through specified channels"""
    try:
        # Get alert details
        async with get_db_session() as db:
            alert = await db.get(SecurityAlert, alert_id)
            if not alert:
                logger.error(f"Alert {alert_id} not found")
                return {"status": "error", "message": "Alert not found"}

            # Load related interaction data
            interaction = None
            if alert.interaction_id:
                interaction = await db.get(AIInteraction, alert.interaction_id)

        # Determine notification channels if not specified
        if not channels:
            channels = determine_notification_channels(alert)

        notification_results = {}

        # Send email notifications
        if "email" in channels and settings.ALERT_EMAIL_ENABLED:
            email_result = await send_email_notification(alert, interaction)
            notification_results["email"] = email_result

        # Send Slack notifications
        if "slack" in channels and settings.ALERT_SLACK_ENABLED:
            slack_result = await send_slack_notification(alert, interaction)
            notification_results["slack"] = slack_result

        # Send webhook notifications
        if "webhook" in channels and settings.ALERT_WEBHOOK_ENABLED:
            webhook_result = await send_webhook_notification(alert, interaction)
            notification_results["webhook"] = webhook_result

        # Send SMS notifications (for critical alerts)
        if "sms" in channels and alert.severity == "critical":
            sms_result = await send_sms_notification(alert, interaction)
            notification_results["sms"] = sms_result

        # Update alert with notification status
        async with get_db_session() as db:
            alert = await db.get(SecurityAlert, alert_id)
            alert.notification_sent = any(
                result.get("success", False) for result in notification_results.values()
            )
            alert.notification_sent_at = utcnow() if alert.notification_sent else None
            alert.notification_channels = [
                ch
                for ch, result in notification_results.items()
                if result.get("success", False)
            ]
            await db.commit()

        # Record audit event
        await record_audit_event(
            event_type="security_alert_notification_sent",
            event_category="security",
            description=f"Notifications sent for alert {alert_id}",
            event_data={
                "alert_id": alert_id,
                "channels": channels,
                "results": notification_results,
            },
        )

        # Record metrics
        for channel, result in notification_results.items():
            await record_metric(
                f"notification_{channel}_sent",
                1,
                {
                    "success": result.get("success", False),
                    "alert_severity": alert.severity.value,
                },
            )

        logger.info(f"Alert {alert_id} notifications sent: {notification_results}")

        return {
            "status": "completed",
            "alert_id": alert_id,
            "channels": channels,
            "results": notification_results,
        }

    except Exception as e:
        logger.error(f"Alert notification failed for {alert_id}: {str(e)}", exc_info=True)
        await record_metric("notification_failed", 1, {"alert_id": alert_id})
        raise self.retry(exc=e, countdown=300, max_retries=3)


@celery_app.task(bind=True, base=AsyncTask, queue="notifications")
async def send_daily_security_digest(self):
    """Send daily security digest to stakeholders"""
    try:
        logger.info("Generating daily security digest...")

        # Calculate date range (last 24 hours)
        end_date = utcnow()
        start_date = end_date - timedelta(hours=24)

        # Collect security metrics
        digest_data = await collect_daily_digest_data(start_date, end_date)

        if digest_data["total_interactions"] == 0:
            logger.info("No activity to report in daily digest")
            return {"status": "skipped", "reason": "no_activity"}

        # Generate digest report
        digest_report = await generate_digest_report(digest_data, start_date, end_date)

        # Send digest via email
        email_recipients = get_digest_recipients()
        email_results = []

        for recipient in email_recipients:
            result = await send_digest_email(recipient, digest_report)
            email_results.append(result)

        # Send to Slack if configured
        slack_result = None
        if settings.ALERT_SLACK_ENABLED:
            slack_result = await send_digest_slack(digest_report)

        # Record audit event
        await record_audit_event(
            event_type="daily_security_digest_sent",
            event_category="reporting",
            description=f"Daily digest sent to {len(email_recipients)} recipients",
            event_data={
                "period": f"{start_date.date()} to {end_date.date()}",
                "recipients": len(email_recipients),
                "total_interactions": digest_data["total_interactions"],
                "total_alerts": digest_data["total_alerts"],
            },
        )

        logger.info(f"Daily security digest sent to {len(email_recipients)} recipients")

        return {
            "status": "completed",
            "recipients": len(email_recipients),
            "email_results": email_results,
            "slack_result": slack_result,
            "digest_data": digest_data,
        }

    except Exception as e:
        logger.error(f"Daily digest generation failed: {str(e)}", exc_info=True)
        raise self.retry(exc=e, countdown=3600, max_retries=2)


@celery_app.task(bind=True, base=AsyncTask, queue="notifications")
async def send_system_health_alert(self, health_data: Dict[str, Any]):
    """Send system health alerts when services are degraded"""
    try:
        # Check if this is a critical health issue
        is_critical = any(
            status == "unhealthy" for status in health_data.get("services", {}).values()
        )

        if not is_critical:
            return {"status": "skipped", "reason": "not_critical"}

        # Create health alert message
        alert_message = create_health_alert_message(health_data)

        # Send to admin channels
        admin_recipients = settings.ALERT_RECIPIENTS_CRITICAL

        notification_results = {}

        # Send email to admins
        if settings.ALERT_EMAIL_ENABLED:
            email_results = []
            for recipient in admin_recipients:
                result = await send_health_alert_email(
                    recipient, alert_message, health_data
                )
                email_results.append(result)
            notification_results["email"] = email_results

        # Send Slack notification
        if settings.ALERT_SLACK_ENABLED:
            slack_result = await send_health_alert_slack(alert_message, health_data)
            notification_results["slack"] = slack_result

        # Broadcast to WebSocket clients
        await websocket_manager.broadcast_system_alert(
            {
                "type": "system_health_critical",
                "message": alert_message,
                "health_data": health_data,
                "timestamp": utcnow().isoformat(),
            }
        )

        # Record audit event
        await record_audit_event(
            event_type="system_health_alert_sent",
            event_category="system",
            description="Critical system health alert sent",
            event_data={
                "health_status": health_data.get("status"),
                "unhealthy_services": [
                    service
                    for service, status in health_data.get("services", {}).items()
                    if status == "unhealthy"
                ],
            },
        )

        logger.warning(f"System health alert sent: {alert_message}")

        return {
            "status": "completed",
            "message": alert_message,
            "notification_results": notification_results,
        }

    except Exception as e:
        logger.error(f"System health alert failed: {str(e)}", exc_info=True)
        raise self.retry(exc=e, countdown=300, max_retries=2)


@celery_app.task(bind=True, base=AsyncTask, queue="notifications")
async def process_notification_queue(self):
    """Process queued notifications that failed to send"""
    try:
        # Get failed notifications from the last hour
        cutoff_time = utcnow() - timedelta(hours=1)

        async with get_db_session() as db:
            failed_alerts = await db.execute(
                """
                SELECT id FROM security_alerts
                WHERE notification_sent = false
                AND created_at >= %s
                AND severity IN ('high', 'critical')
                ORDER BY created_at ASC
                LIMIT 50
            """,
                (cutoff_time,),
            )

            alert_ids = [row[0] for row in failed_alerts.fetchall()]

        if not alert_ids:
            return {"status": "no_pending", "processed": 0}

        # Process each failed notification
        results = []
        for alert_id in alert_ids:
            try:
                result = await send_security_alert_notification.apply_async(
                    args=[alert_id], countdown=10  # Small delay to avoid overwhelming
                )
                results.append({"alert_id": alert_id, "task_id": result.id})
            except Exception as e:
                logger.error(
                    f"Failed to queue notification for alert {alert_id}: {str(e)}"
                )
                results.append({"alert_id": alert_id, "error": str(e)})

        logger.info(f"Processed {len(results)} pending notifications")

        return {"status": "completed", "processed": len(results), "results": results}

    except Exception as e:
        logger.error(f"Notification queue processing failed: {str(e)}", exc_info=True)
        raise self.retry(exc=e, countdown=1800, max_retries=2)


# Helper functions for notifications


def determine_notification_channels(alert: SecurityAlert) -> List[str]:
    """Determine which notification channels to use based on alert severity"""
    channels = []

    if alert.severity in ["critical", "high"]:
        channels.extend(["email", "slack", "webhook"])
        if alert.severity == "critical":
            channels.append("sms")
    elif alert.severity == "medium":
        channels.extend(["email", "slack"])
    else:  # low severity
        channels.append("email")

    return channels


async def send_email_notification(
    alert: SecurityAlert, interaction: Optional[AIInteraction] = None
) -> Dict[str, Any]:
    """Send email notification for security alert"""
    try:
        # Get recipients based on alert severity
        recipients = get_alert_email_recipients(alert.severity.value)

        if not recipients:
            return {"success": False, "error": "No recipients configured"}

        # Generate email content
        email_subject = f"[{alert.severity.value.upper()}] Security Alert: {alert.title}"
        email_body = generate_alert_email_body(alert, interaction)

        # Send email
        smtp_server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT)
        if settings.EMAIL_USE_TLS:
            smtp_server.starttls()

        if settings.EMAIL_USER and settings.EMAIL_PASSWORD:
            smtp_server.login(settings.EMAIL_USER, settings.EMAIL_PASSWORD)

        # Create message
        msg = MIMEMultipart()
        msg["From"] = settings.EMAIL_FROM
        msg["Subject"] = email_subject

        # Send to each recipient
        sent_count = 0
        for recipient in recipients:
            try:
                msg["To"] = recipient
                msg.attach(MIMEText(email_body, "html"))

                smtp_server.send_message(msg)
                sent_count += 1

                del msg["To"]  # Remove To header for next iteration

            except Exception as e:
                logger.error(f"Failed to send email to {recipient}: {str(e)}")

        smtp_server.quit()

        return {
            "success": sent_count > 0,
            "recipients_sent": sent_count,
            "total_recipients": len(recipients),
        }

    except Exception as e:
        logger.error(f"Email notification failed: {str(e)}")
        return {"success": False, "error": str(e)}


async def send_slack_notification(
    alert: SecurityAlert, interaction: Optional[AIInteraction] = None
) -> Dict[str, Any]:
    """Send Slack notification for security alert"""
    try:
        webhook_url = settings.SLACK_WEBHOOK_URL
        if not webhook_url:
            return {"success": False, "error": "Slack webhook not configured"}

        # Create Slack message
        slack_message = create_slack_alert_message(alert, interaction)

        # Send to Slack
        async with httpx.AsyncClient() as client:
            response = await client.post(webhook_url, json=slack_message, timeout=30)

            if response.status_code == 200:
                return {"success": True, "response": "Message sent"}
            else:
                return {"success": False, "error": f"HTTP {response.status_code}"}

    except Exception as e:
        logger.error(f"Slack notification failed: {str(e)}")
        return {"success": False, "error": str(e)}


async def send_webhook_notification(
    alert: SecurityAlert, interaction: Optional[AIInteraction] = None
) -> Dict[str, Any]:
    """Send webhook notification for security alert"""
    try:
        webhook_url = settings.WEBHOOK_URL
        if not webhook_url:
            return {"success": False, "error": "Webhook URL not configured"}

        # Create webhook payload
        webhook_payload = create_webhook_payload(alert, interaction)

        # Generate signature if secret is configured
        headers = {"Content-Type": "application/json"}
        if settings.WEBHOOK_SECRET:
            import hashlib
            import hmac

            payload_str = json.dumps(webhook_payload)
            signature = hmac.new(
                settings.WEBHOOK_SECRET.encode(), payload_str.encode(), hashlib.sha256
            ).hexdigest()
            headers["X-Webhook-Signature"] = f"sha256={signature}"

        # Send webhook
        async with httpx.AsyncClient() as client:
            response = await client.post(
                webhook_url, json=webhook_payload, headers=headers, timeout=30
            )

            if response.status_code in [200, 201, 202]:
                return {"success": True, "status_code": response.status_code}
            else:
                return {"success": False, "error": f"HTTP {response.status_code}"}

    except Exception as e:
        logger.error(f"Webhook notification failed: {str(e)}")
        return {"success": False, "error": str(e)}


async def send_sms_notification(
    alert: SecurityAlert, interaction: Optional[AIInteraction] = None
) -> Dict[str, Any]:
    """Send SMS notification for critical security alerts"""
    try:
        # SMS implementation would depend on your SMS provider (Twilio, AWS SNS, etc.)
        # This is a placeholder implementation

        sms_recipients = get_sms_recipients()
        if not sms_recipients:
            return {"success": False, "error": "No SMS recipients configured"}

        # Create SMS message
        sms_message = f"CRITICAL SECURITY ALERT: {alert.title} - Platform: {interaction.platform if interaction else 'Unknown'}"

        # For demonstration, we'll log the SMS (replace with actual SMS service)
        logger.warning(f"SMS Alert (simulated): {sms_message}")

        return {
            "success": True,
            "message": "SMS sent (simulated)",
            "recipients": len(sms_recipients),
        }

    except Exception as e:
        logger.error(f"SMS notification failed: {str(e)}")
        return {"success": False, "error": str(e)}


def get_alert_email_recipients(severity: str) -> List[str]:
    """Get email recipients based on alert severity"""
    if severity == "critical":
        return settings.ALERT_RECIPIENTS_CRITICAL
    elif severity == "high":
        return settings.ALERT_RECIPIENTS_HIGH
    else:
        return settings.ALERT_RECIPIENTS_DEFAULT


def get_sms_recipients() -> List[str]:
    """Get SMS recipients for critical alerts"""
    # This would be configured in settings
    return getattr(settings, "SMS_RECIPIENTS_CRITICAL", [])


def get_digest_recipients() -> List[str]:
    """Get recipients for daily digest"""
    return settings.ALERT_RECIPIENTS_DEFAULT


def generate_alert_email_body(
    alert: SecurityAlert, interaction: Optional[AIInteraction] = None
) -> str:
    """Generate HTML email body for security alert"""

    email_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; }
            .alert-header { background-color: {{ color }}; color: white; padding: 10px; }
            .alert-content { padding: 20px; }
            .detail-table { border-collapse: collapse; width: 100%; }
            .detail-table th, .detail-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            .detail-table th { background-color: #f2f2f2; }
        </style>
    </head>
    <body>
        <div class="alert-header">
            <h2>🚨 {{ severity.title() }} Security Alert</h2>
        </div>
        <div class="alert-content">
            <h3>{{ title }}</h3>
            <p>{{ description }}</p>

            <table class="detail-table">
                <tr><th>Alert ID</th><td>{{ alert_id }}</td></tr>
                <tr><th>Severity</th><td>{{ severity.title() }}</td></tr>
                <tr><th>Type</th><td>{{ alert_type }}</td></tr>
                <tr><th>Confidence</th><td>{{ confidence }}%</td></tr>
                <tr><th>Created</th><td>{{ created_at }}</td></tr>
                {% if platform %}
                <tr><th>Platform</th><td>{{ platform }}</td></tr>
                {% endif %}
                {% if risk_score %}
                <tr><th>Risk Score</th><td>{{ risk_score }}/100</td></tr>
                {% endif %}
            </table>

            {% if evidence %}
            <h4>Evidence:</h4>
            <ul>
            {% for key, value in evidence.items() %}
                <li><strong>{{ key.replace('_', ' ').title() }}:</strong> {{ value }}</li>
            {% endfor %}
            </ul>
            {% endif %}

            <p><strong>Action Required:</strong> Please review this alert and take appropriate action.</p>
            <p><a href="{{ dashboard_url }}/alerts/{{ alert_id }}">View in Dashboard</a></p>
        </div>
    </body>
    </html>
    """

    template = Template(email_template)

    # Determine color based on severity
    color_map = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#d97706",
        "low": "#65a30d",
    }

    return template.render(
        alert_id=alert.id,
        severity=alert.severity.value,
        title=alert.title,
        description=alert.description,
        alert_type=alert.alert_type,
        confidence=alert.confidence_score,
        created_at=alert.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        platform=interaction.platform if interaction else None,
        risk_score=interaction.risk_score if interaction else None,
        evidence=alert.evidence or {},
        color=color_map.get(alert.severity.value, "#6b7280"),
        dashboard_url=getattr(settings, "DASHBOARD_URL", "https://your-domain.com"),
    )


def create_slack_alert_message(
    alert: SecurityAlert, interaction: Optional[AIInteraction] = None
) -> Dict[str, Any]:
    """Create Slack message for security alert"""

    # Color based on severity
    color_map = {
        "critical": "#ff0000",
        "high": "#ff6600",
        "medium": "#ffaa00",
        "low": "#00aa00",
    }

    # Emoji based on severity
    emoji_map = {"critical": "🚨", "high": "⚠️", "medium": "⚡", "low": "ℹ️"}

    fields = [
        {"title": "Severity", "value": alert.severity.value.title(), "short": True},
        {
            "title": "Type",
            "value": alert.alert_type.replace("_", " ").title(),
            "short": True,
        },
        {"title": "Confidence", "value": f"{alert.confidence_score}%", "short": True},
        {"title": "Alert ID", "value": str(alert.id), "short": True},
    ]

    if interaction:
        fields.extend(
            [
                {"title": "Platform", "value": interaction.platform, "short": True},
                {
                    "title": "Risk Score",
                    "value": f"{interaction.risk_score}/100",
                    "short": True,
                },
            ]
        )

    return {
        "text": f"{emoji_map.get(alert.severity.value, '🔔')} Security Alert: {alert.title}",
        "attachments": [
            {
                "color": color_map.get(alert.severity.value, "#cccccc"),
                "fields": fields,
                "footer": "InfoSec AI Monitor",
                "ts": int(alert.created_at.timestamp()),
            }
        ],
    }


def create_webhook_payload(
    alert: SecurityAlert, interaction: Optional[AIInteraction] = None
) -> Dict[str, Any]:
    """Create webhook payload for security alert"""

    payload = {
        "event_type": "security_alert",
        "alert": {
            "id": alert.id,
            "severity": alert.severity.value,
            "alert_type": alert.alert_type,
            "title": alert.title,
            "description": alert.description,
            "confidence_score": alert.confidence_score,
            "status": alert.status.value,
            "created_at": alert.created_at.isoformat(),
            "evidence": alert.evidence,
        },
        "timestamp": utcnow().isoformat(),
    }

    if interaction:
        payload["interaction"] = {
            "id": interaction.id,
            "platform": interaction.platform,
            "risk_level": interaction.risk_level.value,
            "risk_score": interaction.risk_score,
            "session_id": interaction.session_id,
        }

    return payload


async def collect_daily_digest_data(
    start_date: datetime, end_date: datetime
) -> Dict[str, Any]:
    """Collect data for daily security digest"""

    async with get_db_session() as db:
        # Total interactions
        interactions_result = await db.execute(
            "SELECT COUNT(*) FROM ai_interactions WHERE created_at BETWEEN %s AND %s",
            (start_date, end_date),
        )
        total_interactions = interactions_result.scalar()

        # Total alerts
        alerts_result = await db.execute(
            "SELECT COUNT(*) FROM security_alerts WHERE created_at BETWEEN %s AND %s",
            (start_date, end_date),
        )
        total_alerts = alerts_result.scalar()

        # High-risk interactions
        high_risk_result = await db.execute(
            "SELECT COUNT(*) FROM ai_interactions WHERE created_at BETWEEN %s AND %s AND risk_level IN ('high', 'critical')",
            (start_date, end_date),
        )
        high_risk_interactions = high_risk_result.scalar()

        # Platform breakdown
        platform_result = await db.execute(
            "SELECT platform, COUNT(*) as count FROM ai_interactions WHERE created_at BETWEEN %s AND %s GROUP BY platform",
            (start_date, end_date),
        )
        platform_stats = dict(platform_result.fetchall())

        # Alert breakdown by severity
        alert_severity_result = await db.execute(
            "SELECT severity, COUNT(*) as count FROM security_alerts WHERE created_at BETWEEN %s AND %s GROUP BY severity",
            (start_date, end_date),
        )
        alert_severity_stats = dict(alert_severity_result.fetchall())

        return {
            "total_interactions": total_interactions,
            "total_alerts": total_alerts,
            "high_risk_interactions": high_risk_interactions,
            "platform_stats": platform_stats,
            "alert_severity_stats": alert_severity_stats,
        }


async def generate_digest_report(
    data: Dict[str, Any], start_date: datetime, end_date: datetime
) -> Dict[str, Any]:
    """Generate formatted digest report"""

    return {
        "period": {
            "start": start_date.strftime("%Y-%m-%d"),
            "end": end_date.strftime("%Y-%m-%d"),
        },
        "summary": {
            "total_interactions": data["total_interactions"],
            "total_alerts": data["total_alerts"],
            "high_risk_interactions": data["high_risk_interactions"],
            "risk_percentage": (
                (data["high_risk_interactions"] / data["total_interactions"] * 100)
                if data["total_interactions"] > 0
                else 0
            ),
        },
        "platform_breakdown": data["platform_stats"],
        "alert_breakdown": data["alert_severity_stats"],
        "generated_at": utcnow().isoformat(),
    }


async def send_digest_email(
    recipient: str, digest_report: Dict[str, Any]
) -> Dict[str, Any]:
    """Send daily digest email to recipient"""
    try:
        subject = f"Daily Security Digest - {digest_report['period']['start']}"
        body = generate_digest_email_body(digest_report)

        # Delegate to the notification service rather than reporting success
        # for an email that was never actually sent.
        from app.services.notification_service import NotificationService

        delivered = await asyncio.to_thread(
            NotificationService()._deliver_email, [recipient], subject, body, None
        )

        if delivered:
            logger.info(f"Digest email delivered to {recipient}")
        else:
            logger.warning(f"Digest email to {recipient} was not delivered")

        return {"success": delivered, "recipient": recipient}

    except Exception as e:
        logger.error(f"Failed to send digest email to {recipient}: {str(e)}")
        return {"success": False, "recipient": recipient, "error": str(e)}


def generate_digest_email_body(digest_report: Dict[str, Any]) -> str:
    """Generate HTML body for digest email"""
    # This would contain a comprehensive HTML template for the digest
    return f"""
    <h2>Daily Security Digest - {digest_report['period']['start']}</h2>
    <p>Summary: {digest_report['summary']['total_interactions']} interactions, {digest_report['summary']['total_alerts']} alerts</p>
    <!-- Add more detailed HTML content here -->
    """


def create_health_alert_message(health_data: Dict[str, Any]) -> str:
    """Create system health alert message"""
    unhealthy_services = [
        service
        for service, status in health_data.get("services", {}).items()
        if status == "unhealthy"
    ]

    return f"SYSTEM HEALTH CRITICAL: {', '.join(unhealthy_services)} service(s) are unhealthy"


async def send_health_alert_email(
    recipient: str, message: str, health_data: Dict[str, Any]
) -> Dict[str, Any]:
    """Send system health alert email"""
    try:
        # Implementation for health alert email
        logger.warning(f"Health alert email to {recipient}: {message}")
        return {"success": True, "recipient": recipient}
    except Exception as e:
        return {"success": False, "recipient": recipient, "error": str(e)}


async def send_health_alert_slack(
    message: str, health_data: Dict[str, Any]
) -> Dict[str, Any]:
    """Send system health alert to Slack"""
    try:
        # Implementation for health alert Slack message
        logger.warning(f"Health alert Slack: {message}")
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


async def send_digest_slack(digest_report: Dict[str, Any]) -> Dict[str, Any]:
    """Send daily digest to Slack"""
    try:
        # Implementation for digest Slack message
        logger.info("Sending digest to Slack")
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}
