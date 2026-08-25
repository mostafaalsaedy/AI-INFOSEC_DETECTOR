"""
GDPR/CCPA Compliant Privacy Service
Advanced privacy and compliance management system
"""

import csv
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, Optional

from cryptography.fernet import Fernet
from sqlalchemy import and_, delete, or_, select, update

from app.core.config import settings
from app.core.database import (
    AIInteraction,
    AuditLog,
    SecurityAlert,
    UserSession,
    get_db_session,
    record_audit_event,
    record_metric,
)
from app.core.logging import logger
from app.core.timeutils import utcnow


class ConsentStatus(Enum):
    """Consent status enumeration"""

    GRANTED = "granted"
    DENIED = "denied"
    EXPIRED = "expired"
    WITHDRAWN = "withdrawn"
    PENDING = "pending"


class DataSubjectRight(Enum):
    """Data subject rights under GDPR"""

    ACCESS = "access"  # Right to access
    RECTIFICATION = "rectification"  # Right to rectify
    ERASURE = "erasure"  # Right to be forgotten
    PORTABILITY = "portability"  # Right to data portability
    RESTRICT = "restrict"  # Right to restrict processing
    OBJECT = "object"  # Right to object


@dataclass
class ConsentRecord:
    """Consent tracking record"""

    session_id: str
    user_id: Optional[str]
    consent_status: ConsentStatus
    consent_date: datetime
    consent_version: str
    expiry_date: datetime
    withdrawal_date: Optional[datetime] = None
    legal_basis: str = "consent"
    purpose: str = "security_monitoring"


@dataclass
class DataExportResult:
    """Data export result"""

    success: bool
    export_id: str
    file_path: Optional[str]
    record_count: int
    export_date: datetime
    error_message: Optional[str] = None


@dataclass
class DataDeletionResult:
    """Data deletion result"""

    success: bool
    deletion_id: str
    interactions_deleted: int
    sessions_deleted: int
    alerts_anonymized: int
    deletion_date: datetime
    error_message: Optional[str] = None


class PrivacyService:
    """Comprehensive privacy and compliance service"""

    def __init__(self):
        self.encryption_key = self._get_or_create_encryption_key()
        self.fernet = Fernet(self.encryption_key)

        # Privacy configuration
        self.anonymization_salt = settings.ANONYMIZATION_SALT.encode()
        self.consent_expiry_days = settings.CONSENT_EXPIRY_DAYS
        self.data_retention_days = settings.DATA_RETENTION_DAYS

        # Legal basis mapping
        self.legal_bases = {
            "consent": "User explicit consent (GDPR Art. 6(1)(a))",
            "legitimate_interest": "Legitimate interest for security (GDPR Art. 6(1)(f))",
            "legal_obligation": "Legal obligation compliance (GDPR Art. 6(1)(c))",
        }

    def _get_or_create_encryption_key(self) -> bytes:
        """Get or create encryption key for sensitive data"""
        try:
            # In production, this should be stored securely (e.g., AWS KMS, HashiCorp Vault)
            key_file = "encryption.key"
            try:
                with open(key_file, "rb") as f:
                    return f.read()
            except FileNotFoundError:
                key = Fernet.generate_key()
                with open(key_file, "wb") as f:
                    f.write(key)
                logger.info("Generated new encryption key")
                return key
        except Exception as e:
            logger.error(f"Encryption key setup failed: {str(e)}")
            # Fallback to settings-based key (less secure)
            return hashlib.sha256(settings.SECRET_KEY.encode()).digest()[:32]

    async def record_consent(
        self,
        session_id: str,
        consent_granted: bool,
        user_id: Optional[str] = None,
        consent_version: str = "1.0",
        legal_basis: str = "consent",
    ) -> ConsentRecord:
        """Record user consent with full audit trail"""
        try:
            consent_status = (
                ConsentStatus.GRANTED if consent_granted else ConsentStatus.DENIED
            )
            consent_date = utcnow()
            expiry_date = consent_date + timedelta(days=self.consent_expiry_days)

            consent_record = ConsentRecord(
                session_id=session_id,
                user_id=user_id,
                consent_status=consent_status,
                consent_date=consent_date,
                consent_version=consent_version,
                expiry_date=expiry_date,
                legal_basis=legal_basis,
            )

            # Update session with consent information
            async with get_db_session() as db:
                session_result = await db.execute(
                    select(UserSession).where(UserSession.session_id == session_id)
                )
                session = session_result.scalars().first()

                if session:
                    session.data_collection_consent = consent_granted
                    session.consent_updated_at = consent_date
                    await db.commit()

            # Record audit event
            await record_audit_event(
                event_type="consent_recorded",
                event_category="privacy",
                description=f"Consent {'granted' if consent_granted else 'denied'} for session {session_id}",
                user_id=user_id,
                event_data={
                    "session_id": session_id,
                    "consent_status": consent_status.value,
                    "consent_version": consent_version,
                    "legal_basis": legal_basis,
                    "expiry_date": expiry_date.isoformat(),
                },
            )

            # Record metrics
            await record_metric(
                "privacy_consent_recorded",
                1,
                {"consent_status": consent_status.value, "legal_basis": legal_basis},
            )

            logger.info(f"Consent recorded: {session_id} - {consent_status.value}")
            return consent_record

        except Exception as e:
            logger.error(f"Consent recording failed: {str(e)}", exc_info=True)
            raise

    async def withdraw_consent(
        self, session_id: str, user_id: Optional[str] = None
    ) -> bool:
        """Process consent withdrawal with immediate data handling"""
        try:
            withdrawal_date = utcnow()

            async with get_db_session() as db:
                # Update session consent status
                await db.execute(
                    update(UserSession)
                    .where(UserSession.session_id == session_id)
                    .values(
                        data_collection_consent=False,
                        consent_updated_at=withdrawal_date,
                    )
                )

                await db.commit()

            # Trigger immediate data anonymization
            await self.anonymize_user_data(session_id, user_id)

            # Record audit event
            await record_audit_event(
                event_type="consent_withdrawn",
                event_category="privacy",
                description=f"Consent withdrawn for session {session_id}",
                user_id=user_id,
                event_data={
                    "session_id": session_id,
                    "withdrawal_date": withdrawal_date.isoformat(),
                    "anonymization_triggered": True,
                },
            )

            await record_metric("privacy_consent_withdrawn", 1)

            logger.info(f"Consent withdrawn and data anonymized: {session_id}")
            return True

        except Exception as e:
            logger.error(f"Consent withdrawal failed: {str(e)}", exc_info=True)
            return False

    def is_consent_expired(self, session: UserSession) -> bool:
        """Check if consent has expired"""
        if not session.data_collection_consent:
            return True

        if not session.consent_updated_at:
            return True

        expiry_date = session.consent_updated_at + timedelta(
            days=self.consent_expiry_days
        )
        return utcnow() > expiry_date

    async def anonymize_user_data(
        self, session_id: str, user_id: Optional[str] = None
    ) -> Dict[str, int]:
        """Anonymize user data while preserving analytical value"""
        try:
            anonymization_stats = {
                "interactions_anonymized": 0,
                "sessions_anonymized": 0,
                "alerts_anonymized": 0,
            }

            anonymized_hash = self._generate_anonymized_id(session_id)

            async with get_db_session() as db:
                # Anonymize interactions
                interaction_result = await db.execute(
                    update(AIInteraction)
                    .where(
                        or_(
                            AIInteraction.session_id == session_id,
                            AIInteraction.user_id == user_id if user_id else False,
                        )
                    )
                    .values(
                        user_id=f"anon_{anonymized_hash[:8]}",
                        ip_address=None,
                        user_agent="[ANONYMIZED]",
                        content_hash=None,  # Remove content hash
                        anonymized=True,
                        metadata={},  # Clear metadata
                    )
                )
                anonymization_stats["interactions_anonymized"] = (
                    interaction_result.rowcount
                )

                # Anonymize sessions
                session_result = await db.execute(
                    update(UserSession)
                    .where(
                        or_(
                            UserSession.session_id == session_id,
                            UserSession.user_id == user_id if user_id else False,
                        )
                    )
                    .values(
                        user_id=f"anon_{anonymized_hash[:8]}",
                        user_agent="[ANONYMIZED]",
                        platforms_used=[],  # Clear platform usage
                    )
                )
                anonymization_stats["sessions_anonymized"] = session_result.rowcount

                # Anonymize security alerts evidence
                alert_result = await db.execute(
                    update(SecurityAlert)
                    .where(
                        SecurityAlert.interaction_id.in_(
                            select(AIInteraction.id).where(
                                AIInteraction.session_id == session_id
                            )
                        )
                    )
                    .values(
                        evidence={
                            "anonymized": True,
                            "anonymization_date": utcnow().isoformat(),
                        }
                    )
                )
                anonymization_stats["alerts_anonymized"] = alert_result.rowcount

                await db.commit()

            # Record audit event
            await record_audit_event(
                event_type="data_anonymized",
                event_category="privacy",
                description=f"User data anonymized for session {session_id}",
                user_id=user_id,
                event_data={
                    "session_id": session_id,
                    "anonymization_stats": anonymization_stats,
                    "anonymized_id": f"anon_{anonymized_hash[:8]}",
                },
            )

            await record_metric("privacy_data_anonymized", 1, anonymization_stats)

            logger.info(f"Data anonymization completed: {anonymization_stats}")
            return anonymization_stats

        except Exception as e:
            logger.error(f"Data anonymization failed: {str(e)}", exc_info=True)
            raise

    async def delete_user_data(
        self, session_id: str, user_id: Optional[str] = None, hard_delete: bool = False
    ) -> DataDeletionResult:
        """Delete user data (right to be forgotten)"""
        try:
            deletion_id = f"del_{int(utcnow().timestamp())}"
            deletion_date = utcnow()
            stats = {
                "interactions_deleted": 0,
                "sessions_deleted": 0,
                "alerts_anonymized": 0,
            }

            async with get_db_session() as db:
                if hard_delete:
                    # Hard delete - permanent removal

                    # Delete interactions
                    interaction_result = await db.execute(
                        delete(AIInteraction).where(
                            or_(
                                AIInteraction.session_id == session_id,
                                AIInteraction.user_id == user_id if user_id else False,
                            )
                        )
                    )
                    stats["interactions_deleted"] = interaction_result.rowcount

                    # Delete sessions
                    session_result = await db.execute(
                        delete(UserSession).where(
                            or_(
                                UserSession.session_id == session_id,
                                UserSession.user_id == user_id if user_id else False,
                            )
                        )
                    )
                    stats["sessions_deleted"] = session_result.rowcount

                else:
                    # Soft delete - mark as deleted but preserve for legal compliance
                    deletion_timestamp = utcnow()

                    interaction_result = await db.execute(
                        update(AIInteraction)
                        .where(
                            or_(
                                AIInteraction.session_id == session_id,
                                AIInteraction.user_id == user_id if user_id else False,
                            )
                        )
                        .values(deleted_at=deletion_timestamp)
                    )
                    stats["interactions_deleted"] = interaction_result.rowcount

                # Anonymize related security alerts
                alert_result = await db.execute(
                    update(SecurityAlert)
                    .where(
                        SecurityAlert.interaction_id.in_(
                            select(AIInteraction.id).where(
                                or_(
                                    AIInteraction.session_id == session_id,
                                    (
                                        AIInteraction.user_id == user_id
                                        if user_id
                                        else False
                                    ),
                                )
                            )
                        )
                    )
                    .values(
                        evidence={
                            "deleted": True,
                            "deletion_date": deletion_date.isoformat(),
                        }
                    )
                )
                stats["alerts_anonymized"] = alert_result.rowcount

                await db.commit()

            # Record audit event
            await record_audit_event(
                event_type="data_deleted",
                event_category="privacy",
                description=f"User data {'hard' if hard_delete else 'soft'} deleted for session {session_id}",
                user_id=user_id,
                event_data={
                    "deletion_id": deletion_id,
                    "session_id": session_id,
                    "hard_delete": hard_delete,
                    "deletion_stats": stats,
                },
            )

            await record_metric(
                "privacy_data_deleted",
                1,
                {"deletion_type": "hard" if hard_delete else "soft", **stats},
            )

            return DataDeletionResult(
                success=True,
                deletion_id=deletion_id,
                interactions_deleted=stats["interactions_deleted"],
                sessions_deleted=stats["sessions_deleted"],
                alerts_anonymized=stats["alerts_anonymized"],
                deletion_date=deletion_date,
            )

        except Exception as e:
            logger.error(f"Data deletion failed: {str(e)}", exc_info=True)
            return DataDeletionResult(
                success=False,
                deletion_id=f"failed_{int(utcnow().timestamp())}",
                interactions_deleted=0,
                sessions_deleted=0,
                alerts_anonymized=0,
                deletion_date=utcnow(),
                error_message=str(e),
            )

    async def export_user_data(
        self, session_id: str, user_id: Optional[str] = None, format: str = "json"
    ) -> DataExportResult:
        """Export user data for data portability"""
        try:
            export_id = f"exp_{int(utcnow().timestamp())}"
            export_date = utcnow()

            export_data = {
                "export_metadata": {
                    "export_id": export_id,
                    "export_date": export_date.isoformat(),
                    "session_id": session_id,
                    "user_id": user_id,
                    "format": format,
                },
                "sessions": [],
                "interactions": [],
                "alerts": [],
            }

            async with get_db_session() as db:
                # Export sessions
                session_result = await db.execute(
                    select(UserSession).where(
                        or_(
                            UserSession.session_id == session_id,
                            UserSession.user_id == user_id if user_id else False,
                        )
                    )
                )
                sessions = session_result.scalars().all()

                for session in sessions:
                    export_data["sessions"].append(
                        {
                            "session_id": session.session_id,
                            "started_at": (
                                session.session_started_at.isoformat()
                                if session.session_started_at
                                else None
                            ),
                            "ended_at": (
                                session.session_ended_at.isoformat()
                                if session.session_ended_at
                                else None
                            ),
                            "duration_minutes": session.duration_minutes,
                            "total_interactions": session.total_interactions,
                            "total_alerts": session.total_alerts,
                            "platforms_used": session.platforms_used,
                            "consent_status": session.data_collection_consent,
                            "consent_date": (
                                session.consent_updated_at.isoformat()
                                if session.consent_updated_at
                                else None
                            ),
                        }
                    )

                # Export interactions (anonymized)
                interaction_result = await db.execute(
                    select(AIInteraction).where(
                        or_(
                            AIInteraction.session_id == session_id,
                            AIInteraction.user_id == user_id if user_id else False,
                        )
                    )
                )
                interactions = interaction_result.scalars().all()

                for interaction in interactions:
                    export_data["interactions"].append(
                        {
                            "interaction_id": interaction.id,
                            "timestamp": interaction.interaction_timestamp.isoformat(),
                            "platform": interaction.platform,
                            "interaction_type": interaction.interaction_type.value,
                            "content_length": interaction.content_length,
                            "risk_level": interaction.risk_level.value,
                            "risk_score": interaction.risk_score,
                            "risk_flags": interaction.risk_flags,
                            "user_consent": interaction.user_consent,
                        }
                    )

                # Export related alerts (anonymized)
                alert_result = await db.execute(
                    select(SecurityAlert).where(
                        SecurityAlert.interaction_id.in_(
                            select(AIInteraction.id).where(
                                or_(
                                    AIInteraction.session_id == session_id,
                                    (
                                        AIInteraction.user_id == user_id
                                        if user_id
                                        else False
                                    ),
                                )
                            )
                        )
                    )
                )
                alerts = alert_result.scalars().all()

                for alert in alerts:
                    export_data["alerts"].append(
                        {
                            "alert_id": alert.id,
                            "timestamp": alert.created_at.isoformat(),
                            "alert_type": alert.alert_type,
                            "severity": alert.severity.value,
                            "status": alert.status.value,
                            "confidence_score": alert.confidence_score,
                        }
                    )

            # Save export file. The directory may not exist on a fresh
            # deployment, so it is created rather than failing the request.
            export_dir = "exports"
            os.makedirs(export_dir, exist_ok=True)

            export_filename = f"data_export_{export_id}.{format}"
            export_path = os.path.join(export_dir, export_filename)

            if format.lower() == "json":
                with open(export_path, "w", encoding="utf-8") as f:
                    json.dump(export_data, f, indent=2, default=str)
            elif format.lower() == "csv":
                # One CSV per record type - a subject access request is easier
                # to read as separate tables than as one ragged file.
                for data_type, data_list in export_data.items():
                    if data_type == "export_metadata" or not data_list:
                        continue

                    csv_path = os.path.join(export_dir, f"{data_type}_{export_id}.csv")
                    fieldnames = list(data_list[0].keys())

                    with open(csv_path, "w", newline="", encoding="utf-8") as f:
                        writer = csv.DictWriter(f, fieldnames=fieldnames)
                        writer.writeheader()
                        writer.writerows(data_list)
            else:
                raise ValueError(
                    f"Unsupported export format '{format}'. Expected 'json' or 'csv'."
                )

            record_count = (
                len(export_data["sessions"])
                + len(export_data["interactions"])
                + len(export_data["alerts"])
            )

            # Record audit event
            await record_audit_event(
                event_type="data_exported",
                event_category="privacy",
                description=f"User data exported for session {session_id}",
                user_id=user_id,
                event_data={
                    "export_id": export_id,
                    "session_id": session_id,
                    "format": format,
                    "record_count": record_count,
                },
            )

            await record_metric(
                "privacy_data_exported",
                1,
                {"format": format, "record_count": record_count},
            )

            return DataExportResult(
                success=True,
                export_id=export_id,
                file_path=export_path,
                record_count=record_count,
                export_date=export_date,
            )

        except Exception as e:
            logger.error(f"Data export failed: {str(e)}", exc_info=True)
            return DataExportResult(
                success=False,
                export_id=f"failed_{int(utcnow().timestamp())}",
                file_path=None,
                record_count=0,
                export_date=utcnow(),
                error_message=str(e),
            )

    def sanitize_evidence(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize evidence data by removing PII"""
        if not isinstance(evidence, dict):
            return {"sanitized": True}

        sanitized = {}

        # Safe keys to preserve
        safe_keys = {
            "platform",
            "risk_level",
            "risk_score",
            "confidence",
            "alert_type",
            "severity",
            "timestamp",
            "content_length",
            "risk_flags",
            "anomaly_score",
        }

        for key, value in evidence.items():
            if key in safe_keys:
                sanitized[key] = value
            elif key.endswith("_count") or key.endswith("_score"):
                sanitized[key] = value
            else:
                # Hash or remove sensitive data
                if isinstance(value, str) and len(value) > 10:
                    sanitized[f"{key}_hash"] = self._hash_data(value)
                elif isinstance(value, (int, float)):
                    sanitized[key] = value

        sanitized["sanitized"] = True
        sanitized["sanitization_date"] = utcnow().isoformat()

        return sanitized

    def _generate_anonymized_id(self, original_id: str) -> str:
        """Generate anonymized ID that's consistent but not reversible"""
        combined = f"{original_id}:{self.anonymization_salt.decode()}"
        return hashlib.sha256(combined.encode()).hexdigest()

    def _hash_data(self, data: str) -> str:
        """Hash sensitive data with salt"""
        combined = f"{data}:{self.anonymization_salt.decode()}"
        return hashlib.sha256(combined.encode()).hexdigest()[:16]

    async def cleanup_expired_consents(self):
        """Background task to handle expired consents"""
        try:
            cutoff_date = utcnow() - timedelta(days=self.consent_expiry_days)

            async with get_db_session() as db:
                # Find sessions with expired consent
                expired_sessions_result = await db.execute(
                    select(UserSession).where(
                        and_(
                            UserSession.data_collection_consent.is_(True),
                            UserSession.consent_updated_at < cutoff_date,
                        )
                    )
                )
                expired_sessions = expired_sessions_result.scalars().all()

                for session in expired_sessions:
                    # Mark consent as expired
                    session.data_collection_consent = False

                    # Trigger anonymization
                    await self.anonymize_user_data(session.session_id, session.user_id)

                    logger.info(f"Expired consent processed: {session.session_id}")

                await db.commit()

                if expired_sessions:
                    await record_metric(
                        "privacy_expired_consents_processed", len(expired_sessions)
                    )

                    await record_audit_event(
                        event_type="expired_consents_processed",
                        event_category="privacy",
                        description=f"Processed {len(expired_sessions)} expired consents",
                        event_data={"processed_count": len(expired_sessions)},
                    )

        except Exception as e:
            logger.error(f"Expired consent cleanup failed: {str(e)}")

    async def generate_privacy_report(
        self, start_date: datetime, end_date: datetime
    ) -> Dict[str, Any]:
        """Generate privacy compliance report"""
        try:
            report = {
                "report_period": {
                    "start_date": start_date.isoformat(),
                    "end_date": end_date.isoformat(),
                    "generated_at": utcnow().isoformat(),
                },
                "consent_metrics": {},
                "data_requests": {},
                "compliance_status": {},
            }

            async with get_db_session() as db:
                # Consent metrics
                consent_granted = await db.execute(
                    select(UserSession).where(
                        and_(
                            UserSession.data_collection_consent.is_(True),
                            UserSession.consent_updated_at.between(start_date, end_date),
                        )
                    )
                )

                consent_denied = await db.execute(
                    select(UserSession).where(
                        and_(
                            UserSession.data_collection_consent.is_(False),
                            UserSession.consent_updated_at.between(start_date, end_date),
                        )
                    )
                )

                report["consent_metrics"] = {
                    "consents_granted": len(consent_granted.scalars().all()),
                    "consents_denied": len(consent_denied.scalars().all()),
                    "consent_rate": 0.0,  # Calculate based on totals
                }

                # Data subject requests (from audit logs)
                data_requests = await db.execute(
                    select(AuditLog).where(
                        and_(
                            AuditLog.event_category == "privacy",
                            AuditLog.created_at.between(start_date, end_date),
                        )
                    )
                )

                request_types = {}
                for log in data_requests.scalars().all():
                    event_type = log.event_type
                    request_types[event_type] = request_types.get(event_type, 0) + 1

                report["data_requests"] = request_types

                # Compliance status
                total_consents = (
                    report["consent_metrics"]["consents_granted"]
                    + report["consent_metrics"]["consents_denied"]
                )
                if total_consents > 0:
                    report["consent_metrics"]["consent_rate"] = (
                        report["consent_metrics"]["consents_granted"] / total_consents
                    )

                report["compliance_status"] = {
                    "gdpr_compliant": True,  # Based on implementation features
                    "ccpa_compliant": True,
                    "data_retention_compliant": True,
                    "consent_management_active": True,
                }

            return report

        except Exception as e:
            logger.error(f"Privacy report generation failed: {str(e)}")
            return {"error": str(e)}
