"""
Configuration management with Pydantic Settings
"""

import os
from typing import List, Optional

from pydantic import EmailStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable support"""

    # Application
    APP_NAME: str = "InfoSec AI Monitor"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Security
    # NOTE: the defaults below are development-only placeholders. Production
    # deployments MUST override them (see .env.example); ProductionSettings
    # refuses to start while they are still in place.
    SECRET_KEY: str = "dev-insecure-secret-key-change-me"
    EXTENSION_SECRET: str = "dev-insecure-extension-secret-change-me"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    ALGORITHM: str = "HS256"

    # Database
    DATABASE_URL: str = (
        "postgresql+asyncpg://infosec:infosec@localhost:5432/infosec_ai_monitor"
    )
    DATABASE_ECHO: bool = False  # log every SQL statement (very verbose)
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_CACHE_TTL: int = 3600

    # Celery
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/1"

    # CORS
    ALLOWED_ORIGINS: List[str] = ["https://localhost:3000"]
    ALLOWED_HOSTS: List[str] = ["localhost", "127.0.0.1"]

    # Data Retention & Privacy
    DATA_RETENTION_DAYS: int = 365
    CONSENT_EXPIRY_DAYS: int = 180
    ANONYMIZATION_SALT: str = "dev-insecure-anonymization-salt-change-me"

    # Email Configuration
    EMAIL_HOST: str = "smtp.gmail.com"
    EMAIL_PORT: int = 587
    EMAIL_USER: Optional[str] = None
    EMAIL_PASSWORD: Optional[str] = None
    EMAIL_USE_TLS: bool = True
    EMAIL_FROM: EmailStr = "security@company.com"

    # Alert Configuration
    ALERT_EMAIL_ENABLED: bool = True
    ALERT_SLACK_ENABLED: bool = False
    ALERT_WEBHOOK_ENABLED: bool = False

    # Alert Recipients
    ALERT_RECIPIENTS_DEFAULT: List[EmailStr] = ["security@company.com"]
    ALERT_RECIPIENTS_CRITICAL: List[EmailStr] = ["ciso@company.com"]
    ALERT_RECIPIENTS_HIGH: List[EmailStr] = ["security-team@company.com"]

    # Slack Configuration
    SLACK_WEBHOOK_URL: Optional[str] = None
    SLACK_BOT_TOKEN: Optional[str] = None

    # Webhook Configuration
    WEBHOOK_URL: Optional[str] = None
    WEBHOOK_SECRET: Optional[str] = None

    # ML Configuration
    ML_MODEL_PATH: str = "models/"
    ML_BATCH_SIZE: int = 32
    ML_CONFIDENCE_THRESHOLD: float = 0.7
    ML_RETRAIN_INTERVAL_HOURS: int = 24

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 100
    RATE_LIMIT_BURST: int = 20

    # Monitoring
    ENABLE_METRICS: bool = True
    LOG_LEVEL: str = "INFO"

    # Business Hours for Alerts
    BUSINESS_HOURS_START: int = 9
    BUSINESS_HOURS_END: int = 17
    BUSINESS_DAYS: List[int] = [0, 1, 2, 3, 4]  # Monday-Friday

    # File Upload
    MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10MB
    UPLOAD_PATH: str = "uploads/"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    @field_validator("SECRET_KEY", "EXTENSION_SECRET", "ANONYMIZATION_SALT")
    @classmethod
    def secret_must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Security secrets must be set to a non-empty value")
        return v

    @field_validator("DATABASE_URL")
    @classmethod
    def database_url_must_be_supported(cls, v: str) -> str:
        supported = (
            "postgresql://",
            "postgresql+asyncpg://",
            "sqlite://",
            "sqlite+aiosqlite://",
        )
        if not v.startswith(supported):
            raise ValueError(
                "DATABASE_URL must be a PostgreSQL URL (asyncpg) or a SQLite URL "
                f"(aiosqlite). Got: {v.split('://')[0]}://"
            )
        return v

    @field_validator("ALLOWED_ORIGINS", "ALLOWED_HOSTS")
    @classmethod
    def list_must_not_be_empty(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("At least one entry must be specified")
        return v

    @property
    def is_async_sqlite(self) -> bool:
        """True when running against SQLite (used to skip pool tuning)."""
        return self.DATABASE_URL.startswith("sqlite")


class DevelopmentSettings(Settings):
    """Development-specific settings"""

    DEBUG: bool = True
    LOG_LEVEL: str = "DEBUG"
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3000",
    ]


class ProductionSettings(Settings):
    """Production-specific settings"""

    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    @field_validator("ALLOWED_ORIGINS")
    @classmethod
    def prod_origins_must_be_https(cls, v: List[str]) -> List[str]:
        for origin in v:
            if not origin.startswith("https://"):
                raise ValueError(f"Production origins must use HTTPS: {origin}")
        return v

    @field_validator("SECRET_KEY", "EXTENSION_SECRET", "ANONYMIZATION_SALT")
    @classmethod
    def prod_secrets_must_be_overridden(cls, v: str) -> str:
        if "dev-insecure" in v:
            raise ValueError(
                "Development placeholder secrets detected. Set SECRET_KEY, "
                "EXTENSION_SECRET and ANONYMIZATION_SALT to real values before "
                "running with ENVIRONMENT=production."
            )
        if len(v) < 32:
            raise ValueError("Production secrets must be at least 32 characters long")
        return v


class TestingSettings(Settings):
    """Testing-specific settings"""

    DEBUG: bool = True
    DATABASE_URL: str = "sqlite+aiosqlite:///:memory:"
    ALLOWED_HOSTS: List[str] = ["localhost", "127.0.0.1", "testserver"]
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000"]
    REDIS_URL: str = "redis://localhost:6379/15"  # Use separate DB for testing

    # Disable external services in testing
    ALERT_EMAIL_ENABLED: bool = False
    ALERT_SLACK_ENABLED: bool = False
    ALERT_WEBHOOK_ENABLED: bool = False


def get_settings() -> Settings:
    """Factory function to get settings based on environment"""
    environment = os.getenv("ENVIRONMENT", "development").lower()

    if environment == "production":
        return ProductionSettings()
    elif environment == "testing":
        return TestingSettings()
    else:
        return DevelopmentSettings()


# Global settings instance
settings = get_settings()


# ML Model Configuration
ML_MODELS = {
    "risk_classifier": {
        "model_type": "transformers",
        "model_name": "distilbert-base-uncased",
        "num_labels": 4,  # low, medium, high, critical
        "max_length": 512,
    },
    "anomaly_detector": {
        "model_type": "sklearn",
        "algorithm": "isolation_forest",
        "contamination": 0.1,
    },
    "content_classifier": {"model_type": "spacy", "model_name": "en_core_web_sm"},
}

# Risk Analysis Patterns
RISK_PATTERNS = {
    "credit_card": {
        "pattern": r"\b(?:\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}|\d{4}[-\s]?\d{6}[-\s]?\d{5})\b",
        "weight": 10,
        "category": "financial",
    },
    "ssn": {"pattern": r"\b\d{3}-\d{2}-\d{4}\b", "weight": 10, "category": "personal"},
    "email": {
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "weight": 3,
        "category": "personal",
    },
    "api_key": {
        "pattern": r"\b(?:api[_-]?key|access[_-]?token|secret[_-]?key)\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{20,})['\"]?",
        "weight": 9,
        "category": "credentials",
    },
    "password": {
        "pattern": r"\b(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{6,})['\"]?",
        "weight": 8,
        "category": "credentials",
    },
    "confidential": {
        "pattern": r"\b(?:confidential|internal|proprietary|classified|restricted)\b",
        "weight": 6,
        "category": "classification",
    },
    "security_terms": {
        "pattern": r"\b(?:hack|exploit|vulnerability|penetration|malware|backdoor)\b",
        "weight": 7,
        "category": "security",
    },
}

# AI Platform Configurations
AI_PLATFORMS = {
    "openai.com": {
        "name": "ChatGPT",
        "selectors": {
            "input": "textarea[placeholder*='message'], textarea#prompt-textarea",
            "response": ".markdown-content, .message-content",
        },
        "risk_multiplier": 1.0,
    },
    "claude.ai": {
        "name": "Claude",
        "selectors": {
            "input": "[contenteditable='true'], textarea",
            "response": ".prose, .response-body",
        },
        "risk_multiplier": 1.0,
    },
    "deepseek.com": {
        "name": "DeepSeek",
        "selectors": {
            "input": "textarea, [contenteditable='true']",
            "response": ".message-content, .response-text",
        },
        "risk_multiplier": 1.1,
    },
}

# Notification Templates
NOTIFICATION_TEMPLATES = {
    "email": {
        "high_risk": {
            "subject": "[HIGH RISK] AI Security Alert - {platform}",
            "template": "templates/email/high_risk_alert.html",
        },
        "critical_risk": {
            "subject": "[CRITICAL] Immediate Security Alert - {platform}",
            "template": "templates/email/critical_alert.html",
        },
    },
    "slack": {
        "high_risk": {"color": "#ff6b35", "emoji": ":warning:"},
        "critical_risk": {"color": "#d63031", "emoji": ":rotating_light:"},
    },
}
