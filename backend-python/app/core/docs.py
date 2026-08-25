"""
API Documentation Configuration
OpenAPI/Swagger documentation setup for InfoSec AI Monitor
"""

from typing import Any, Dict

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

# API Documentation Metadata
API_TITLE = "InfoSec AI Monitor API"
API_VERSION = "1.0.0"
API_DESCRIPTION = """
# InfoSec AI Monitor API

Advanced AI platform monitoring system for enterprise security and compliance.

## Features

* **Real-time Monitoring** - Monitor AI platform usage across ChatGPT, Claude, and other platforms
* **ML-Powered Risk Analysis** - Advanced machine learning models for risk detection and classification
* **Privacy Compliance** - Full GDPR/CCPA compliance with consent management and data protection
* **Real-time Alerts** - WebSocket-based real-time security alert notifications
* **Comprehensive Analytics** - Detailed analytics and reporting on AI usage patterns
* **Enterprise Security** - Role-based access control, audit logging, and security hardening

## Authentication

The API uses Bearer token authentication. Include your API token in the Authorization header:

```
Authorization: Bearer your-api-token-here
```

## Rate Limiting

API requests are rate limited to prevent abuse:
- **Standard endpoints**: 1000 requests per hour per API key
- **Data collection endpoints**: 5000 requests per hour per API key
- **Analytics endpoints**: 500 requests per hour per API key

## Data Privacy

This API is designed with privacy-first principles:
- All user content is hashed and never stored in plain text
- Consent is required for all data processing
- Data retention policies are automatically enforced
- GDPR/CCPA compliance features are built-in

## Support

For technical support or questions about the API, please contact:
- **Documentation**: [API Documentation Portal](https://docs.infosecmonitor.ai)
- **Support Email**: support@infosecmonitor.ai
- **GitHub Issues**: [Report Issues](https://github.com/company/infosec-ai-monitor/issues)
"""

API_TAGS_METADATA = [
    {
        "name": "Health",
        "description": "API health check and system status endpoints",
    },
    {
        "name": "Data Collection",
        "description": "Endpoints for collecting AI platform interaction data",
        "externalDocs": {
            "description": "Data Collection Guide",
            "url": "https://docs.infosecmonitor.ai/data-collection",
        },
    },
    {
        "name": "Analytics",
        "description": "Analytics and reporting endpoints for risk analysis and usage metrics",
        "externalDocs": {
            "description": "Analytics Guide",
            "url": "https://docs.infosecmonitor.ai/analytics",
        },
    },
    {
        "name": "Alerts",
        "description": "Security alert management and notification endpoints",
    },
    {
        "name": "Privacy",
        "description": "GDPR/CCPA compliance and privacy management endpoints",
        "externalDocs": {
            "description": "Privacy Compliance Guide",
            "url": "https://docs.infosecmonitor.ai/privacy",
        },
    },
    {
        "name": "Machine Learning",
        "description": "ML model management and analysis endpoints",
    },
    {
        "name": "WebSocket",
        "description": "Real-time WebSocket connections for live monitoring",
        "externalDocs": {
            "description": "WebSocket Integration Guide",
            "url": "https://docs.infosecmonitor.ai/websockets",
        },
    },
    {
        "name": "Administration",
        "description": "Administrative endpoints for system management",
    },
]

# Response Examples
RESPONSE_EXAMPLES = {
    "health_check": {
        "status": "healthy",
        "timestamp": "2025-01-01T12:00:00Z",
        "version": "1.0.0",
        "uptime": "2 days, 14:23:15",
    },
    "interaction_collected": {
        "status": "processed",
        "interaction_id": 12345,
        "risk_assessment": {
            "risk_level": "medium",
            "risk_score": 65.0,
            "confidence": 0.85,
            "anomaly_score": 0.23,
            "flags": ["keyword_match", "unusual_timing"],
        },
        "processing_time_ms": 245,
    },
    "analytics_response": {
        "total_interactions": 15420,
        "date_range": {"start": "2025-01-01T00:00:00Z", "end": "2025-01-07T23:59:59Z"},
        "risk_distribution": {
            "low": 12450,
            "medium": 2100,
            "high": 750,
            "critical": 120,
        },
        "platform_breakdown": {"chatgpt": 8500, "claude": 4200, "bard": 2720},
        "trend_data": [
            {"date": "2025-01-01", "interactions": 2200, "high_risk": 45},
            {"date": "2025-01-02", "interactions": 2350, "high_risk": 52},
        ],
    },
    "alert_list": {
        "alerts": [
            {
                "id": 101,
                "severity": "high",
                "title": "Suspicious AI Platform Usage",
                "description": "Unusual pattern of AI interactions detected",
                "created_at": "2025-01-01T12:00:00Z",
                "status": "active",
                "confidence_score": 87.5,
                "platform": "chatgpt",
                "risk_score": 78.2,
            }
        ],
        "pagination": {"page": 1, "per_page": 20, "total": 156, "total_pages": 8},
    },
    "consent_recorded": {
        "consent_recorded": True,
        "consent_id": "consent-uuid-123",
        "expires_at": "2026-01-01T12:00:00Z",
        "purposes": ["security_monitoring", "risk_analysis"],
        "can_withdraw": True,
    },
    "ml_status": {
        "models": {
            "anomaly_detector": {
                "status": "active",
                "accuracy": 0.891,
                "last_trained": "2025-01-01T08:00:00Z",
                "version": "2.1.0",
            },
            "risk_classifier": {
                "status": "active",
                "accuracy": 0.923,
                "last_trained": "2025-01-01T08:00:00Z",
                "version": "1.8.2",
            },
        },
        "performance_metrics": {
            "avg_inference_time_ms": 45,
            "daily_predictions": 15420,
            "accuracy_trend": "stable",
        },
    },
}

# Error Response Examples
ERROR_EXAMPLES = {
    "validation_error": {
        "detail": [
            {
                "loc": ["body", "platform"],
                "msg": "field required",
                "type": "value_error.missing",
            }
        ]
    },
    "auth_error": {
        "detail": "Authentication credentials were not provided or are invalid"
    },
    "rate_limit_error": {
        "detail": "Rate limit exceeded. Try again in 60 seconds.",
        "retry_after": 60,
    },
    "consent_error": {
        "detail": "User consent is required for data processing. Please obtain consent before submitting data."
    },
    "internal_error": {
        "detail": "An internal server error occurred. Please try again later.",
        "error_id": "err-uuid-123",
    },
}

# Schema Definitions
SCHEMA_DEFINITIONS = {
    "InteractionData": {
        "title": "Interaction Data",
        "description": "AI platform interaction data for analysis",
        "type": "object",
        "required": ["session_id", "platform", "content_hash", "user_consent"],
        "properties": {
            "session_id": {
                "type": "string",
                "description": "Unique session identifier",
                "example": "session-abc123",
            },
            "platform": {
                "type": "string",
                "enum": ["chatgpt", "claude", "bard", "copilot", "other"],
                "description": "AI platform name",
                "example": "chatgpt",
            },
            "content_hash": {
                "type": "string",
                "description": "SHA-256 hash of interaction content",
                "example": "abc123def456...",
            },
            "content_length": {
                "type": "integer",
                "description": "Length of interaction content in characters",
                "minimum": 0,
                "example": 150,
            },
            "user_consent": {
                "type": "boolean",
                "description": "Whether user has provided consent for data processing",
                "example": True,
            },
            "metadata": {
                "type": "object",
                "description": "Additional metadata about the interaction",
                "properties": {
                    "user_agent": {"type": "string"},
                    "timestamp": {"type": "string", "format": "date-time"},
                    "url": {"type": "string", "format": "uri"},
                },
            },
        },
    },
    "RiskAssessment": {
        "title": "Risk Assessment",
        "description": "ML-powered risk assessment result",
        "type": "object",
        "properties": {
            "risk_level": {
                "type": "string",
                "enum": ["low", "medium", "high", "critical"],
                "description": "Overall risk level classification",
            },
            "risk_score": {
                "type": "number",
                "minimum": 0,
                "maximum": 100,
                "description": "Numeric risk score (0-100)",
            },
            "confidence": {
                "type": "number",
                "minimum": 0,
                "maximum": 1,
                "description": "Confidence in risk assessment (0-1)",
            },
            "anomaly_score": {
                "type": "number",
                "minimum": 0,
                "maximum": 1,
                "description": "Anomaly detection score (0-1)",
            },
            "flags": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of triggered risk flags",
            },
        },
    },
    "SecurityAlert": {
        "title": "Security Alert",
        "description": "Security alert generated by the monitoring system",
        "type": "object",
        "properties": {
            "id": {"type": "integer", "description": "Unique alert identifier"},
            "severity": {
                "type": "string",
                "enum": ["low", "medium", "high", "critical"],
                "description": "Alert severity level",
            },
            "title": {"type": "string", "description": "Alert title"},
            "description": {
                "type": "string",
                "description": "Detailed alert description",
            },
            "created_at": {
                "type": "string",
                "format": "date-time",
                "description": "Alert creation timestamp",
            },
            "status": {
                "type": "string",
                "enum": ["active", "acknowledged", "resolved", "false_positive"],
                "description": "Current alert status",
            },
            "confidence_score": {
                "type": "number",
                "minimum": 0,
                "maximum": 100,
                "description": "Confidence in alert accuracy",
            },
        },
    },
}


def custom_openapi(app: FastAPI) -> Dict[str, Any]:
    """
    Generate custom OpenAPI schema with enhanced documentation.

    Args:
        app: FastAPI application instance

    Returns:
        Dict containing the OpenAPI schema
    """
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=API_TITLE,
        version=API_VERSION,
        description=API_DESCRIPTION,
        routes=app.routes,
        tags=API_TAGS_METADATA,
    )

    # Add custom schema definitions
    if "components" not in openapi_schema:
        openapi_schema["components"] = {}
    if "schemas" not in openapi_schema["components"]:
        openapi_schema["components"]["schemas"] = {}

    openapi_schema["components"]["schemas"].update(SCHEMA_DEFINITIONS)

    # Add security schemes
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "Enter your API token",
        }
    }

    # Add global security requirement
    openapi_schema["security"] = [{"BearerAuth": []}]

    # Add server information
    openapi_schema["servers"] = [
        {"url": "https://api.infosecmonitor.ai/v1", "description": "Production server"},
        {
            "url": "https://staging-api.infosecmonitor.ai/v1",
            "description": "Staging server",
        },
        {"url": "http://localhost:8000", "description": "Development server"},
    ]

    # Add contact and license information
    openapi_schema["info"]["contact"] = {
        "name": "InfoSec AI Monitor Support",
        "url": "https://docs.infosecmonitor.ai",
        "email": "support@infosecmonitor.ai",
    }

    openapi_schema["info"]["license"] = {
        "name": "Commercial License",
        "url": "https://infosecmonitor.ai/license",
    }

    # Add external documentation
    openapi_schema["externalDocs"] = {
        "description": "Full Documentation",
        "url": "https://docs.infosecmonitor.ai",
    }

    # Enhance path descriptions with examples
    for path, path_item in openapi_schema["paths"].items():
        for method, operation in path_item.items():
            if method in ["get", "post", "put", "patch", "delete"]:
                # Add response examples
                if "responses" in operation:
                    for status_code, response in operation["responses"].items():
                        if status_code == "200" and "content" in response:
                            for content_type, content in response["content"].items():
                                if content_type == "application/json":
                                    # Add appropriate example based on endpoint
                                    if "/health" in path:
                                        content["example"] = RESPONSE_EXAMPLES[
                                            "health_check"
                                        ]
                                    elif "/data/collect" in path:
                                        content["example"] = RESPONSE_EXAMPLES[
                                            "interaction_collected"
                                        ]
                                    elif "/analytics" in path:
                                        content["example"] = RESPONSE_EXAMPLES[
                                            "analytics_response"
                                        ]
                                    elif "/alerts" in path:
                                        content["example"] = RESPONSE_EXAMPLES[
                                            "alert_list"
                                        ]
                                    elif "/privacy/consent" in path:
                                        content["example"] = RESPONSE_EXAMPLES[
                                            "consent_recorded"
                                        ]
                                    elif "/ml/status" in path:
                                        content["example"] = RESPONSE_EXAMPLES[
                                            "ml_status"
                                        ]

                        # Add error examples
                        elif status_code in ["400", "401", "403", "422", "429", "500"]:
                            if "content" in response:
                                for content_type, content in response["content"].items():
                                    if content_type == "application/json":
                                        if status_code == "422":
                                            content["example"] = ERROR_EXAMPLES[
                                                "validation_error"
                                            ]
                                        elif status_code == "401":
                                            content["example"] = ERROR_EXAMPLES[
                                                "auth_error"
                                            ]
                                        elif status_code == "429":
                                            content["example"] = ERROR_EXAMPLES[
                                                "rate_limit_error"
                                            ]
                                        elif status_code == "403":
                                            content["example"] = ERROR_EXAMPLES[
                                                "consent_error"
                                            ]
                                        elif status_code == "500":
                                            content["example"] = ERROR_EXAMPLES[
                                                "internal_error"
                                            ]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


# Documentation utilities
def get_endpoint_docs(tag: str, operation: str) -> Dict[str, Any]:
    """
    Get standardized documentation for an endpoint.

    Args:
        tag: API tag/category
        operation: Operation type (create, read, update, delete, etc.)

    Returns:
        Dict containing documentation metadata
    """
    docs = {
        "tags": [tag],
        "responses": {
            "500": {
                "description": "Internal server error",
                "content": {
                    "application/json": {"example": ERROR_EXAMPLES["internal_error"]}
                },
            }
        },
    }

    # Add authentication requirement for protected endpoints
    if tag not in ["Health"]:
        docs["responses"]["401"] = {
            "description": "Authentication required",
            "content": {"application/json": {"example": ERROR_EXAMPLES["auth_error"]}},
        }

    # Add rate limiting info for data endpoints
    if tag in ["Data Collection", "Analytics"]:
        docs["responses"]["429"] = {
            "description": "Rate limit exceeded",
            "content": {
                "application/json": {"example": ERROR_EXAMPLES["rate_limit_error"]}
            },
        }

    # Add consent requirement for data processing endpoints
    if tag == "Data Collection":
        docs["responses"]["403"] = {
            "description": "User consent required",
            "content": {"application/json": {"example": ERROR_EXAMPLES["consent_error"]}},
        }

    return docs
