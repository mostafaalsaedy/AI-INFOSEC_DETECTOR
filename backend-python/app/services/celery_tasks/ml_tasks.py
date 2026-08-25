"""
Celery Tasks for Machine Learning Operations
Advanced ML pipeline tasks for training, inference, and model management
"""

import pickle
import statistics
from collections import Counter, defaultdict
from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
from sqlalchemy import select, text

# The heavy ML stack is optional (see requirements-ml.txt). These tasks only run
# on a worker that has it installed, so the imports are guarded and each task
# checks `HAS_SKLEARN` before doing anything that needs them.
try:  # pragma: no cover - import guard
    import pandas as pd

    HAS_PANDAS = True
except ImportError:  # pragma: no cover
    pd = None
    HAS_PANDAS = False

try:  # pragma: no cover - import guard
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler

    HAS_SKLEARN = True
except ImportError:  # pragma: no cover
    IsolationForest = RandomForestClassifier = None
    accuracy_score = precision_recall_fscore_support = None
    train_test_split = StandardScaler = None
    HAS_SKLEARN = False

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
from app.services.ml_service import MLRiskAnalyzer


@celery_app.task(bind=True, base=AsyncTask, queue="ml_processing")
async def retrain_models(self):
    """Periodic task to retrain ML models with new data"""
    try:
        logger.info("Starting ML model retraining...")

        # Collect training data from recent interactions
        training_data = await collect_training_data()

        if len(training_data) < 100:  # Need minimum data for training
            logger.warning(f"Insufficient training data: {len(training_data)} samples")
            return {
                "status": "skipped",
                "reason": "insufficient_data",
                "samples": len(training_data),
            }

        # Retrain anomaly detection model
        anomaly_metrics = await retrain_anomaly_detector(training_data)

        # Retrain risk classification model
        risk_metrics = await retrain_risk_classifier(training_data)

        # Update model versions and metrics
        await update_model_registry(
            {
                "anomaly_detector": anomaly_metrics,
                "risk_classifier": risk_metrics,
                "retrained_at": utcnow(),
                "training_samples": len(training_data),
            }
        )

        # Record audit event
        await record_audit_event(
            event_type="ml_models_retrained",
            event_category="system",
            description=f"ML models retrained with {len(training_data)} samples",
            event_data={
                "training_samples": len(training_data),
                "anomaly_accuracy": anomaly_metrics.get("accuracy", 0),
                "risk_accuracy": risk_metrics.get("accuracy", 0),
            },
        )

        # Record metrics
        await record_metric(
            "ml_model_retraining_completed",
            1,
            {
                "training_samples": len(training_data),
                "anomaly_accuracy": anomaly_metrics.get("accuracy", 0),
            },
        )

        logger.info(f"ML model retraining completed: {len(training_data)} samples")

        return {
            "status": "completed",
            "training_samples": len(training_data),
            "metrics": {
                "anomaly_detector": anomaly_metrics,
                "risk_classifier": risk_metrics,
            },
        }

    except Exception as e:
        logger.error(f"ML model retraining failed: {str(e)}", exc_info=True)
        await record_metric("ml_model_retraining_failed", 1)
        raise self.retry(exc=e, countdown=3600, max_retries=3)  # Retry in 1 hour


@celery_app.task(bind=True, base=AsyncTask, queue="ml_processing")
async def batch_risk_analysis(self, interaction_ids: List[int]):
    """Batch process multiple interactions for risk analysis"""
    try:
        logger.info(
            f"Starting batch risk analysis for {len(interaction_ids)} interactions"
        )

        ml_analyzer = MLRiskAnalyzer()
        await ml_analyzer.initialize()

        results = []

        async with get_db_session() as db:
            for interaction_id in interaction_ids:
                # Get interaction
                interaction = await db.get(AIInteraction, interaction_id)
                if not interaction:
                    continue

                # Perform ML analysis
                analysis_result = await ml_analyzer.analyze_interaction_async(interaction)

                # Update interaction with results
                interaction.ml_predictions = analysis_result.predictions
                interaction.confidence_score = analysis_result.confidence
                interaction.anomaly_score = analysis_result.anomaly_score
                interaction.risk_score = max(
                    interaction.risk_score, analysis_result.risk_score
                )

                if analysis_result.risk_level.value != interaction.risk_level.value:
                    interaction.risk_level = analysis_result.risk_level

                results.append(
                    {
                        "interaction_id": interaction_id,
                        "risk_level": analysis_result.risk_level.value,
                        "risk_score": analysis_result.risk_score,
                        "confidence": analysis_result.confidence,
                    }
                )

            await db.commit()

        await ml_analyzer.cleanup()

        logger.info(
            f"Batch risk analysis completed: {len(results)} interactions processed"
        )

        return {"status": "completed", "processed": len(results), "results": results}

    except Exception as e:
        logger.error(f"Batch risk analysis failed: {str(e)}", exc_info=True)
        raise self.retry(exc=e, countdown=300, max_retries=3)


@celery_app.task(bind=True, base=AsyncTask, queue="ml_processing")
async def evaluate_model_performance(self):
    """Evaluate current model performance and generate metrics"""
    try:
        logger.info("Starting model performance evaluation...")

        # Get test dataset from recent interactions
        test_data = await collect_test_data()

        if len(test_data) < 50:
            logger.warning("Insufficient test data for evaluation")
            return {"status": "skipped", "reason": "insufficient_data"}

        ml_analyzer = MLRiskAnalyzer()
        await ml_analyzer.initialize()

        # Evaluate each model
        results = {}

        # Evaluate anomaly detection
        if ml_analyzer.models.get("anomaly_detector"):
            anomaly_metrics = await evaluate_anomaly_detector(ml_analyzer, test_data)
            results["anomaly_detector"] = anomaly_metrics

        # Evaluate risk classifier
        if ml_analyzer.models.get("risk_classifier"):
            risk_metrics = await evaluate_risk_classifier(ml_analyzer, test_data)
            results["risk_classifier"] = risk_metrics

        # Store evaluation results
        await store_evaluation_results(results)

        await ml_analyzer.cleanup()

        logger.info(
            f"Model performance evaluation completed: {len(test_data)} test samples"
        )

        return {
            "status": "completed",
            "test_samples": len(test_data),
            "results": results,
        }

    except Exception as e:
        logger.error(f"Model evaluation failed: {str(e)}", exc_info=True)
        raise self.retry(exc=e, countdown=1800, max_retries=2)


@celery_app.task(bind=True, base=AsyncTask, queue="ml_processing")
async def optimize_model_hyperparameters(self, model_name: str):
    """Optimize hyperparameters for specified model"""
    try:
        logger.info(f"Starting hyperparameter optimization for {model_name}")

        # Get training data
        training_data = await collect_training_data()

        if len(training_data) < 200:
            return {"status": "skipped", "reason": "insufficient_data"}

        # Perform hyperparameter optimization based on model type
        if model_name == "anomaly_detector":
            best_params = await optimize_anomaly_detector_params(training_data)
        elif model_name == "risk_classifier":
            best_params = await optimize_risk_classifier_params(training_data)
        else:
            raise ValueError(f"Unknown model: {model_name}")

        # Train model with optimized parameters
        performance_metrics = await train_optimized_model(
            model_name, best_params, training_data
        )

        # Record results
        await record_audit_event(
            event_type="ml_hyperparameter_optimization",
            event_category="system",
            description=f"Optimized hyperparameters for {model_name}",
            event_data={
                "model_name": model_name,
                "best_params": best_params,
                "performance": performance_metrics,
            },
        )

        logger.info(f"Hyperparameter optimization completed for {model_name}")

        return {
            "status": "completed",
            "model_name": model_name,
            "best_params": best_params,
            "performance": performance_metrics,
        }

    except Exception as e:
        logger.error(f"Hyperparameter optimization failed: {str(e)}", exc_info=True)
        raise self.retry(exc=e, countdown=7200, max_retries=2)  # Retry in 2 hours


@celery_app.task(bind=True, base=AsyncTask, queue="ml_processing")
async def generate_ml_insights_report(self):
    """Generate comprehensive ML insights and performance report"""
    try:
        logger.info("Generating ML insights report...")

        # Collect data for analysis
        interactions_data = await collect_interactions_for_analysis()
        alerts_data = await collect_alerts_for_analysis()

        # Generate insights
        insights = {
            "model_performance": await analyze_model_performance(),
            "risk_patterns": await analyze_risk_patterns(interactions_data),
            "anomaly_trends": await analyze_anomaly_trends(interactions_data),
            "alert_effectiveness": await analyze_alert_effectiveness(alerts_data),
            "platform_risks": await analyze_platform_risks(interactions_data),
            "temporal_patterns": await analyze_temporal_patterns(interactions_data),
        }

        # Generate recommendations
        recommendations = await generate_ml_recommendations(insights)

        # Create report
        report = {
            "generated_at": utcnow().isoformat(),
            "period_start": (utcnow() - timedelta(days=7)).isoformat(),
            "period_end": utcnow().isoformat(),
            "insights": insights,
            "recommendations": recommendations,
            "data_quality": {
                "interactions_analyzed": len(interactions_data),
                "alerts_analyzed": len(alerts_data),
                "data_completeness": calculate_data_completeness(interactions_data),
            },
        }

        # Store report
        report_path = await store_ml_report(report)

        logger.info("ML insights report generated successfully")

        return {
            "status": "completed",
            "report_path": report_path,
            "insights_count": len(insights),
            "recommendations_count": len(recommendations),
        }

    except Exception as e:
        logger.error(f"ML insights report generation failed: {str(e)}", exc_info=True)
        raise self.retry(exc=e, countdown=3600, max_retries=2)


# Helper functions
async def collect_training_data() -> List[Dict[str, Any]]:
    """Collect recent consented interactions for training."""
    cutoff_date = utcnow() - timedelta(days=30)

    async with get_db_session() as db:
        result = await db.execute(
            select(AIInteraction).where(
                AIInteraction.created_at >= cutoff_date,
                AIInteraction.user_consent.is_(True),
                AIInteraction.deleted_at.is_(None),
            )
        )
        return [_interaction_to_dict(row) for row in result.scalars().all()]


async def collect_test_data() -> List[Dict[str, Any]]:
    """Collect interactions with a known outcome, for evaluation.

    The label is the severity of any alert the interaction produced; an
    interaction with no alert is labelled `low`.
    """
    cutoff_date = utcnow() - timedelta(days=7)

    async with get_db_session() as db:
        result = await db.execute(
            select(AIInteraction, SecurityAlert.severity)
            .outerjoin(SecurityAlert, SecurityAlert.interaction_id == AIInteraction.id)
            .where(
                AIInteraction.created_at >= cutoff_date,
                AIInteraction.user_consent.is_(True),
                AIInteraction.deleted_at.is_(None),
            )
        )

        rows = []
        for interaction, severity in result.all():
            record = _interaction_to_dict(interaction)
            record["actual_risk"] = severity.value if severity is not None else "low"
            rows.append(record)
        return rows


async def retrain_anomaly_detector(training_data: List[Dict]) -> Dict[str, float]:
    """Retrain anomaly detection model"""
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    # Prepare features
    features = []
    for interaction in training_data:
        feature_vector = [
            interaction.get("content_length", 0) / 1000.0,
            len(interaction.get("risk_flags", [])),
            interaction.get("risk_score", 0) / 100.0,
            # Add more features as needed
        ]
        features.append(feature_vector)

    X = np.array(features)

    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Train model
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X_scaled)

    # Evaluate on training data (for monitoring)
    predictions = model.predict(X_scaled)
    outlier_fraction = (predictions == -1).mean()

    # Save model
    model_path = Path(settings.ML_MODEL_PATH) / "anomaly_detector.pkl"
    with open(model_path, "wb") as f:
        pickle.dump((model, scaler), f)

    return {
        "accuracy": 1 - outlier_fraction,  # Rough approximation
        "outlier_fraction": outlier_fraction,
        "training_samples": len(training_data),
        "model_path": str(model_path),
    }


async def retrain_risk_classifier(training_data: List[Dict]) -> Dict[str, float]:
    """Retrain risk classification model"""
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler

    # Prepare features and labels
    features = []
    labels = []

    for interaction in training_data:
        feature_vector = [
            interaction.get("content_length", 0) / 1000.0,
            len(interaction.get("risk_flags", [])),
            interaction.get("confidence_score", 0),
            # Add more features
        ]
        features.append(feature_vector)

        # Convert risk level to numeric
        risk_map = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        labels.append(risk_map.get(interaction.get("risk_level", "low"), 0))

    X = np.array(features)
    y = np.array(labels)

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train_scaled, y_train)

    # Evaluate
    y_pred = model.predict(X_test_scaled)
    accuracy = accuracy_score(y_test, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, y_pred, average="weighted"
    )

    # Save model
    model_path = Path(settings.ML_MODEL_PATH) / "risk_classifier.pkl"
    with open(model_path, "wb") as f:
        pickle.dump((model, scaler), f)

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "training_samples": len(X_train),
        "test_samples": len(X_test),
        "model_path": str(model_path),
    }


async def update_model_registry(metrics: Dict[str, Any]):
    """Update model registry with new metrics"""
    from app.core.database import MLModel

    async with get_db_session() as db:
        for model_name, model_metrics in metrics.items():
            if isinstance(model_metrics, dict) and "accuracy" in model_metrics:
                ml_model = MLModel(
                    model_name=model_name,
                    model_type="sklearn",
                    version="1.0",
                    accuracy=model_metrics.get("accuracy"),
                    precision=model_metrics.get("precision"),
                    recall=model_metrics.get("recall"),
                    f1_score=model_metrics.get("f1_score"),
                    is_active=True,
                    training_completed_at=utcnow(),
                    training_samples=model_metrics.get("training_samples"),
                )
                db.add(ml_model)

        await db.commit()


async def analyze_risk_patterns(interactions_data: List[Dict]) -> Dict[str, Any]:
    """Analyze risk patterns in the data"""
    if not HAS_PANDAS:
        return {"status": "skipped", "reason": "pandas not installed"}

    df = pd.DataFrame(interactions_data)

    if df.empty:
        return {}

    return {
        "risk_distribution": df["risk_level"].value_counts().to_dict(),
        "platform_risk_correlation": df.groupby("platform")["risk_score"]
        .mean()
        .to_dict(),
        "temporal_risk_trend": df.groupby(df["created_at"].dt.date)["risk_score"]
        .mean()
        .to_dict(),
        "high_risk_patterns": identify_high_risk_patterns(df),
    }


def identify_high_risk_patterns(df: "pd.DataFrame") -> List[Dict[str, Any]]:
    """Identify patterns in high-risk interactions"""
    high_risk = df[df["risk_level"].isin(["high", "critical"])]

    patterns = []

    # Platform patterns
    platform_risks = high_risk["platform"].value_counts()
    if not platform_risks.empty:
        patterns.append(
            {
                "type": "platform_concentration",
                "description": f"Most high-risk activity on {platform_risks.index[0]}",
                "data": platform_risks.to_dict(),
            }
        )

    # Time patterns
    if "created_at" in high_risk.columns:
        hour_risks = high_risk["created_at"].dt.hour.value_counts()
        if not hour_risks.empty:
            patterns.append(
                {
                    "type": "temporal_pattern",
                    "description": f"Peak high-risk activity at hour {hour_risks.index[0]}",
                    "data": hour_risks.to_dict(),
                }
            )

    return patterns


async def generate_ml_recommendations(insights: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Generate ML-based recommendations"""
    recommendations = []

    # Model performance recommendations
    if "model_performance" in insights:
        perf = insights["model_performance"]
        if perf.get("accuracy", 1.0) < 0.8:
            recommendations.append(
                {
                    "type": "model_improvement",
                    "priority": "high",
                    "description": "Model accuracy below 80%, consider retraining with more data",
                    "action": "increase_training_data",
                }
            )

    # Risk pattern recommendations
    if "risk_patterns" in insights:
        patterns = insights["risk_patterns"]
        if patterns.get("high_risk_patterns"):
            recommendations.append(
                {
                    "type": "risk_monitoring",
                    "priority": "medium",
                    "description": "Specific high-risk patterns identified",
                    "action": "enhance_monitoring_rules",
                }
            )

    return recommendations


async def store_ml_report(report: Dict[str, Any]) -> str:
    """Store ML insights report"""
    import json

    timestamp = utcnow().strftime("%Y%m%d_%H%M%S")
    report_path = f"reports/ml_insights_{timestamp}.json"

    # Create reports directory
    Path("reports").mkdir(exist_ok=True)

    # Save report
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    return report_path


def calculate_data_completeness(data: List[Dict]) -> float:
    """Calculate data completeness score"""
    if not data:
        return 0.0

    required_fields = ["content_length", "risk_score", "platform", "created_at"]
    complete_records = 0

    for record in data:
        if all(
            field in record and record[field] is not None for field in required_fields
        ):
            complete_records += 1

    return complete_records / len(data)


# ---------------------------------------------------------------------------
# Helpers
#
# These back the Celery tasks above. They are plain functions rather than tasks
# so they can be called directly from a REPL or a test without a broker.
# ---------------------------------------------------------------------------


def _interaction_to_dict(interaction: AIInteraction) -> Dict[str, Any]:
    """Flatten an interaction into the plain dict the analysis code expects."""
    return {
        "id": interaction.id,
        "session_id": interaction.session_id,
        "platform": interaction.platform,
        "risk_level": interaction.risk_level.value if interaction.risk_level else "low",
        "risk_score": float(interaction.risk_score or 0.0),
        "risk_flags": interaction.risk_flags or [],
        "confidence_score": float(interaction.confidence_score or 0.0),
        "anomaly_score": float(interaction.anomaly_score or 0.0),
        "sentiment_score": float(interaction.sentiment_score or 0.0),
        "content_length": interaction.content_length or 0,
        "content_language": interaction.content_language,
        "created_at": interaction.created_at,
    }


def _feature_matrix(records: List[Dict[str, Any]]) -> np.ndarray:
    """Build the numeric feature matrix both models are trained on."""
    return np.array(
        [
            [
                float(record.get("risk_score", 0.0)),
                float(record.get("content_length", 0)),
                float(len(record.get("risk_flags") or [])),
                float(record.get("confidence_score", 0.0)),
                float(record.get("anomaly_score", 0.0)),
                float(record.get("sentiment_score", 0.0)),
                float(record["created_at"].hour) if record.get("created_at") else 0.0,
            ]
            for record in records
        ],
        dtype=float,
    )


def _labels(records: List[Dict[str, Any]], key: str = "risk_level") -> List[str]:
    return [record.get(key) or "low" for record in records]


async def evaluate_anomaly_detector(
    ml_analyzer: MLRiskAnalyzer, test_data: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Score the anomaly detector against interactions with known outcomes.

    An interaction that produced a high or critical alert is treated as a true
    anomaly; the detector's -1/1 output is compared against that.
    """
    if not HAS_SKLEARN:
        return {"status": "skipped", "reason": "scikit-learn not installed"}

    model = ml_analyzer.models.get("anomaly_detector")
    if model is None or not test_data:
        return {"status": "skipped", "reason": "no model or no data"}

    features = _feature_matrix(test_data)
    expected = np.array(
        [
            -1 if record.get("actual_risk") in ("high", "critical") else 1
            for record in test_data
        ]
    )

    try:
        predicted = model.predict(features)
    except Exception as exc:  # the model may not have been fitted yet
        logger.warning(f"Anomaly detector could not score the test set: {exc}")
        return {"status": "skipped", "reason": str(exc)}

    true_positive = int(np.sum((predicted == -1) & (expected == -1)))
    false_positive = int(np.sum((predicted == -1) & (expected == 1)))
    false_negative = int(np.sum((predicted == 1) & (expected == -1)))

    precision = (
        true_positive / (true_positive + false_positive)
        if (true_positive + false_positive)
        else 0.0
    )
    recall = (
        true_positive / (true_positive + false_negative)
        if (true_positive + false_negative)
        else 0.0
    )

    return {
        "status": "completed",
        "samples": len(test_data),
        "accuracy": float(np.mean(predicted == expected)),
        "precision": precision,
        "recall": recall,
        "f1": (
            (2 * precision * recall / (precision + recall))
            if (precision + recall)
            else 0.0
        ),
    }


async def evaluate_risk_classifier(
    ml_analyzer: MLRiskAnalyzer, test_data: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Compare the analyzer's predicted risk band against the observed outcome."""
    if not test_data:
        return {"status": "skipped", "reason": "no data"}

    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    correct = 0
    within_one_band = 0

    for record in test_data:
        result = await ml_analyzer.analyze_risk_indicators(
            {
                "flags": record.get("risk_flags", []),
                "score": record.get("risk_score", 0),
            }
        )
        predicted = result.risk_level.value
        actual = record.get("actual_risk", "low")

        if predicted == actual:
            correct += 1
        if abs(order.get(predicted, 0) - order.get(actual, 0)) <= 1:
            within_one_band += 1

    return {
        "status": "completed",
        "samples": len(test_data),
        "accuracy": correct / len(test_data),
        "within_one_band": within_one_band / len(test_data),
    }


async def store_evaluation_results(results: Dict[str, Any]) -> None:
    """Persist evaluation metrics as system metrics and an audit record."""
    for model_name, metrics in results.items():
        if not isinstance(metrics, dict):
            continue
        for metric_name in ("accuracy", "precision", "recall", "f1"):
            value = metrics.get(metric_name)
            if isinstance(value, (int, float)):
                await record_metric(
                    f"ml_{model_name}_{metric_name}",
                    float(value),
                    {"model": model_name},
                )

    await record_audit_event(
        event_type="ml_model_evaluated",
        event_category="system",
        description="ML model evaluation completed",
        event_data=results,
    )


async def optimize_anomaly_detector_params(
    training_data: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Grid-search the isolation forest's contamination and tree count.

    Selection is by mean anomaly-score separation: an unsupervised model has no
    labels to optimise against, so the objective is a decision function that
    separates the tail from the bulk as cleanly as possible.
    """
    if not HAS_SKLEARN:
        return {"contamination": 0.1, "n_estimators": 100}

    features = _feature_matrix(training_data)
    scaled = StandardScaler().fit_transform(features)

    best_score = float("-inf")
    best_params: Dict[str, Any] = {}

    for contamination in (0.02, 0.05, 0.1, 0.15):
        for n_estimators in (100, 200):
            model = IsolationForest(
                contamination=contamination,
                n_estimators=n_estimators,
                random_state=42,
            ).fit(scaled)

            scores = model.decision_function(scaled)
            outliers = scores[scores < 0]
            inliers = scores[scores >= 0]

            if len(outliers) == 0 or len(inliers) == 0:
                continue

            separation = float(np.mean(inliers) - np.mean(outliers))
            if separation > best_score:
                best_score = separation
                best_params = {
                    "contamination": contamination,
                    "n_estimators": n_estimators,
                }

    return best_params or {"contamination": 0.1, "n_estimators": 100}


async def optimize_risk_classifier_params(
    training_data: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Grid-search the random-forest classifier by held-out accuracy."""
    if not HAS_SKLEARN:
        return {"n_estimators": 100, "max_depth": 10}

    features = _feature_matrix(training_data)
    labels = _labels(training_data)

    # Stratified splitting needs at least two examples of at least two classes.
    if len(set(labels)) < 2 or min(Counter(labels).values()) < 2:
        return {"n_estimators": 100, "max_depth": 10}

    x_train, x_test, y_train, y_test = train_test_split(
        features, labels, test_size=0.25, random_state=42, stratify=labels
    )

    best_accuracy = -1.0
    best_params: Dict[str, Any] = {"n_estimators": 100, "max_depth": 10}

    for n_estimators in (100, 200):
        for max_depth in (5, 10, None):
            model = RandomForestClassifier(
                n_estimators=n_estimators,
                max_depth=max_depth,
                random_state=42,
            ).fit(x_train, y_train)

            accuracy = float(accuracy_score(y_test, model.predict(x_test)))
            if accuracy > best_accuracy:
                best_accuracy = accuracy
                best_params = {"n_estimators": n_estimators, "max_depth": max_depth}

    return best_params


async def train_optimized_model(
    model_name: str,
    best_params: Dict[str, Any],
    training_data: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Fit a model with the chosen hyperparameters and persist it."""
    if not HAS_SKLEARN:
        return {"status": "skipped", "reason": "scikit-learn not installed"}

    features = _feature_matrix(training_data)
    model_dir = Path(settings.ML_MODEL_PATH)
    model_dir.mkdir(parents=True, exist_ok=True)

    if model_name == "anomaly_detector":
        model = IsolationForest(random_state=42, **best_params).fit(features)
        metrics = {"training_samples": float(len(training_data))}
    elif model_name == "risk_classifier":
        labels = _labels(training_data)
        model = RandomForestClassifier(random_state=42, **best_params).fit(
            features, labels
        )
        metrics = {
            "training_samples": float(len(training_data)),
            "train_accuracy": float(accuracy_score(labels, model.predict(features))),
        }
    else:
        raise ValueError(f"Unknown model: {model_name}")

    with open(model_dir / f"{model_name}.pkl", "wb") as handle:
        pickle.dump(model, handle)

    return metrics


async def collect_interactions_for_analysis() -> List[Dict[str, Any]]:
    """Collect the last week of interactions for the insights report."""
    cutoff = utcnow() - timedelta(days=7)

    async with get_db_session() as db:
        result = await db.execute(
            select(AIInteraction)
            .where(
                AIInteraction.created_at >= cutoff,
                AIInteraction.deleted_at.is_(None),
            )
            .limit(50_000)
        )
        return [_interaction_to_dict(row) for row in result.scalars().all()]


async def collect_alerts_for_analysis() -> List[Dict[str, Any]]:
    """Collect the last week of alerts for the insights report."""
    cutoff = utcnow() - timedelta(days=7)

    async with get_db_session() as db:
        result = await db.execute(
            select(SecurityAlert).where(SecurityAlert.created_at >= cutoff).limit(50_000)
        )
        return [
            {
                "id": alert.id,
                "alert_type": alert.alert_type,
                "severity": alert.severity.value if alert.severity else "low",
                "status": alert.status.value if alert.status else "open",
                "confidence_score": float(alert.confidence_score or 0.0),
                "created_at": alert.created_at,
                "resolved_at": alert.resolved_at,
            }
            for alert in result.scalars().all()
        ]


async def analyze_model_performance() -> Dict[str, Any]:
    """Summarise the most recently recorded evaluation metric per model."""
    cutoff = utcnow() - timedelta(days=30)

    async with get_db_session() as db:
        result = await db.execute(
            text(
                "SELECT metric_name, metric_value, recorded_at FROM system_metrics "
                "WHERE metric_name LIKE :prefix AND recorded_at >= :cutoff "
                "ORDER BY recorded_at DESC"
            ),
            {"prefix": "ml_%", "cutoff": cutoff},
        )

        latest: Dict[str, Dict[str, Any]] = {}
        for metric_name, metric_value, recorded_at in result.all():
            # Rows arrive newest first, so the first sighting is the current one.
            if metric_name not in latest:
                latest[metric_name] = {
                    "value": float(metric_value),
                    "recorded_at": recorded_at,
                }

    return latest


async def analyze_anomaly_trends(
    interactions_data: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Track how anomaly scores move day to day."""
    if not interactions_data:
        return {}

    per_day: Dict[str, List[float]] = defaultdict(list)
    for record in interactions_data:
        created = record.get("created_at")
        if created:
            per_day[created.strftime("%Y-%m-%d")].append(record.get("anomaly_score", 0.0))

    daily_mean = {
        day: round(statistics.fmean(scores), 3) for day, scores in sorted(per_day.items())
    }
    all_scores = [score for scores in per_day.values() for score in scores]

    return {
        "daily_mean_anomaly_score": daily_mean,
        "overall_mean": round(statistics.fmean(all_scores), 3) if all_scores else 0.0,
        "peak_day": (
            max(daily_mean, key=lambda day: daily_mean[day]) if daily_mean else None
        ),
        "samples": len(all_scores),
    }


async def analyze_alert_effectiveness(
    alerts_data: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Measure how many alerts were actionable, and how fast they were closed."""
    if not alerts_data:
        return {"total_alerts": 0}

    total = len(alerts_data)
    false_positives = sum(
        1 for alert in alerts_data if alert["status"] == "false_positive"
    )
    resolved = [alert for alert in alerts_data if alert.get("resolved_at")]

    resolution_hours = [
        (alert["resolved_at"] - alert["created_at"]).total_seconds() / 3600
        for alert in resolved
        if alert.get("created_at") and alert.get("resolved_at")
    ]

    by_type = Counter(alert["alert_type"] for alert in alerts_data)
    fp_by_type = Counter(
        alert["alert_type"]
        for alert in alerts_data
        if alert["status"] == "false_positive"
    )

    return {
        "total_alerts": total,
        "false_positive_rate": round(false_positives / total * 100, 2),
        "resolution_rate": round(len(resolved) / total * 100, 2),
        "mean_resolution_hours": (
            round(statistics.fmean(resolution_hours), 2) if resolution_hours else 0.0
        ),
        "noisiest_rules": [
            {
                "alert_type": alert_type,
                "alerts": count,
                "false_positive_rate": round(
                    fp_by_type.get(alert_type, 0) / count * 100, 2
                ),
            }
            for alert_type, count in by_type.most_common(5)
        ],
    }


async def analyze_platform_risks(
    interactions_data: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Rank platforms by mean risk and by share of high-risk interactions."""
    if not interactions_data:
        return {}

    per_platform: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for record in interactions_data:
        per_platform[record.get("platform") or "unknown"].append(record)

    summary = {}
    for platform, records in per_platform.items():
        scores = [record.get("risk_score", 0.0) for record in records]
        high_risk = sum(
            1 for record in records if record.get("risk_level") in ("high", "critical")
        )
        summary[platform] = {
            "interactions": len(records),
            "mean_risk_score": round(statistics.fmean(scores), 2) if scores else 0.0,
            "peak_risk_score": round(max(scores), 2) if scores else 0.0,
            "high_risk_share": round(high_risk / len(records) * 100, 2),
        }

    return dict(
        sorted(summary.items(), key=lambda item: item[1]["mean_risk_score"], reverse=True)
    )


async def analyze_temporal_patterns(
    interactions_data: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Find when risky activity happens - out-of-hours use is its own signal."""
    if not interactions_data:
        return {}

    by_hour: Dict[int, List[float]] = defaultdict(list)
    by_weekday: Dict[int, List[float]] = defaultdict(list)

    for record in interactions_data:
        created = record.get("created_at")
        if not created:
            continue
        by_hour[created.hour].append(record.get("risk_score", 0.0))
        by_weekday[created.weekday()].append(record.get("risk_score", 0.0))

    business_hours = range(settings.BUSINESS_HOURS_START, settings.BUSINESS_HOURS_END)
    out_of_hours = sum(
        len(scores) for hour, scores in by_hour.items() if hour not in business_hours
    )
    total = sum(len(scores) for scores in by_hour.values())

    return {
        "interactions_by_hour": {
            hour: len(scores) for hour, scores in sorted(by_hour.items())
        },
        "mean_risk_by_hour": {
            hour: round(statistics.fmean(scores), 2)
            for hour, scores in sorted(by_hour.items())
        },
        "interactions_by_weekday": {
            day: len(scores) for day, scores in sorted(by_weekday.items())
        },
        "out_of_hours_share": round(out_of_hours / total * 100, 2) if total else 0.0,
        "busiest_hour": (
            max(by_hour, key=lambda hour: len(by_hour[hour])) if by_hour else None
        ),
    }
