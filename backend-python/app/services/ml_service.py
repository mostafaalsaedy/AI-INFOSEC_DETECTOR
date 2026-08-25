"""
Advanced ML-powered Risk Analysis Service
Comprehensive machine learning pipeline for security risk assessment
"""

import asyncio
import pickle
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from app.core.config import ML_MODELS, RISK_PATTERNS, settings
from app.core.database import RiskLevel, record_audit_event, record_metric
from app.core.logging import logger
from app.core.timeutils import utcnow

# ---------------------------------------------------------------------------
# Optional heavy dependencies.
#
# The deep-learning stack (torch, transformers, spaCy) adds several gigabytes
# and is not needed to run the API: without it the analyzer degrades to the
# deterministic regex/heuristic pipeline, which is what actually raises the
# majority of alerts. Install the ML extras to enable the model-backed paths:
#
#     pip install -r requirements-ml.txt
#
# `MLRiskAnalyzer.health_check()` reports which backends actually loaded.
# ---------------------------------------------------------------------------

try:  # pragma: no cover - import guard
    import pandas as pd

    HAS_PANDAS = True
except ImportError:  # pragma: no cover
    pd = None
    HAS_PANDAS = False

try:  # pragma: no cover - import guard
    import torch
    import torch.nn as nn

    HAS_TORCH = True
except ImportError:  # pragma: no cover
    torch = None
    nn = None
    HAS_TORCH = False

try:  # pragma: no cover - import guard
    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
        TextClassificationPipeline,
        pipeline,
    )

    HAS_TRANSFORMERS = True
except ImportError:  # pragma: no cover
    AutoTokenizer = AutoModelForSequenceClassification = None
    pipeline = TextClassificationPipeline = None
    HAS_TRANSFORMERS = False

try:  # pragma: no cover - import guard
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support
    from sklearn.preprocessing import StandardScaler

    HAS_SKLEARN = True
except ImportError:  # pragma: no cover
    IsolationForest = RandomForestClassifier = None
    TfidfVectorizer = StandardScaler = None
    accuracy_score = precision_recall_fscore_support = None
    HAS_SKLEARN = False

try:  # pragma: no cover - import guard
    import spacy

    HAS_SPACY = True
except ImportError:  # pragma: no cover
    spacy = None
    HAS_SPACY = False

try:  # pragma: no cover - import guard
    from textblob import TextBlob

    HAS_TEXTBLOB = True
except ImportError:  # pragma: no cover
    TextBlob = None
    HAS_TEXTBLOB = False

ML_BACKENDS = {
    "pandas": HAS_PANDAS,
    "torch": HAS_TORCH,
    "transformers": HAS_TRANSFORMERS,
    "sklearn": HAS_SKLEARN,
    "spacy": HAS_SPACY,
    "textblob": HAS_TEXTBLOB,
}


@dataclass
class RiskAnalysisResult:
    """Result from ML risk analysis"""

    risk_level: RiskLevel
    risk_score: float
    confidence: float
    predictions: Dict[str, Any]
    anomaly_score: float
    sentiment_score: float
    flags: List[str]
    triggered_rules: List[str]
    should_alert: bool
    explanation: str


@dataclass
class MLModelInfo:
    """ML Model metadata"""

    name: str
    version: str
    accuracy: float
    last_trained: datetime
    model_path: str
    is_loaded: bool = False


class MLRiskAnalyzer:
    """Advanced ML-powered risk analysis system"""

    def __init__(self):
        self.models = {}
        self.vectorizers = {}
        self.scalers = {}
        self.nlp = None
        self.model_info = {}
        self.is_initialized = False

        # Risk pattern cache
        self.pattern_cache = {}
        self.compile_risk_patterns()

        # Model paths
        self.model_path = Path(settings.ML_MODEL_PATH)
        self.model_path.mkdir(parents=True, exist_ok=True)

    async def initialize(self) -> bool:
        """Initialize all ML models and components"""
        try:
            logger.info("Initializing ML Risk Analyzer...")

            # Load spaCy model for NLP
            await self._load_spacy_model()

            # Load transformer models
            await self._load_transformer_models()

            # Load scikit-learn models
            await self._load_sklearn_models()

            # Load custom models
            await self._load_custom_models()

            self.is_initialized = True
            logger.info("ML Risk Analyzer initialized successfully")

            # Record initialization metric
            await record_metric("ml_analyzer_initialized", 1)

            return True

        except Exception as e:
            logger.error(f"ML Analyzer initialization failed: {str(e)}", exc_info=True)
            return False

    async def _load_spacy_model(self):
        """Load spaCy NLP model"""
        if not HAS_SPACY:
            logger.info("spaCy is not installed; falling back to basic text processing")
            self.nlp = None
            return

        try:
            model_name = ML_MODELS["content_classifier"]["model_name"]
            self.nlp = spacy.load(model_name)
            logger.info(f"Loaded spaCy model: {model_name}")
        except (OSError, IOError):
            logger.warning(
                "spaCy model not downloaded. Run: python -m spacy download en_core_web_sm"
            )
            self.nlp = None

    async def _load_transformer_models(self):
        """Load Hugging Face transformer models"""
        if not (HAS_TRANSFORMERS and HAS_TORCH):
            logger.info(
                "transformers/torch not installed; transformer risk classification disabled"
            )
            self.models["risk_classifier"] = None
            return

        try:
            model_config = ML_MODELS["risk_classifier"]
            model_name = model_config["model_name"]

            # Load tokenizer and model
            tokenizer = AutoTokenizer.from_pretrained(model_name)
            model = AutoModelForSequenceClassification.from_pretrained(
                model_name, num_labels=model_config["num_labels"]
            )

            # Create classification pipeline
            classifier = pipeline(
                "text-classification",
                model=model,
                tokenizer=tokenizer,
                return_all_scores=True,
            )

            self.models["risk_classifier"] = classifier
            self.model_info["risk_classifier"] = MLModelInfo(
                name="risk_classifier",
                version="1.0",
                accuracy=0.85,  # Would be loaded from training metrics
                last_trained=utcnow(),
                model_path=str(self.model_path / "risk_classifier"),
            )

            logger.info(f"Loaded transformer model: {model_name}")

        except Exception as e:
            logger.error(f"Failed to load transformer models: {str(e)}")
            # Fall back to rule-based classification
            self.models["risk_classifier"] = None

    async def _load_sklearn_models(self):
        """Load scikit-learn models.

        Persisted models are unpickled from `settings.ML_MODEL_PATH`. Unpickling
        executes arbitrary code, so that directory must be treated as trusted -
        never point it at user-writable storage.
        """
        if not HAS_SKLEARN:
            logger.info("scikit-learn not installed; anomaly detection disabled")
            return

        try:
            # Load anomaly detection model
            anomaly_model_path = self.model_path / "anomaly_detector.pkl"

            if anomaly_model_path.exists():
                with open(anomaly_model_path, "rb") as f:
                    anomaly_model = pickle.load(f)
                    self.models["anomaly_detector"] = anomaly_model
            else:
                # Create and train initial model
                anomaly_model = IsolationForest(
                    contamination=ML_MODELS["anomaly_detector"]["contamination"],
                    random_state=42,
                )
                self.models["anomaly_detector"] = anomaly_model
                logger.info("Created new anomaly detection model")

            # Load TF-IDF vectorizer
            vectorizer_path = self.model_path / "tfidf_vectorizer.pkl"
            if vectorizer_path.exists():
                with open(vectorizer_path, "rb") as f:
                    self.vectorizers["tfidf"] = pickle.load(f)
            else:
                self.vectorizers["tfidf"] = TfidfVectorizer(
                    max_features=10000, stop_words="english", ngram_range=(1, 2)
                )

            # Load feature scaler
            scaler_path = self.model_path / "feature_scaler.pkl"
            if scaler_path.exists():
                with open(scaler_path, "rb") as f:
                    self.scalers["standard"] = pickle.load(f)
            else:
                self.scalers["standard"] = StandardScaler()

            logger.info("Loaded scikit-learn models")

        except Exception as e:
            logger.error(f"Failed to load sklearn models: {str(e)}")

    async def _load_custom_models(self):
        """Load custom PyTorch models"""
        if not HAS_TORCH:
            logger.info("torch not installed; custom neural risk model disabled")
            return

        try:
            # Load custom neural network models if available
            custom_model_path = self.model_path / "custom_risk_model.pt"

            if custom_model_path.exists():
                # Define custom model architecture
                class RiskAssessmentNN(nn.Module):
                    def __init__(self, input_size=100, hidden_size=64, num_classes=4):
                        super().__init__()
                        self.fc1 = nn.Linear(input_size, hidden_size)
                        self.fc2 = nn.Linear(hidden_size, hidden_size)
                        self.fc3 = nn.Linear(hidden_size, num_classes)
                        self.relu = nn.ReLU()
                        self.dropout = nn.Dropout(0.3)

                    def forward(self, x):
                        x = self.relu(self.fc1(x))
                        x = self.dropout(x)
                        x = self.relu(self.fc2(x))
                        x = self.dropout(x)
                        x = self.fc3(x)
                        return x

                model = RiskAssessmentNN()
                # weights_only=True refuses pickled Python objects inside the checkpoint
                model.load_state_dict(
                    torch.load(custom_model_path, map_location="cpu", weights_only=True)
                )
                model.eval()

                self.models["custom_risk_nn"] = model
                logger.info("Loaded custom PyTorch model")

        except Exception as e:
            logger.error(f"Failed to load custom models: {str(e)}")

    def compile_risk_patterns(self):
        """Compile regex patterns for performance"""
        for pattern_name, pattern_config in RISK_PATTERNS.items():
            try:
                compiled_pattern = re.compile(pattern_config["pattern"], re.IGNORECASE)
                self.pattern_cache[pattern_name] = {
                    "pattern": compiled_pattern,
                    "weight": pattern_config["weight"],
                    "category": pattern_config["category"],
                }
            except re.error as e:
                logger.error(f"Failed to compile pattern {pattern_name}: {str(e)}")

    async def analyze_interaction_async(self, interaction) -> RiskAnalysisResult:
        """Comprehensive async analysis of AI interaction"""
        try:
            if not self.is_initialized:
                await self.initialize()

            # Create feature vector from interaction metadata
            features = self._extract_features(interaction)

            # Perform various ML analyses
            results = {}

            # 1. Pattern-based risk analysis
            pattern_result = self._analyze_patterns(
                features.get("content_indicators", {})
            )
            results["pattern_analysis"] = pattern_result

            # 2. Transformer-based classification
            if self.models.get("risk_classifier"):
                transformer_result = await self._analyze_with_transformer(features)
                results["transformer_analysis"] = transformer_result

            # 3. Anomaly detection
            if self.models.get("anomaly_detector"):
                anomaly_result = self._analyze_anomaly(features)
                results["anomaly_analysis"] = anomaly_result

            # 4. Sentiment analysis
            sentiment_result = self._analyze_sentiment(features)
            results["sentiment_analysis"] = sentiment_result

            # 5. Custom neural network analysis
            if self.models.get("custom_risk_nn"):
                nn_result = self._analyze_with_custom_nn(features)
                results["nn_analysis"] = nn_result

            # Combine results and make final assessment
            final_result = self._combine_analysis_results(results, features)

            # Record analysis metrics
            await record_metric(
                "ml_analysis_completed",
                1,
                {
                    "risk_level": final_result.risk_level.value,
                    "confidence": final_result.confidence,
                },
            )

            return final_result

        except Exception as e:
            logger.error(f"ML analysis failed: {str(e)}", exc_info=True)

            # Return fallback result
            return RiskAnalysisResult(
                risk_level=RiskLevel.LOW,
                risk_score=0.0,
                confidence=0.0,
                predictions={},
                anomaly_score=0.0,
                sentiment_score=0.0,
                flags=[],
                triggered_rules=[],
                should_alert=False,
                explanation="ML analysis failed, using fallback assessment",
            )

    async def analyze_risk_indicators(
        self, risk_indicators: Dict[str, Any]
    ) -> RiskAnalysisResult:
        """Analyze risk indicators from browser extension"""
        try:
            # Extract risk score and flags from client-side analysis
            client_score = risk_indicators.get("score", 0)
            client_flags = risk_indicators.get("flags", [])
            client_risk_level = risk_indicators.get("riskLevel", "low")

            # Enhance with server-side ML analysis
            enhanced_score = client_score
            enhanced_flags = client_flags.copy()
            triggered_rules = ["client_analysis"]

            # Apply server-side pattern analysis if available
            if "patterns" in risk_indicators:
                pattern_result = self._analyze_patterns(risk_indicators["patterns"])
                enhanced_score = max(enhanced_score, pattern_result["score"])
                enhanced_flags.extend(pattern_result["flags"])
                triggered_rules.extend(pattern_result["rules"])

            # Determine final risk level
            risk_level = self._calculate_risk_level(enhanced_score)

            # Override with client risk level if higher
            client_risk_enum = RiskLevel(client_risk_level)
            if self._risk_level_priority(client_risk_enum) > self._risk_level_priority(
                risk_level
            ):
                risk_level = client_risk_enum

            return RiskAnalysisResult(
                risk_level=risk_level,
                risk_score=enhanced_score,
                confidence=0.8,  # Medium confidence for client-based analysis
                predictions={"client_analysis": risk_indicators},
                anomaly_score=0.0,
                sentiment_score=0.0,
                flags=enhanced_flags,
                triggered_rules=triggered_rules,
                should_alert=risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL],
                explanation=f"Enhanced client analysis with {len(enhanced_flags)} risk indicators",
            )

        except Exception as e:
            logger.error(f"Risk indicator analysis failed: {str(e)}")
            return RiskAnalysisResult(
                risk_level=RiskLevel.LOW,
                risk_score=0.0,
                confidence=0.0,
                predictions={},
                anomaly_score=0.0,
                sentiment_score=0.0,
                flags=[],
                triggered_rules=[],
                should_alert=False,
                explanation="Risk indicator analysis failed",
            )

    def _extract_features(self, interaction) -> Dict[str, Any]:
        """Extract features from interaction for ML analysis"""
        features = {
            "platform": interaction.platform,
            "content_length": interaction.content_length or 0,
            "interaction_type": interaction.interaction_type.value,
            "risk_flags": interaction.risk_flags or [],
            "content_language": interaction.content_language,
            "timestamp_hour": interaction.interaction_timestamp.hour,
            "timestamp_weekday": interaction.interaction_timestamp.weekday(),
        }

        # Extract session-based features
        if interaction.session:
            features.update(
                {
                    "session_duration": interaction.session.duration_minutes,
                    "session_interactions": interaction.session.total_interactions,
                    "session_platforms": len(interaction.session.platforms_used or []),
                    "session_alerts": interaction.session.total_alerts,
                }
            )

        # Extract risk indicators from metadata
        interaction_metadata = getattr(interaction, "interaction_metadata", None)
        if interaction_metadata:
            features["content_indicators"] = interaction_metadata.get(
                "riskIndicators", {}
            )
            features["page_title"] = interaction_metadata.get("pageTitle", "")

        return features

    def _analyze_patterns(self, content_indicators: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze content using compiled regex patterns"""
        score = 0
        flags = []
        rules = []

        # Check client-side detected patterns
        if isinstance(content_indicators, dict):
            for flag in content_indicators.get("flags", []):
                if flag in RISK_PATTERNS:
                    pattern_config = RISK_PATTERNS[flag]
                    score += pattern_config["weight"]
                    flags.append(flag)
                    rules.append(f"pattern_{flag}")

        return {"score": score, "flags": flags, "rules": rules}

    async def _analyze_with_transformer(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze using transformer model"""
        try:
            classifier = self.models["risk_classifier"]

            # Create input text from features
            input_text = self._features_to_text(features)

            # Get predictions
            results = classifier(input_text)

            # Parse results (assuming LABEL_0=low, LABEL_1=medium, LABEL_2=high, LABEL_3=critical)
            risk_scores = {"low": 0.0, "medium": 0.0, "high": 0.0, "critical": 0.0}

            label_mapping = ["low", "medium", "high", "critical"]
            for result in results:
                label_idx = int(result["label"].split("_")[1])
                if label_idx < len(label_mapping):
                    risk_scores[label_mapping[label_idx]] = result["score"]

            # Calculate overall score
            weighted_score = (
                risk_scores["low"] * 1
                + risk_scores["medium"] * 25
                + risk_scores["high"] * 70
                + risk_scores["critical"] * 100
            )

            return {
                "scores": risk_scores,
                "weighted_score": weighted_score,
                "confidence": max(risk_scores.values()),
            }

        except Exception as e:
            logger.error(f"Transformer analysis failed: {str(e)}")
            return {"scores": {}, "weighted_score": 0.0, "confidence": 0.0}

    def _analyze_anomaly(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Detect anomalies using Isolation Forest"""
        try:
            anomaly_model = self.models["anomaly_detector"]

            # Convert features to numerical vector
            feature_vector = self._features_to_vector(features)

            # Detect anomaly
            anomaly_score = anomaly_model.decision_function([feature_vector])[0]
            is_anomaly = anomaly_model.predict([feature_vector])[0] == -1

            # Normalize score (Isolation Forest returns negative values for anomalies)
            normalized_score = max(0, -anomaly_score * 50)  # Scale to 0-100

            return {
                "anomaly_score": normalized_score,
                "is_anomaly": is_anomaly,
                "confidence": abs(anomaly_score),
            }

        except Exception as e:
            logger.error(f"Anomaly analysis failed: {str(e)}")
            return {"anomaly_score": 0.0, "is_anomaly": False, "confidence": 0.0}

    def _analyze_sentiment(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze sentiment of content indicators"""
        try:
            # Use TextBlob for basic sentiment analysis
            content_text = (
                features.get("page_title", "")
                + " "
                + str(features.get("content_indicators", ""))
            )

            if content_text.strip():
                blob = TextBlob(content_text)
                sentiment_score = blob.sentiment.polarity  # -1 to 1

                # Negative sentiment might indicate security-related content
                risk_score = max(
                    0, -sentiment_score * 30
                )  # Scale negative sentiment to 0-30

                return {
                    "sentiment_polarity": sentiment_score,
                    "sentiment_risk_score": risk_score,
                }

            return {"sentiment_polarity": 0.0, "sentiment_risk_score": 0.0}

        except Exception as e:
            logger.error(f"Sentiment analysis failed: {str(e)}")
            return {"sentiment_polarity": 0.0, "sentiment_risk_score": 0.0}

    def _analyze_with_custom_nn(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze using custom neural network"""
        try:
            model = self.models["custom_risk_nn"]

            # Convert features to tensor
            feature_vector = self._features_to_vector(
                features, size=100
            )  # Pad/truncate to 100
            input_tensor = torch.tensor(feature_vector, dtype=torch.float32).unsqueeze(0)

            with torch.no_grad():
                outputs = model(input_tensor)
                probabilities = torch.softmax(outputs, dim=1)

            # Convert to risk scores
            risk_levels = ["low", "medium", "high", "critical"]
            scores = {}
            for i, level in enumerate(risk_levels):
                scores[level] = float(probabilities[0][i])

            # Calculate weighted score
            weighted_score = sum(
                scores[level] * (i + 1) * 25 for i, level in enumerate(risk_levels)
            )

            return {
                "nn_scores": scores,
                "nn_weighted_score": weighted_score,
                "nn_confidence": float(torch.max(probabilities)),
            }

        except Exception as e:
            logger.error(f"Custom NN analysis failed: {str(e)}")
            return {"nn_scores": {}, "nn_weighted_score": 0.0, "nn_confidence": 0.0}

    def _combine_analysis_results(
        self, results: Dict[str, Any], features: Dict[str, Any]
    ) -> RiskAnalysisResult:
        """Combine all analysis results into final assessment"""

        # Extract scores from different analyses
        pattern_score = results.get("pattern_analysis", {}).get("score", 0)
        transformer_score = results.get("transformer_analysis", {}).get(
            "weighted_score", 0
        )
        anomaly_score = results.get("anomaly_analysis", {}).get("anomaly_score", 0)
        sentiment_score = results.get("sentiment_analysis", {}).get(
            "sentiment_risk_score", 0
        )
        nn_score = results.get("nn_analysis", {}).get("nn_weighted_score", 0)

        # Combine scores with weights
        weights = {
            "pattern": 0.4,
            "transformer": 0.3,
            "anomaly": 0.1,
            "sentiment": 0.1,
            "nn": 0.1,
        }

        final_score = (
            pattern_score * weights["pattern"]
            + transformer_score * weights["transformer"]
            + anomaly_score * weights["anomaly"]
            + sentiment_score * weights["sentiment"]
            + nn_score * weights["nn"]
        )

        # Calculate confidence
        confidences = [
            results.get("transformer_analysis", {}).get("confidence", 0),
            results.get("anomaly_analysis", {}).get("confidence", 0),
            results.get("nn_analysis", {}).get("nn_confidence", 0),
        ]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.5

        # Determine risk level
        risk_level = self._calculate_risk_level(final_score)

        # Collect all flags and rules
        all_flags = results.get("pattern_analysis", {}).get("flags", [])
        all_rules = results.get("pattern_analysis", {}).get("rules", [])

        # Add ML-based rules
        if transformer_score > 50:
            all_rules.append("transformer_high_risk")
        if results.get("anomaly_analysis", {}).get("is_anomaly", False):
            all_rules.append("anomaly_detected")
            all_flags.append("behavioral_anomaly")

        # Generate explanation
        explanation_parts = []
        if pattern_score > 0:
            explanation_parts.append(f"Pattern analysis: {pattern_score:.1f}")
        if transformer_score > 0:
            explanation_parts.append(f"ML classification: {transformer_score:.1f}")
        if anomaly_score > 0:
            explanation_parts.append(f"Anomaly detection: {anomaly_score:.1f}")

        explanation = (
            "; ".join(explanation_parts)
            if explanation_parts
            else "No significant risk indicators"
        )

        return RiskAnalysisResult(
            risk_level=risk_level,
            risk_score=final_score,
            confidence=avg_confidence,
            predictions=results,
            anomaly_score=anomaly_score,
            sentiment_score=results.get("sentiment_analysis", {}).get(
                "sentiment_polarity", 0
            ),
            flags=list(set(all_flags)),
            triggered_rules=list(set(all_rules)),
            should_alert=risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
            and avg_confidence > 0.6,
            explanation=explanation,
        )

    def _features_to_text(self, features: Dict[str, Any]) -> str:
        """Convert features to text for transformer analysis"""
        text_parts = [
            f"Platform: {features.get('platform', 'unknown')}",
            f"Content length: {features.get('content_length', 0)} characters",
            f"Type: {features.get('interaction_type', 'unknown')}",
            f"Language: {features.get('content_language', 'unknown')}",
        ]

        if features.get("page_title"):
            text_parts.append(f"Page: {features['page_title']}")

        if features.get("risk_flags"):
            text_parts.append(f"Flags: {', '.join(features['risk_flags'])}")

        return " | ".join(text_parts)

    def _features_to_vector(
        self, features: Dict[str, Any], size: int = 50
    ) -> List[float]:
        """Convert features to numerical vector"""
        vector = [0.0] * size

        # Basic features
        vector[0] = features.get("content_length", 0) / 1000.0  # Normalize
        vector[1] = 1.0 if features.get("interaction_type") == "prompt" else 0.0
        vector[2] = features.get("timestamp_hour", 12) / 24.0  # Normalize hour
        vector[3] = features.get("timestamp_weekday", 0) / 7.0  # Normalize weekday
        vector[4] = len(features.get("risk_flags", [])) / 10.0  # Normalize flag count

        # Session features
        vector[5] = min(
            features.get("session_duration", 0) / 60.0, 1.0
        )  # Normalize to max 1 hour
        vector[6] = min(features.get("session_interactions", 0) / 100.0, 1.0)  # Normalize
        vector[7] = min(features.get("session_platforms", 1) / 5.0, 1.0)  # Normalize
        vector[8] = min(features.get("session_alerts", 0) / 10.0, 1.0)  # Normalize

        # Platform encoding (one-hot style)
        platforms = ["ChatGPT", "Claude", "DeepSeek", "Perplexity", "Other"]
        platform = features.get("platform", "Other")
        for i, p in enumerate(platforms):
            if platform == p or (platform not in platforms and p == "Other"):
                vector[9 + i] = 1.0
                break

        return vector[:size]

    def _calculate_risk_level(self, score: float) -> RiskLevel:
        """Calculate risk level from numerical score"""
        if score >= 80:
            return RiskLevel.CRITICAL
        elif score >= 50:
            return RiskLevel.HIGH
        elif score >= 20:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def _risk_level_priority(self, risk_level: RiskLevel) -> int:
        """Get numerical priority for risk level comparison"""
        priorities = {
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4,
        }
        return priorities.get(risk_level, 1)

    async def health_check(self) -> bool:
        """Check if ML analyzer is healthy and functional"""
        try:
            if not self.is_initialized:
                return False

            # Test basic pattern analysis
            test_result = self._analyze_patterns({"flags": ["email"]})
            if not isinstance(test_result, dict):
                return False

            # Test feature extraction
            test_features = self._features_to_vector({"content_length": 100})
            if len(test_features) == 0:
                return False

            return True

        except Exception as e:
            logger.error(f"ML health check failed: {str(e)}")
            return False

    async def cleanup(self):
        """Clean up resources"""
        try:
            # Save models if needed
            if self.models:
                await self._save_models()

            # Clear memory
            self.models.clear()
            self.vectorizers.clear()
            self.scalers.clear()

            logger.info("ML Analyzer cleanup completed")

        except Exception as e:
            logger.error(f"ML cleanup error: {str(e)}")

    async def _save_models(self):
        """Save trained models to disk"""
        try:
            # Save scikit-learn models
            if "anomaly_detector" in self.models:
                with open(self.model_path / "anomaly_detector.pkl", "wb") as f:
                    pickle.dump(self.models["anomaly_detector"], f)

            if "tfidf" in self.vectorizers:
                with open(self.model_path / "tfidf_vectorizer.pkl", "wb") as f:
                    pickle.dump(self.vectorizers["tfidf"], f)

            if "standard" in self.scalers:
                with open(self.model_path / "feature_scaler.pkl", "wb") as f:
                    pickle.dump(self.scalers["standard"], f)

            logger.info("Models saved successfully")

        except Exception as e:
            logger.error(f"Model saving failed: {str(e)}")

    async def periodic_retraining(self):
        """Background task for periodic model retraining"""
        while True:
            try:
                await asyncio.sleep(settings.ML_RETRAIN_INTERVAL_HOURS * 3600)

                logger.info("Starting periodic ML model retraining...")

                # Retrain models with new data
                await self._retrain_models()

                logger.info("Periodic retraining completed")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Periodic retraining failed: {str(e)}")
                await asyncio.sleep(3600)  # Wait 1 hour before retry

    async def _retrain_models(self):
        """Retrain models with new data"""
        try:
            # This would fetch recent interaction data and retrain models
            # Implementation depends on specific requirements

            await record_audit_event(
                event_type="ml_model_retrained",
                event_category="system",
                description="ML models retrained with new data",
            )

        except Exception as e:
            logger.error(f"Model retraining failed: {str(e)}")
            raise
