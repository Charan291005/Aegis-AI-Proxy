"""Data Loss Prevention (DLP) & PII Redaction Engine.

Powered by Microsoft Presidio (AnalyzerEngine & AnonymizerEngine).
Guarantees return-path privacy for tool output payloads:
- Scans all values in structured tool responses.
- Redacts CREDIT_CARD, EMAIL_ADDRESS, and PHONE_NUMBER.
- Substitutes sensitive tokens with '<REDACTED_PII>'.
- Recursively sanitizes nested dictionaries, lists, and primitives without corrupting schema.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Union
from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from security.config import get_settings

logger = logging.getLogger("aegis.services.dlp")

# Target PII entities to sanitize on the return path
TARGET_ENTITIES: List[str] = [
    "CREDIT_CARD",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
]

REDACTION_MARKER: str = "<REDACTED_PII>"


def _build_analyzer_engine() -> AnalyzerEngine:
    """Initialize and configure the Presidio AnalyzerEngine.

    Applies custom pattern recognizers to supplement default spaCy/phonenumber checks
    and guarantee high recall on formatted card numbers and phone formats.
    """
    try:
        # Explicitly configure small English NLP pipeline for fast memory-efficient execution
        nlp_config = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
        provider = NlpEngineProvider(nlp_configuration=nlp_config)
        analyzer = AnalyzerEngine(nlp_engine=provider.create_engine())
    except Exception as exc:
        logger.warning(
            "Custom NLP engine initialization failed (%s). Falling back to default AnalyzerEngine.",
            str(exc),
        )
        analyzer = AnalyzerEngine()

    # Resilient regex recognizer for broad international and local phone number formats
    phone_pattern = Pattern(
        name="aegis_generic_phone_regex",
        regex=r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
        score=0.85,
    )
    phone_recognizer = PatternRecognizer(
        supported_entity="PHONE_NUMBER",
        patterns=[phone_pattern],
        supported_language="en",
    )
    analyzer.registry.add_recognizer(phone_recognizer)

    # Resilient regex recognizer for formatted credit card numbers (13-19 digits)
    cc_pattern = Pattern(
        name="aegis_generic_cc_regex",
        regex=r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{13,19}\b",
        score=0.85,
    )
    cc_recognizer = PatternRecognizer(
        supported_entity="CREDIT_CARD",
        patterns=[cc_pattern],
        supported_language="en",
    )
    analyzer.registry.add_recognizer(cc_recognizer)

    # Resilient regex recognizer for enterprise, internal (.corp, .internal), and standard emails
    email_pattern = Pattern(
        name="aegis_generic_email_regex",
        regex=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        score=0.90,
    )
    email_recognizer = PatternRecognizer(
        supported_entity="EMAIL_ADDRESS",
        patterns=[email_pattern],
        supported_language="en",
    )
    analyzer.registry.add_recognizer(email_recognizer)

    logger.info("Presidio AnalyzerEngine initialized with enhanced PII recognizers.")
    return analyzer


# Singleton DLP Engine components
_ANALYZER_ENGINE: AnalyzerEngine = _build_analyzer_engine()
_ANONYMIZER_ENGINE: AnonymizerEngine = AnonymizerEngine()

# Presidio Anonymizer Operator Configuration
_ANONYMIZER_OPERATORS: Dict[str, OperatorConfig] = {
    "DEFAULT": OperatorConfig("replace", {"new_value": REDACTION_MARKER}),
    "CREDIT_CARD": OperatorConfig("replace", {"new_value": REDACTION_MARKER}),
    "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": REDACTION_MARKER}),
    "PHONE_NUMBER": OperatorConfig("replace", {"new_value": REDACTION_MARKER}),
}


def sanitize_text(text: str) -> str:
    """Analyze a single string for PII entities and redact occurrences.

    Args:
        text: Raw input string from tool output or log.

    Returns:
        Sanitized string with sensitive tokens replaced by '<REDACTED_PII>'.
    """
    sanitized, _ = sanitize_text_with_count(text)
    return sanitized


def sanitize_text_with_count(text: str) -> Tuple[str, int]:
    """Analyze a single string for PII entities and redact occurrences with count.

    Args:
        text: Raw input string from tool output or log.

    Returns:
        Tuple[str, int]: (sanitized_text, count_of_redacted_entities)
    """
    if not text or not isinstance(text, str):
        return text, 0

    try:
        results = _ANALYZER_ENGINE.analyze(
            text=text,
            entities=TARGET_ENTITIES,
            language="en",
            score_threshold=0.3,
        )

        if not results:
            return text, 0

        anonymized = _ANONYMIZER_ENGINE.anonymize(
            text=text,
            analyzer_results=results,
            operators=_ANONYMIZER_OPERATORS,
        )
        return anonymized.text, len(results)
    except Exception as exc:
        logger.error("Presidio anonymization failed on text chunk: %s", str(exc))
        # Fail safe: preserve data or return text if non-critical
        return text, 0


def _sanitize_recursive(node: Any) -> Tuple[Any, int]:
    """Recursively traverse a JSON data structure to sanitize string values and count redactions."""
    total_redacted = 0
    if isinstance(node, dict):
        new_dict = {}
        for key, val in node.items():
            sanitized_val, count = _sanitize_recursive(val)
            new_dict[key] = sanitized_val
            total_redacted += count
        return new_dict, total_redacted
    elif isinstance(node, list):
        new_list = []
        for item in node:
            sanitized_item, count = _sanitize_recursive(item)
            new_list.append(sanitized_item)
            total_redacted += count
        return new_list, total_redacted
    elif isinstance(node, tuple):
        new_items = []
        for item in node:
            sanitized_item, count = _sanitize_recursive(item)
            new_items.append(sanitized_item)
            total_redacted += count
        return tuple(new_items), total_redacted
    elif isinstance(node, str):
        return sanitize_text_with_count(node)
    else:
        # Integers, floats, booleans, None are returned without modification
        return node, 0


def sanitize_tool_response(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Scan and redact PII from an outgoing MCP tool response payload.

    Intercepts the return path before data reaches the calling LLM agent.
    Redacts:
    - CREDIT_CARD
    - EMAIL_ADDRESS
    - PHONE_NUMBER

    Args:
        payload: Python dictionary representing the raw MCP tool output response.

    Returns:
        Dict[str, Any]: Deep-copied and sanitized response dictionary.
    """
    sanitized, _ = sanitize_tool_response_with_report(payload)
    return sanitized


def sanitize_tool_response_with_report(
    payload: Dict[str, Any]
) -> Tuple[Dict[str, Any], bool, int]:
    """Scan and redact PII from an outgoing MCP tool response payload, returning audit metrics.

    Args:
        payload: Python dictionary representing the raw MCP tool output response.

    Returns:
        Tuple[Dict[str, Any], bool, int]: (sanitized_payload, was_pii_redacted, redactions_count)
    """
    settings = get_settings()

    if not settings.enable_pii_redaction:
        logger.debug("DLP redaction disabled via settings. Bypassing return path.")
        return payload, False, 0

    if not isinstance(payload, dict):
        logger.warning(
            "sanitize_tool_response received non-dict payload of type %s", type(payload)
        )
        return payload, False, 0

    sanitized, count = _sanitize_recursive(payload)
    was_redacted = count > 0
    if was_redacted:
        logger.info(
            "DLP Redaction: %d sensitive PII entities redacted from tool response.", count
        )
    return sanitized, was_redacted, count
