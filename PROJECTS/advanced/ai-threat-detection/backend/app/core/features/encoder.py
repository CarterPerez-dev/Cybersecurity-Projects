"""
©AngelaMos | 2026
encoder.py
"""

from app.core.features.mappings import (
    BOOLEAN_FEATURES,
    CATEGORICAL_ENCODERS,
    FEATURE_ORDER,
)


def _encode_country(code: str) -> float:
    """
    Deterministic ordinal encoding for 2-letter ISO country codes.
    """
    if not code or len(code) != 2:
        return 0.0
    return float((ord(code[0]) - 64) * 26 + (ord(code[1]) - 64))


def encode_for_inference(
    features: dict[str, int | float | bool | str],
) -> list[float]:
    """
    Encode a combined feature dict into a 35-element float vector
    matching the model input specification.
    """
    vector: list[float] = []

    for name in FEATURE_ORDER:
        raw = features[name]

        if name in BOOLEAN_FEATURES:
            vector.append(1.0 if raw else 0.0)
        elif name in CATEGORICAL_ENCODERS:
            vector.append(float(CATEGORICAL_ENCODERS[name].get(str(raw), 0)))
        elif name == "country_code":
            vector.append(_encode_country(str(raw)))
        else:
            vector.append(float(raw))

    return vector
