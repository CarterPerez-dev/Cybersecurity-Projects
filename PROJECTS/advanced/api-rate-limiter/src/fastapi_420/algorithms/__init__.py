"""
ⒸAngelaMos | 2025
__init__.py
"""

from fastapi_420.algorithms.base import BaseAlgorithm
from fastapi_420.algorithms.fixed_window import FixedWindowAlgorithm
from fastapi_420.algorithms.sliding_window import SlidingWindowAlgorithm
from fastapi_420.algorithms.token_bucket import TokenBucketAlgorithm
from fastapi_420.types import Algorithm


def create_algorithm(algorithm_type: Algorithm) -> BaseAlgorithm:
    """
    Factory function to create appropriate algorithm instance
    """
    algorithm_map: dict[Algorithm,
                        type[BaseAlgorithm]] = {
                            Algorithm.SLIDING_WINDOW:
                            SlidingWindowAlgorithm,
                            Algorithm.TOKEN_BUCKET: TokenBucketAlgorithm,
                            Algorithm.FIXED_WINDOW: FixedWindowAlgorithm,
                            Algorithm.LEAKY_BUCKET: SlidingWindowAlgorithm,
                        }

    algorithm_class = algorithm_map.get(
        algorithm_type,
        SlidingWindowAlgorithm
    )
    return algorithm_class()


__all__ = [
    "BaseAlgorithm",
    "FixedWindowAlgorithm",
    "SlidingWindowAlgorithm",
    "TokenBucketAlgorithm",
    "create_algorithm",
]
