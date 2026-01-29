"""
ⒸAngelaMos | 2025
responses.py
"""

from typing import Any

from .error_schemas import ErrorDetail


AUTH_401: dict[int | str,
               dict[str,
                    Any]] = {
                        401: {
                            "model": ErrorDetail,
                            "description": "Authentication failed"
                        },
                    }

FORBIDDEN_403: dict[int | str,
                    dict[str,
                         Any]] = {
                             403: {
                                 "model": ErrorDetail,
                                 "description": "Permission denied"
                             },
                         }

NOT_FOUND_404: dict[int | str,
                    dict[str,
                         Any]] = {
                             404: {
                                 "model": ErrorDetail,
                                 "description": "Resource not found"
                             },
                         }

CONFLICT_409: dict[int | str,
                   dict[str,
                        Any]] = {
                            409: {
                                "model": ErrorDetail,
                                "description": "Resource conflict"
                            },
                        }
