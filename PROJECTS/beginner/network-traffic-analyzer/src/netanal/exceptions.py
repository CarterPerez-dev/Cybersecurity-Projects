"""
ⒸAngelaMos | 2026
exceptions.py

Custom exception hierarchy for network traffic analyzer
"""


class NetAnalError(Exception):
    """
    Base exception for all netanal errors
    """


class CaptureError(NetAnalError):
    """
    Errors related to packet capture operations
    """


class CapturePermissionError(CaptureError):
    """
    Insufficient permissions for packet capture
    """


class NpcapNotFoundError(CaptureError):
    """
    Npcap is not installed on Windows
    """


class InvalidFilterError(NetAnalError):
    """
    Invalid BPF filter expression
    """


class ExportError(NetAnalError):
    """
    Errors during data export operations
    """


class AnalysisError(NetAnalError):
    """
    Errors during packet analysis
    """


class ValidationError(NetAnalError):
    """
    Input validation errors
    """


__all__ = [
    "AnalysisError",
    "CaptureError",
    "CapturePermissionError",
    "ExportError",
    "InvalidFilterError",
    "NetAnalError",
    "NpcapNotFoundError",
    "ValidationError",
]
