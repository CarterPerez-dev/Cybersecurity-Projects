"""
©AngelaMos | 2026
constants.py
"""


from typing import Literal


Severity = Literal["critical", "high", "medium", "low"]
OutputFormat = Literal["console", "json", "sarif", "csv"]
RedactionStyle = Literal["partial", "full", "none"]
ScanTargetType = Literal["file", "database", "network"]

SEVERITY_ORDER: dict[Severity,
                     int] = {
                         "critical": 0,
                         "high": 1,
                         "medium": 2,
                         "low": 3,
                     }

SEVERITY_SCORE_THRESHOLDS: list[tuple[float,
                                      Severity]] = [
                                          (0.85,
                                           "critical"),
                                          (0.65,
                                           "high"),
                                          (0.40,
                                           "medium"),
                                          (0.20,
                                           "low"),
                                      ]

COMPLIANCE_FRAMEWORKS: list[str] = [
    "HIPAA",
    "PCI_DSS",
    "GDPR",
    "CCPA",
    "SOX",
    "GLBA",
    "FERPA",
]

DEFAULT_CONTEXT_WINDOW_TOKENS: int = 10
DEFAULT_MIN_CONFIDENCE: float = 0.20
DEFAULT_ENTROPY_THRESHOLD: float = 7.2
DEFAULT_DNS_ENTROPY_THRESHOLD: float = 4.0
DEFAULT_MAX_FILE_SIZE_MB: int = 100
DEFAULT_DB_SAMPLE_PERCENTAGE: int = 5
DEFAULT_DB_MAX_ROWS: int = 10000
DEFAULT_DB_TIMEOUT_SECONDS: int = 30

CHECKSUM_BOOST: float = 0.30
CONTEXT_BOOST_MAX: float = 0.35
CONTEXT_BOOST_MIN_FLOOR: float = 0.40
COOCCURRENCE_BOOST: float = 0.15

KNOWN_TEST_VALUES: frozenset[str] = frozenset(
    {
        "123-45-6789",
        "000-00-0000",
        "078-05-1120",
        "219-09-9999",
        "4111111111111111",
        "5500000000000004",
        "340000000000009",
        "6011000000000004",
        "test@example.com",
        "user@test.com",
    }
)

DEFAULT_EXCLUDE_PATTERNS: list[str] = [
    "*.pyc",
    "__pycache__",
    ".git",
    "node_modules",
    ".venv",
    ".env",
    "*.egg-info",
]

SCANNABLE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".pdf",
        ".docx",
        ".xlsx",
        ".xls",
        ".csv",
        ".json",
        ".xml",
        ".yaml",
        ".yml",
        ".txt",
        ".log",
        ".cfg",
        ".ini",
        ".toml",
        ".conf",
        ".eml",
        ".msg",
        ".parquet",
        ".avro",
        ".md",
        ".rst",
        ".html",
        ".htm",
        ".tsv",
        ".py",
        ".js",
        ".ts",
        ".go",
        ".rb",
        ".java",
        ".c",
        ".cpp",
        ".h",
        ".hpp",
        ".rs",
        ".env",
        ".sh",
        ".bat",
        ".ps1",
        ".tf",
        ".hcl",
    }
)

TEXT_DB_COLUMN_TYPES_PG: frozenset[str] = frozenset(
    {
        "text",
        "character varying",
        "character",
        "json",
        "jsonb",
        "varchar",
    }
)

TEXT_DB_COLUMN_TYPES_MYSQL: frozenset[str] = frozenset(
    {
        "varchar",
        "text",
        "mediumtext",
        "longtext",
        "json",
        "char",
        "tinytext",
    }
)

SEVERITY_COLORS: dict[Severity,
                      str] = {
                          "critical": "bold red",
                          "high": "red",
                          "medium": "yellow",
                          "low": "green",
                      }

SARIF_SEVERITY_MAP: dict[Severity,
                         str] = {
                             "critical": "error",
                             "high": "error",
                             "medium": "warning",
                             "low": "note",
                         }

MAX_ARCHIVE_DEPTH: int = 3
MAX_ARCHIVE_MEMBER_SIZE_MB: int = 50
ZIP_BOMB_RATIO_THRESHOLD: int = 100
