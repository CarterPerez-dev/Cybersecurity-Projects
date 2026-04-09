"""
©AngelaMos | 2026
test_data_loader.py

Tests CSIC 2010 dataset parsing, CSICRequest-to-
ParsedLogEntry conversion, and end-to-end dataset loading

TestParseCSICFile validates HTTP request block splitting,
method/path/query/header extraction, POST body capture,
attack label assignment, malformed block skipping, and
empty file handling using inline CSIC-format fixtures.
TestCSICToParsedEntry verifies synthesized defaults (IP,
timestamp, status) and POST body query string merging.
TestLoadCSICDataset confirms 35-column X shape, dual-label
y arrays, correct per-file label counts, and finite feature
values

Connects to:
  ml/data_loader - parse_csic_file, csic_to_parsed_entry,
                   load_csic_dataset
"""

from pathlib import Path

import numpy as np

from ml.data_loader import (
    CSICRequest,
    csic_to_parsed_entry,
    load_csic_dataset,
    parse_csic_file,
)

NORMAL_GET_FIXTURE = """\
GET /tienda1/publico/anadir.jsp?id=2&nombre=Jam%F3n HTTP/1.1
Host: localhost:8080
User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)
Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5
Accept-Language: en
Accept-Charset: iso-8859-1,*,utf-8
Accept-Encoding: x-gzip, x-deflate, gzip, deflate
Connection: close

GET /tienda1/publico/pagar.jsp HTTP/1.1
Host: localhost:8080
User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)
Accept: text/xml,application/xml
Accept-Language: en
Connection: close

GET /tienda1/publico/entrar.jsp HTTP/1.1
Host: localhost:8080
User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)
Accept: text/xml
Connection: close

POST /tienda1/publico/registro.jsp HTTP/1.1
Host: localhost:8080
User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)
Accept: text/xml,application/xml
Content-Type: application/x-www-form-urlencoded
Content-Length: 64
Connection: close

nombre=Juan&apellidos=Garcia&email=juan@example.com&submit=Enviar

GET /tienda1/publico/vac498.jsp?manufacturer=Dell HTTP/1.1
Host: localhost:8080
User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)
Accept: text/xml
Connection: close
"""

ATTACK_FIXTURE = """\
GET /tienda1/publico/anadir.jsp?id=2&nombre=Jam%F3n'+OR+1=1-- HTTP/1.1
Host: localhost:8080
User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)
Accept: text/xml
Connection: close

POST /tienda1/publico/autenticar.jsp HTTP/1.1
Host: localhost:8080
User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)
Content-Type: application/x-www-form-urlencoded
Content-Length: 68
Connection: close

usuario=admin'+OR+1=1--&contrasenya=pass&B1=Enviar

GET /tienda1/publico/../../../etc/passwd HTTP/1.1
Host: localhost:8080
User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)
Accept: text/xml
Connection: close

GET /tienda1/publico/anadir.jsp?id=<script>alert(1)</script> HTTP/1.1
Host: localhost:8080
User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)
Accept: text/xml
Connection: close
"""

MALFORMED_FIXTURE = """\
THIS IS NOT HTTP

GET /valid/path HTTP/1.1
Host: localhost:8080
User-Agent: TestBot
Connection: close

just some random garbage here
and more garbage
"""


class TestParseCSICFile:
    """
    Test CSIC 2010 file parser
    """

    def test_parses_normal_get_requests(self, tmp_path: Path) -> None:
        """
        Normal GET requests are parsed into CSICRequest dataclass instances
        """
        f = tmp_path / "normalTrafficTraining.txt"
        f.write_text(NORMAL_GET_FIXTURE, encoding="utf-8")

        results = parse_csic_file(f, label=0)

        assert len(results) == 5
        assert all(isinstance(r, CSICRequest) for r in results)
        assert all(r.label == 0 for r in results)

    def test_parses_get_method_and_path(self, tmp_path: Path) -> None:
        """
        First GET request has correct method, path, and query string
        """
        f = tmp_path / "normal.txt"
        f.write_text(NORMAL_GET_FIXTURE, encoding="utf-8")

        results = parse_csic_file(f, label=0)
        first = results[0]

        assert first.method == "GET"
        assert first.path == "/tienda1/publico/anadir.jsp"
        assert first.query_string == "id=2&nombre=Jam%F3n"
        assert first.protocol == "HTTP/1.1"

    def test_parses_headers(self, tmp_path: Path) -> None:
        """
        Headers are captured as a dict
        """
        f = tmp_path / "normal.txt"
        f.write_text(NORMAL_GET_FIXTURE, encoding="utf-8")

        results = parse_csic_file(f, label=0)
        first = results[0]

        assert first.headers["Host"] == "localhost:8080"
        assert "Konqueror" in first.headers["User-Agent"]

    def test_parses_post_with_body(self, tmp_path: Path) -> None:
        """
        POST request body is captured
        """
        f = tmp_path / "normal.txt"
        f.write_text(NORMAL_GET_FIXTURE, encoding="utf-8")

        results = parse_csic_file(f, label=0)
        post_req = results[3]

        assert post_req.method == "POST"
        assert "nombre=Juan" in post_req.body

    def test_parses_attack_file_with_label_1(self, tmp_path: Path) -> None:
        """
        Attack file entries get label=1
        """
        f = tmp_path / "anomalous.txt"
        f.write_text(ATTACK_FIXTURE, encoding="utf-8")

        results = parse_csic_file(f, label=1)

        assert len(results) == 4
        assert all(r.label == 1 for r in results)

    def test_attack_sqli_in_query(self, tmp_path: Path) -> None:
        """
        SQLi payload appears in query string of attack GET
        """
        f = tmp_path / "anomalous.txt"
        f.write_text(ATTACK_FIXTURE, encoding="utf-8")

        results = parse_csic_file(f, label=1)
        first = results[0]

        assert "OR+1=1" in first.query_string

    def test_attack_sqli_in_body(self, tmp_path: Path) -> None:
        """
        SQLi payload appears in POST body of attack
        """
        f = tmp_path / "anomalous.txt"
        f.write_text(ATTACK_FIXTURE, encoding="utf-8")

        results = parse_csic_file(f, label=1)
        post_req = results[1]

        assert post_req.method == "POST"
        assert "OR+1=1" in post_req.body

    def test_malformed_blocks_skipped(self, tmp_path: Path) -> None:
        """
        Malformed/non-HTTP lines are skipped gracefully
        """
        f = tmp_path / "malformed.txt"
        f.write_text(MALFORMED_FIXTURE, encoding="utf-8")

        results = parse_csic_file(f, label=0)

        assert len(results) == 1
        assert results[0].method == "GET"
        assert results[0].path == "/valid/path"

    def test_empty_file_returns_empty_list(self, tmp_path: Path) -> None:
        """
        Empty file returns an empty list
        """
        f = tmp_path / "empty.txt"
        f.write_text("", encoding="utf-8")

        results = parse_csic_file(f, label=0)

        assert results == []


class TestCSICToParsedEntry:
    """
    Test conversion from CSICRequest to ParsedLogEntry
    """

    def test_converts_get_request(self) -> None:
        """
        GET CSICRequest converts to ParsedLogEntry with synthesized fields
        """
        req = CSICRequest(
            method="GET",
            path="/tienda1/publico/anadir.jsp",
            query_string="id=2&nombre=test",
            protocol="HTTP/1.1",
            headers={
                "Host": "localhost:8080",
                "User-Agent": "Mozilla/5.0 (compatible; Konqueror/3.5)",
            },
            body="",
            label=0,
        )

        entry = csic_to_parsed_entry(req)

        assert entry.method == "GET"
        assert entry.path == "/tienda1/publico/anadir.jsp"
        assert entry.query_string == "id=2&nombre=test"
        assert entry.status_code == 200
        assert entry.response_size == 0
        assert entry.user_agent == "Mozilla/5.0 (compatible; Konqueror/3.5)"
        assert entry.ip != ""
        assert entry.timestamp is not None

    def test_converts_post_with_body_in_query(self) -> None:
        """
        POST body is appended to query_string for feature extraction
        """
        req = CSICRequest(
            method="POST",
            path="/login",
            query_string="",
            protocol="HTTP/1.1",
            headers={"User-Agent": "TestBot"},
            body="user=admin'+OR+1=1--&pass=x",
            label=1,
        )

        entry = csic_to_parsed_entry(req)

        assert entry.method == "POST"
        assert "OR+1=1" in entry.query_string

    def test_missing_ua_gets_default(self) -> None:
        """
        CSICRequest without User-Agent header gets a default user agent
        """
        req = CSICRequest(
            method="GET",
            path="/test",
            query_string="",
            protocol="HTTP/1.1",
            headers={"Host": "localhost"},
            body="",
            label=0,
        )

        entry = csic_to_parsed_entry(req)

        assert len(entry.user_agent) > 0


class TestLoadCSICDataset:
    """
    Test end-to-end dataset loading with feature extraction
    """

    def test_returns_correct_shape(self, tmp_path: Path) -> None:
        """
        load_csic_dataset returns X with 35 columns and matching y
        """
        normal = tmp_path / "normal.txt"
        attack = tmp_path / "attack.txt"
        normal.write_text(NORMAL_GET_FIXTURE, encoding="utf-8")
        attack.write_text(ATTACK_FIXTURE, encoding="utf-8")

        X, y = load_csic_dataset(normal, attack)

        assert X.shape[1] == 35
        assert X.shape[0] == y.shape[0]

    def test_contains_both_labels(self, tmp_path: Path) -> None:
        """
        y array contains both 0 (normal) and 1 (attack) labels
        """
        normal = tmp_path / "normal.txt"
        attack = tmp_path / "attack.txt"
        normal.write_text(NORMAL_GET_FIXTURE, encoding="utf-8")
        attack.write_text(ATTACK_FIXTURE, encoding="utf-8")

        _, y = load_csic_dataset(normal, attack)

        assert 0 in y
        assert 1 in y

    def test_label_counts_match_files(self, tmp_path: Path) -> None:
        """
        Normal and attack counts match the number of requests in each file
        """
        normal = tmp_path / "normal.txt"
        attack = tmp_path / "attack.txt"
        normal.write_text(NORMAL_GET_FIXTURE, encoding="utf-8")
        attack.write_text(ATTACK_FIXTURE, encoding="utf-8")

        _, y = load_csic_dataset(normal, attack)

        assert np.sum(y == 0) == 5
        assert np.sum(y == 1) == 4

    def test_feature_values_are_finite(self, tmp_path: Path) -> None:
        """
        All feature values are finite (no NaN or Inf)
        """
        normal = tmp_path / "normal.txt"
        attack = tmp_path / "attack.txt"
        normal.write_text(NORMAL_GET_FIXTURE, encoding="utf-8")
        attack.write_text(ATTACK_FIXTURE, encoding="utf-8")

        X, _ = load_csic_dataset(normal, attack)

        assert np.all(np.isfinite(X))
