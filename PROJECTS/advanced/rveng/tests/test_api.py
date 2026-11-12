"""
©AngelaMos | 2026
test_api.py
"""

import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from rveng.api.app import create_app
from rveng.api.limits import MAX_HEX_BYTES, MAX_SESSION_LEN
from rveng.api.store import InMemoryProgress, SqliteProgress, load_store


CHALLENGES = Path(__file__).resolve().parents[1] / "challenges"

ELF_MAGIC_LINE = (
    "00000000  7f 45 4c 46 02 01 01 00  "
    "00 00 00 00 00 00 00 00  |.ELF............|"
)


@pytest.fixture()
def client() -> TestClient:
    return TestClient(create_app(progress = InMemoryProgress()))


def test_list_has_the_seed_challenges(client: TestClient):
    body = client.get("/api/challenges").json()
    ids = {c["id"] for c in body}
    assert ids == {
        "01-read-the-hex",
        "02-find-the-entry",
        "03-flip-the-gate",
        "04-name-the-function",
        "05-find-the-gate",
        "06-stripped-gate"
    }


def test_detail_does_not_leak_source_or_answer(client: TestClient):
    body = client.get("/api/challenges/05-find-the-gate").json()
    assert body["category"] == "found_value"
    assert "source" not in body
    assert "answer" not in body
    assert "expected" not in body


def test_missing_challenge_is_404(client: TestClient):
    assert client.get("/api/challenges/nope").status_code == 404


def test_hex_first_line_is_elf_magic(client: TestClient):
    body = client.get("/api/challenges/05-find-the-gate/hex?offset=0&length=16").json()
    assert body["lines"][0] == ELF_MAGIC_LINE


def test_hex_length_is_capped(client: TestClient):
    body = client.get("/api/challenges/05-find-the-gate/hex?length=999999").json()
    assert body["length"] == MAX_HEX_BYTES


def test_elf_view_reports_entry_and_functions(client: TestClient):
    body = client.get("/api/challenges/05-find-the-gate/elf").json()
    assert body["entry"] == 0x401060
    names = {f["name"] for f in body["functions"]}
    assert "check" in names and "main" in names


def test_disasm_hides_gate_before_solve(client: TestClient):
    body = client.get(
        "/api/challenges/05-find-the-gate/disasm"
        "?symbol=check&session=fresh"
    ).json()
    assert body["gate_address"] is None
    assert all(i["is_gate"] is False for i in body["instructions"])
    cmp_ins = next(i for i in body["instructions"] if i["mnemonic"] == "cmp")
    assert "0x539" in cmp_ins["op_str"]


def test_disasm_reveals_gate_after_solve(client: TestClient):
    session = "solver"
    client.post(
        "/api/challenges/05-find-the-gate/submit",
        json = {
            "answer": "1337",
            "session": session
        }
    )
    body = client.get(
        "/api/challenges/05-find-the-gate/disasm"
        f"?symbol=check&session={session}"
    ).json()
    assert body["gate_address"] == 0x40114D
    gate = next(i for i in body["instructions"] if i["is_gate"])
    assert gate["mnemonic"] == "cmp"
    assert gate["immediate"] == 1337


def test_disasm_unknown_symbol_is_404(client: TestClient):
    r = client.get("/api/challenges/05-find-the-gate/disasm?symbol=nope")
    assert r.status_code == 404


def test_strings_finds_the_secret(client: TestClient):
    body = client.get("/api/challenges/05-find-the-gate/strings").json()
    texts = {s["text"] for s in body["strings"]}
    assert "the_flag_is_here" in texts


def test_submit_found_value_correct_reveals_source(client: TestClient):
    r = client.post(
        "/api/challenges/05-find-the-gate/submit",
        json = {
            "answer": "0x539"
        }
    ).json()
    assert r["correct"] is True
    assert "1337" in r["revealed_source"] or "the_flag" in r["revealed_source"]


def test_submit_found_value_wrong_hides_source(client: TestClient):
    r = client.post(
        "/api/challenges/05-find-the-gate/submit",
        json = {
            "answer": "42"
        }
    ).json()
    assert r["correct"] is False
    assert r["revealed_source"] is None


def test_submit_identified_symbol(client: TestClient):
    r = client.post(
        "/api/challenges/04-name-the-function/submit",
        json = {
            "answer": "check"
        }
    ).json()
    assert r["correct"] is True


def test_submit_patched_bytes_correct(client: TestClient):
    r = client.post(
        "/api/challenges/03-flip-the-gate/submit",
        json = {
            "answer": "9090"
        }
    ).json()
    assert r["correct"] is True


def test_submit_bad_hex_does_not_500(client: TestClient):
    r = client.post("/api/challenges/03-flip-the-gate/submit", json = {"answer": "zz"})
    assert r.status_code == 200
    assert r.json()["correct"] is False


def test_submit_oversized_answer_rejected(client: TestClient):
    r = client.post(
        "/api/challenges/05-find-the-gate/submit",
        json = {"answer": "9" * 100000}
    )
    assert r.status_code == 413


def test_progress_tracks_solves(client: TestClient):
    client.post(
        "/api/challenges/05-find-the-gate/submit",
        json = {
            "answer": "1337",
            "session": "s1"
        }
    )
    body = client.get("/api/progress?session=s1").json()
    assert body["solved"] == ["05-find-the-gate"]
    assert body["total"] == 6


def test_disasm_resolves_import_call_names(client: TestClient):
    body = client.get("/api/challenges/05-find-the-gate/disasm?symbol=main").json()
    names = {i["call_name"] for i in body["instructions"] if i["call_name"]}
    assert "atoi" in names and "puts" in names


def test_disasm_exposes_rip_target(client: TestClient):
    body = client.get("/api/challenges/05-find-the-gate/disasm?symbol=main").json()
    targets = {i["rip_target"] for i in body["instructions"]}
    assert 0x402004 in targets


def test_elf_lists_discovered_functions(client: TestClient):
    body = client.get("/api/challenges/05-find-the-gate/elf").json()
    labels = {d["label"] for d in body["discovered"]}
    assert "sub_401146" in labels


def test_cfg_of_check_is_a_diamond(client: TestClient):
    body = client.get("/api/challenges/05-find-the-gate/cfg?symbol=check").json()
    assert len(body["blocks"]) == 4
    assert len(body["edges"]) == 4


def test_xrefs_find_caller_of_check(client: TestClient):
    body = client.get("/api/challenges/05-find-the-gate/xrefs?target=4198726").json()
    assert any(
        r["from_addr"] == 0x4011A6 and r["kind"] == "call" for r in body["references"]
    )


def test_stripped_challenge_disassembles_by_address(client: TestClient):
    elf = client.get("/api/challenges/06-stripped-gate/elf").json()
    assert elf["functions"] == []
    assert any(d["address"] == 0x401146 for d in elf["discovered"])
    dis = client.get("/api/challenges/06-stripped-gate/disasm?address=4198726").json()
    assert dis["instructions"][-1]["mnemonic"] == "ret"


def test_stripped_challenge_grades_found_value(client: TestClient):
    r = client.post(
        "/api/challenges/06-stripped-gate/submit",
        json = {
            "answer": "0x539"
        }
    ).json()
    assert r["correct"] is True


def test_sqlite_backed_progress_survives_a_fresh_app(tmp_path: Path):
    db = tmp_path / "progress.db"
    first = TestClient(create_app(progress = SqliteProgress(db)))
    first.post(
        "/api/challenges/05-find-the-gate/submit",
        json = {
            "answer": "1337",
            "session": "s1"
        }
    )
    reopened = TestClient(create_app(progress = SqliteProgress(db)))
    body = reopened.get("/api/progress?session=s1").json()
    assert body["solved"] == ["05-find-the-gate"]


def test_hex_challenge_reveals_secret_string(client: TestClient):
    r = client.post(
        "/api/challenges/01-read-the-hex/submit",
        json = {
            "answer": "the_flag_is_here"
        }
    ).json()
    assert r["correct"] is True
    assert "the_flag_is_here" in r["revealed_source"]


def test_hex_challenge_wrong_string_hides_source(client: TestClient):
    r = client.post(
        "/api/challenges/01-read-the-hex/submit",
        json = {
            "answer": "wrong_string"
        }
    ).json()
    assert r["correct"] is False
    assert r["revealed_source"] is None


def test_entry_challenge_grades_hex_and_decimal(client: TestClient):
    for answer in ("0x401060", "4198496", "401060h"):
        r = client.post(
            "/api/challenges/02-find-the-entry/submit",
            json = {
                "answer": answer
            }
        ).json()
        assert r["correct"] is True, answer


def test_entry_challenge_matches_engine_header(client: TestClient):
    body = client.get("/api/challenges/02-find-the-entry/elf").json()
    r = client.post(
        "/api/challenges/02-find-the-entry/submit",
        json = {
            "answer": hex(body["entry"])
        }
    ).json()
    assert r["correct"] is True


def test_load_store_skips_malformed_dir(tmp_path: Path):
    root = tmp_path / "challenges"
    root.mkdir()
    shutil.copytree(CHALLENGES / "04-name-the-function", root / "04-name-the-function")
    broken = root / "99-broken"
    broken.mkdir()
    (broken / "challenge.json").write_text("{ not valid json")
    store = load_store(root)
    assert {c.id for c in store.list()} == {"04-name-the-function"}


def test_answer_over_answer_len_is_413(client: TestClient):
    r = client.post(
        "/api/challenges/05-find-the-gate/submit",
        json = {"answer": "9" * 10000}
    )
    assert r.status_code == 413


def test_body_over_size_cap_is_413(client: TestClient):
    r = client.post(
        "/api/challenges/05-find-the-gate/submit",
        json = {"answer": "9" * 100000}
    )
    assert r.status_code == 413


def test_session_over_max_len_is_422(client: TestClient):
    long_session = "s" * (MAX_SESSION_LEN + 1)
    r = client.get(f"/api/progress?session={long_session}")
    assert r.status_code == 422


def test_cors_allows_localhost_dev_origin(client: TestClient):
    r = client.get("/api/challenges", headers = {"origin": "http://localhost:5173"})
    assert r.headers.get("access-control-allow-origin") == ("http://localhost:5173")
