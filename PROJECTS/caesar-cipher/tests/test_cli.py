"""
ⒸAngelaMos | 2026
test_cli.py
"""

from pathlib import Path

from typer.testing import CliRunner

from caesar_cipher.main import app


runner = CliRunner()


class TestEncryptCommand:
    def test_encrypt_basic(self) -> None:
        result = runner.invoke(app, ["encrypt", "HELLO", "--key", "3"])
        assert result.exit_code == 0
        assert "KHOOR" in result.stdout

    def test_encrypt_with_spaces(self) -> None:
        result = runner.invoke(app, ["encrypt", "HELLO WORLD", "--key", "3"])
        assert result.exit_code == 0
        assert "KHOOR ZRUOG" in result.stdout

    def test_encrypt_invalid_key(self) -> None:
        result = runner.invoke(app, ["encrypt", "HELLO", "--key", "30"])
        assert result.exit_code == 1
        assert "Error" in result.stdout


class TestDecryptCommand:
    def test_decrypt_basic(self) -> None:
        result = runner.invoke(app, ["decrypt", "KHOOR", "--key", "3"])
        assert result.exit_code == 0
        assert "HELLO" in result.stdout

    def test_decrypt_with_spaces(self) -> None:
        result = runner.invoke(app, ["decrypt", "KHOOR ZRUOG", "--key", "3"])
        assert result.exit_code == 0
        assert "HELLO WORLD" in result.stdout

    def test_decrypt_invalid_key(self) -> None:
        result = runner.invoke(app, ["decrypt", "KHOOR", "--key", "30"])
        assert result.exit_code == 1
        assert "Error" in result.stdout


class TestCrackCommand:
    def test_crack_basic(self) -> None:
        result = runner.invoke(app, ["crack", "KHOOR"])
        assert result.exit_code == 0
        assert "HELLO" in result.stdout
        assert "Best match" in result.stdout

    def test_crack_with_top_option(self) -> None:
        result = runner.invoke(app, ["crack", "KHOOR", "--top", "3"])
        assert result.exit_code == 0

    def test_crack_show_all(self) -> None:
        result = runner.invoke(app, ["crack", "KHOOR", "--all"])
        assert result.exit_code == 0


class TestFileIO:
    def test_encrypt_from_file(self, tmp_path: Path) -> None:
        input_file = tmp_path / "input.txt"
        input_file.write_text("HELLO WORLD")

        result = runner.invoke(
            app,
            ["encrypt",
             "--input-file",
             str(input_file),
             "--key",
             "3"]
        )
        assert result.exit_code == 0
        assert "KHOOR ZRUOG" in result.stdout

    def test_encrypt_to_file(self, tmp_path: Path) -> None:
        output_file = tmp_path / "output.txt"

        result = runner.invoke(
            app,
            [
                "encrypt",
                "HELLO",
                "--key",
                "3",
                "--output-file",
                str(output_file),
            ],
        )
        assert result.exit_code == 0
        assert output_file.read_text() == "KHOOR"

    def test_decrypt_from_file(self, tmp_path: Path) -> None:
        input_file = tmp_path / "input.txt"
        input_file.write_text("KHOOR")

        result = runner.invoke(
            app,
            ["decrypt",
             "--input-file",
             str(input_file),
             "--key",
             "3"]
        )
        assert result.exit_code == 0
        assert "HELLO" in result.stdout
