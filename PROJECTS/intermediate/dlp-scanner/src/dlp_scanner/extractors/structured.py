"""
©AngelaMos | 2026
structured.py
"""


import csv
import json
from typing import Any

import structlog

from dlp_scanner.models import Location, TextChunk


log = structlog.get_logger()


class CsvExtractor:
    """
    Extracts text from CSV and TSV files
    """
    @property
    def supported_extensions(self) -> frozenset[str]:
        """
        File extensions this extractor handles
        """
        return frozenset({".csv", ".tsv"})

    def extract(self, path: str) -> list[TextChunk]:
        """
        Read CSV row by row and concatenate cell values
        """
        chunks: list[TextChunk] = []

        try:
            with open(
                    path,
                    newline = "",
                    encoding = "utf-8-sig",
            ) as f:
                dialect = csv.Sniffer().sniff(f.read(4096))
                f.seek(0)
                reader = csv.reader(f, dialect)
                rows: list[str] = []

                for _row_num, row in enumerate(reader, 1):
                    cells = [c for c in row if c.strip()]
                    if cells:
                        rows.append(" | ".join(cells))

                if rows:
                    chunks.append(
                        TextChunk(
                            text = "\n".join(rows),
                            location = Location(
                                source_type = "file",
                                uri = path,
                                line = 1,
                            ),
                        )
                    )

        except Exception:
            log.warning("csv_extract_failed", path = path)

        return chunks


class JsonExtractor:
    """
    Extracts text values from JSON files
    """
    @property
    def supported_extensions(self) -> frozenset[str]:
        """
        File extensions this extractor handles
        """
        return frozenset({".json"})

    def extract(self, path: str) -> list[TextChunk]:
        """
        Parse JSON and extract all string values recursively
        """
        chunks: list[TextChunk] = []

        try:
            with open(path, encoding = "utf-8") as f:
                data = json.load(f)

            strings = _extract_json_strings(data)
            if strings:
                chunks.append(
                    TextChunk(
                        text = "\n".join(strings),
                        location = Location(
                            source_type = "file",
                            uri = path,
                        ),
                    )
                )

        except Exception:
            log.warning("json_extract_failed", path = path)

        return chunks


class XmlExtractor:
    """
    Extracts text from XML files using defusedxml
    """
    @property
    def supported_extensions(self) -> frozenset[str]:
        """
        File extensions this extractor handles
        """
        return frozenset({".xml"})

    def extract(self, path: str) -> list[TextChunk]:
        """
        Parse XML safely and extract all text content
        """
        import defusedxml.ElementTree as ET

        chunks: list[TextChunk] = []

        try:
            tree = ET.parse(path)
            root = tree.getroot()
            texts: list[str] = []

            for elem in root.iter():
                if elem.text and elem.text.strip():
                    texts.append(elem.text.strip())
                if elem.tail and elem.tail.strip():
                    texts.append(elem.tail.strip())
                for attr_val in elem.attrib.values():
                    if attr_val.strip():
                        texts.append(attr_val.strip())

            if texts:
                chunks.append(
                    TextChunk(
                        text = "\n".join(texts),
                        location = Location(
                            source_type = "file",
                            uri = path,
                        ),
                    )
                )

        except Exception:
            log.warning("xml_extract_failed", path = path)

        return chunks


class YamlExtractor:
    """
    Extracts text from YAML files
    """
    @property
    def supported_extensions(self) -> frozenset[str]:
        """
        File extensions this extractor handles
        """
        return frozenset({".yaml", ".yml"})

    def extract(self, path: str) -> list[TextChunk]:
        """
        Parse YAML safely and extract string values
        """
        from ruamel.yaml import YAML

        chunks: list[TextChunk] = []

        try:
            yaml = YAML(typ = "safe")
            with open(path) as f:
                data = yaml.load(f)

            if data:
                strings = _extract_json_strings(data)
                if strings:
                    chunks.append(
                        TextChunk(
                            text = "\n".join(strings),
                            location = Location(
                                source_type = "file",
                                uri = path,
                            ),
                        )
                    )

        except Exception:
            log.warning("yaml_extract_failed", path = path)

        return chunks


class ParquetExtractor:
    """
    Extracts text from Parquet files
    """
    @property
    def supported_extensions(self) -> frozenset[str]:
        """
        File extensions this extractor handles
        """
        return frozenset({".parquet"})

    def extract(self, path: str) -> list[TextChunk]:
        """
        Read Parquet file and extract string columns
        """
        import pyarrow.parquet as pq

        chunks: list[TextChunk] = []

        try:
            pf = pq.ParquetFile(path)
            schema = pf.schema_arrow

            string_cols = [
                field.name for field in schema if str(field.type) in (
                    "string",
                    "large_string",
                    "utf8",
                    "large_utf8",)
            ]

            if not string_cols:
                return chunks

            for batch in pf.iter_batches(
                    batch_size = 5000,
                    columns = string_cols,
            ):
                rows: list[str] = []
                table_dict = batch.to_pydict()
                for col_name, values in table_dict.items():
                    for val in values:
                        if val is not None and str(val).strip():
                            rows.append(f"{col_name}: {val}")
                if rows:
                    chunks.append(
                        TextChunk(
                            text = "\n".join(rows),
                            location = Location(
                                source_type = "file",
                                uri = path,
                            ),
                        )
                    )

        except Exception:
            log.warning("parquet_extract_failed", path = path)

        return chunks


class AvroExtractor:
    """
    Extracts text from Avro files
    """
    @property
    def supported_extensions(self) -> frozenset[str]:
        """
        File extensions this extractor handles
        """
        return frozenset({".avro"})

    def extract(self, path: str) -> list[TextChunk]:
        """
        Read Avro file and extract string fields
        """
        from fastavro import reader

        chunks: list[TextChunk] = []

        try:
            with open(path, "rb") as f:
                rows: list[str] = []
                for record in reader(f):
                    strings = _extract_json_strings(record)
                    rows.extend(strings)

                if rows:
                    chunks.append(
                        TextChunk(
                            text = "\n".join(rows),
                            location = Location(
                                source_type = "file",
                                uri = path,
                            ),
                        )
                    )

        except Exception:
            log.warning("avro_extract_failed", path = path)

        return chunks


def _extract_json_strings(
    data: Any,
    prefix: str = "",
) -> list[str]:
    """
    Recursively extract all string values from a JSON-like structure
    """
    strings: list[str] = []

    if isinstance(data, str):
        if data.strip():
            label = f"{prefix}: {data}" if prefix else data
            strings.append(label)
    elif isinstance(data, dict):
        for key, val in data.items():
            key_path = (f"{prefix}.{key}" if prefix else str(key))
            strings.extend(_extract_json_strings(val, key_path))
    elif isinstance(data, list):
        for item in data:
            strings.extend(_extract_json_strings(item, prefix))

    return strings
