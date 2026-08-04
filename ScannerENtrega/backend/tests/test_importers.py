from __future__ import annotations

import io
import zipfile

import pytest
from openpyxl import Workbook

from govsec_scanner.importers import ImportValidationError, parse_import_file


def test_text_and_csv_import() -> None:
    assert parse_import_file("ranges.txt", b"10.0.0.1\n10.0.1.0/24\n", max_bytes=1024) == [
        "10.0.0.1",
        "10.0.1.0/24",
    ]
    assert parse_import_file("ranges.csv", b"nome,cidr\nrede,10.2.0.0/24\n", max_bytes=1024) == [
        "nome",
        "cidr",
        "rede",
        "10.2.0.0/24",
    ]


def test_spreadsheet_formula_is_rejected() -> None:
    workbook = Workbook()
    workbook.active["A1"] = "=1+1"
    payload = io.BytesIO()
    workbook.save(payload)
    workbook.close()

    with pytest.raises(ImportValidationError, match="formulas"):
        parse_import_file("ranges.xlsx", payload.getvalue(), max_bytes=20_000)


def test_zip_traversal_is_rejected() -> None:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("../ranges.txt", "10.0.0.1")

    with pytest.raises(ImportValidationError, match="Caminho inseguro"):
        parse_import_file("ranges.zip", payload.getvalue(), max_bytes=4096)


def test_executable_and_formula_like_text_are_rejected() -> None:
    with pytest.raises(ImportValidationError, match="executaveis"):
        parse_import_file("ranges.txt", b"MZnot-an-allowed-file", max_bytes=1024)
    with pytest.raises(ImportValidationError, match="formula"):
        parse_import_file("ranges.txt", b"=HYPERLINK('x')", max_bytes=1024)
