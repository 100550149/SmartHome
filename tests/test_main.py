"""Menú y validación de las horas, con la entrada sustituida."""
import getpass
import subprocess
import sys
from pathlib import Path

import pytest

import main

ROOT = Path(__file__).resolve().parents[1]


def test_hora_invalida():
    with pytest.raises(ValueError):
        main.hora_a_timestamp("99:99")
    with pytest.raises(ValueError):
        main.hora_a_timestamp("12")
    with pytest.raises(ValueError):
        main.hora_a_timestamp("ab:cd")
    with pytest.raises(ValueError):
        main.hora_a_timestamp(None)
    assert isinstance(main.hora_a_timestamp("00:00"), int)
    assert isinstance(main.hora_a_timestamp(" 23:59 "), int)


def test_menu_rechaza_opcion_y_recorre_el_flujo(monkeypatch, tmp_path, capsys):
    ruta = tmp_path / "casa con espacios" / "datos.json"
    ruta.parent.mkdir()
    monkeypatch.setenv("SMARTHOME_FILE", str(ruta))
    monkeypatch.setenv("SMARTHOME_PASSPHRASE", "hub-passphrase")
    teclado = iter([
        "9",
        "1", "propietario",
        "2", "propietario",
        "1",
        "2", " principal ",
        "6", "nadie", "principal", "99:99",
        "5", " ON ",
        "4",
        "0",
    ])
    claves = iter(["Propietario#2026ok", "Propietario#2026ok"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(teclado))
    monkeypatch.setattr(getpass, "getpass", lambda _prompt="": next(claves))
    main.menu()
    salida = capsys.readouterr().out
    assert "opción desconocida" in salida
    assert "Registrado como propietario" in salida
    assert "propietario" in salida
    assert "abierta" in salida
    assert "Error:" in salida
    assert "True" in salida or "alarma" in salida
    assert ruta.exists()


def test_menu_passphrase_corta(monkeypatch, tmp_path):
    monkeypatch.setenv("SMARTHOME_FILE", str(tmp_path / "datos.json"))
    monkeypatch.setenv("SMARTHOME_PASSPHRASE", "corta")
    with pytest.raises(SystemExit):
        main.menu()


def test_argumento_desconocido():
    resultado = subprocess.run(
        [sys.executable, "-u", "main.py", "ayuda"],
        cwd=ROOT,
        capture_output=True, text=True, check=False,
    )
    assert resultado.returncode != 0
    assert "Uso:" in resultado.stderr + resultado.stdout
