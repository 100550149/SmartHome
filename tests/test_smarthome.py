"""Pruebas de la casa: permisos, persistencia y rechazo sin ejecutar la orden."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

import crypto_utils as cu
from smarthome import App, Hub, HubError

ROOT = Path(__file__).resolve().parents[1]
PASSPHRASE = "hub-passphrase"
OWNER_PW = "Propietario#2026ok"
GUEST_PW = "Invitado#2026ok"


def _casa(tmp_path, reloj=None):
    kwargs = {"reloj": reloj} if reloj is not None else {}
    hub = Hub(tmp_path / "datos.json", PASSPHRASE, **kwargs)
    owner, guest = App(hub), App(hub)
    owner.registrar("propietario", OWNER_PW)
    guest.registrar("Invitado123", GUEST_PW)
    return hub, owner, guest


def test_registro_roles_password_y_usuario_invalido(tmp_path):
    hub = Hub(tmp_path / "datos.json", PASSPHRASE)
    assert hub.registrar("propietario", OWNER_PW) == "propietario"
    assert hub.registrar("Invitado123", GUEST_PW) == "invitado"
    assert hub.registrar("Eva", OWNER_PW) == "invitado"
    assert hub.datos["usuarios"]["propietario"]["pw"]["salt"] != hub.datos["usuarios"]["Eva"]["pw"]["salt"]
    assert hub.datos["usuarios"]["propietario"]["pw"]["hash"] != hub.datos["usuarios"]["Eva"]["pw"]["hash"]
    with pytest.raises(HubError, match="no disponible"):
        hub.registrar("propietario", "otra-clave-valida")
    with pytest.raises(HubError, match="débil"):
        hub.registrar("Pepe", "corta")
    with pytest.raises(HubError, match="contraseña inválida"):
        hub.registrar("Pepe", "x" * 129)
    for malo in ("", "   ", " Ana", None, 12, "linea\npartida"):
        with pytest.raises(HubError, match="usuario inválido"):
            hub.registrar(malo, OWNER_PW)
    assert set(hub.datos["usuarios"]) == {"propietario", "Invitado123", "Eva"}
    with pytest.raises(HubError, match="8"):
        Hub(tmp_path / "otro.json", "corta")


def test_login_mensaje_generico_y_verificacion_aunque_no_exista(tmp_path, monkeypatch):
    hub, owner, _guest = _casa(tmp_path)
    llamadas = {"n": 0}
    real = cu.verify_password

    def contar(*args, **kwargs):
        llamadas["n"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(cu, "verify_password", contar)
    with pytest.raises(HubError, match="credenciales inválidas") as mala:
        hub.login("propietario", "clave-incorrecta-1")
    with pytest.raises(HubError, match="credenciales inválidas") as nadie:
        hub.login("no-existe", "clave-incorrecta-1")
    assert str(mala.value) == str(nadie.value)
    assert llamadas["n"] == 2
    with pytest.raises(HubError, match="credenciales inválidas"):
        hub.login("propietario", "corta")
    with pytest.raises(HubError, match="usuario inválido"):
        hub.login("  ", OWNER_PW)
    owner.login("propietario", OWNER_PW)
    sal_1 = hub.login("propietario", OWNER_PW)[1]
    sal_2 = hub.login("propietario", OWNER_PW)[1]
    assert sal_1 != sal_2
    assert len(sal_1) == len(sal_2) == 16


def test_bloqueo_de_cuenta_60_segundos(tmp_path):
    reloj = {"t": 1_000_000}
    hub = Hub(tmp_path / "datos.json", PASSPHRASE, reloj=lambda: reloj["t"])
    hub.registrar("propietario", OWNER_PW)
    for _ in range(5):
        with pytest.raises(HubError, match="credenciales inválidas"):
            hub.login("propietario", "clave-incorrecta-1")
    with pytest.raises(HubError, match="demasiados intentos"):
        hub.login("propietario", OWNER_PW)
    reloj["t"] += 59
    with pytest.raises(HubError, match="demasiados intentos"):
        hub.login("propietario", OWNER_PW)
    reloj["t"] += 1
    hub.login("propietario", OWNER_PW)
    for _ in range(4):
        with pytest.raises(HubError, match="credenciales inválidas"):
            hub.login("propietario", "clave-incorrecta-1")
    hub.login("propietario", OWNER_PW)


def test_puertas_alarma_y_cierre_sin_autorizacion(tmp_path):
    reloj = {"t": 1_700_000_000}
    hub, owner, guest = _casa(tmp_path, reloj=lambda: reloj["t"])
    owner.login("propietario", OWNER_PW)
    guest.login("Invitado123", GUEST_PW)
    assert guest.enviar("cerrar", puerta="garaje") == {"puerta": "garaje", "estado": "cerrada"}
    with pytest.raises(HubError, match="acceso denegado"):
        guest.enviar("abrir", puerta="principal")
    assert hub.puertas["principal"] == "cerrada"
    owner.enviar("autorizar", invitado="Invitado123", puerta="principal",
                 inicio=reloj["t"] - 10, fin=reloj["t"] + 3600)
    assert guest.enviar("abrir", puerta="principal")["estado"] == "abierta"
    with pytest.raises(HubError, match="acceso denegado"):
        guest.enviar("abrir", puerta="garaje")
    owner.enviar("alarma", estado="on")
    with pytest.raises(HubError, match="alarma activada"):
        guest.enviar("abrir", puerta="principal")
    assert owner.enviar("abrir", puerta="trasera")["estado"] == "abierta"
    owner.enviar("alarma", estado="off")
    assert guest.enviar("estado")["alarma"] is False
    with pytest.raises(HubError, match="puerta desconocida"):
        owner.enviar("abrir", puerta="buhardilla")
    owner.enviar("logout")
    with pytest.raises(HubError, match="inicia sesión"):
        owner.enviar("estado")


def test_firma_alterada_caducada_y_revocada(tmp_path):
    reloj = {"t": 1_700_000_000}
    hub, owner, guest = _casa(tmp_path, reloj=lambda: reloj["t"])
    owner.login("propietario", OWNER_PW)
    guest.login("Invitado123", GUEST_PW)
    datos = owner.enviar("autorizar", invitado="Invitado123", puerta="principal",
                         inicio=reloj["t"] - 10, fin=reloj["t"] + 3600)
    registro = hub.datos["autorizaciones"][0]
    original = registro["firma"]
    firma = bytearray(cu.unb64(original))
    firma[-1] ^= 0x01
    registro["firma"] = cu.b64(bytes(firma))
    with pytest.raises(HubError, match="acceso denegado"):
        guest.enviar("abrir", puerta="principal")
    assert hub.puertas["principal"] == "cerrada"
    assert any("FIRMA_INVALIDA" in evento for evento in hub.eventos)

    registro["firma"] = original
    assert guest.enviar("abrir", puerta="principal")["estado"] == "abierta"
    guest.enviar("cerrar", puerta="principal")
    owner.enviar("revocar", id=datos["id"])
    with pytest.raises(HubError, match="acceso denegado"):
        guest.enviar("abrir", puerta="principal")
    assert hub.puertas["principal"] == "cerrada"

    owner.enviar("autorizar", invitado="Invitado123", puerta="garaje",
                 inicio=reloj["t"] - 10, fin=reloj["t"] + 100)
    reloj["t"] += 101
    with pytest.raises(HubError, match="acceso denegado"):
        guest.enviar("abrir", puerta="garaje")
    with pytest.raises(HubError, match="intervalo"):
        owner.enviar("autorizar", invitado="Invitado123", puerta="trasera",
                     inicio=reloj["t"], fin=reloj["t"] + 24 * 3600 + 1)
    with pytest.raises(HubError, match="fechas"):
        owner.enviar("autorizar", invitado="Invitado123", puerta="trasera", inicio=True, fin=10)


def test_replay_y_tag_alterado_no_ejecutan_la_orden(tmp_path):
    hub, owner, _guest = _casa(tmp_path)
    owner.login("propietario", OWNER_PW)
    token, clave = owner.token, owner.clave
    assert hub.puertas["principal"] == "cerrada"

    def orden(contador, claro):
        cab = contador.to_bytes(8, "big")
        return cab + cu.encrypt(clave, claro, b"C" + token.encode() + cab)

    rx = hub.sesiones[token]["rx"]
    blob = orden(rx + 1, cu.canonico({"cmd": "abrir", "args": {"puerta": "principal"}}))
    alterado = blob[:-1] + bytes([blob[-1] ^ 0x01])
    with pytest.raises(HubError, match="orden rechazada"):
        hub.ejecutar(token, alterado)
    assert hub.sesiones[token]["rx"] == rx
    assert hub.puertas["principal"] == "cerrada"

    hub.ejecutar(token, blob)
    assert hub.puertas["principal"] == "abierta"
    hub.puertas["principal"] = "cerrada"
    with pytest.raises(HubError, match="orden rechazada"):
        hub.ejecutar(token, blob)
    assert hub.puertas["principal"] == "cerrada"

    rx = hub.sesiones[token]["rx"]
    basura = orden(rx + 1, b"{")
    respuesta = hub.ejecutar(token, basura)
    cab = respuesta[:8]
    cuerpo = json.loads(cu.decrypt(clave, respuesta[8:], b"H" + token.encode() + cab))
    assert cuerpo["ok"] is False


def test_fichero_hmac_permisos_y_secreto_fuera_del_disco(tmp_path):
    ruta = tmp_path / "datos.json"
    hub, owner, _guest = _casa(tmp_path)
    owner.login("propietario", OWNER_PW)
    bruta = ruta.read_bytes()
    assert ruta.stat().st_mode & 0o777 == 0o600
    assert OWNER_PW.encode() not in bruta
    assert GUEST_PW.encode() not in bruta
    assert PASSPHRASE.encode() not in bruta
    assert cu.private_to_bytes(hub.sesiones[owner.token]["clave_firma"]) not in bruta

    with pytest.raises(HubError, match="HMAC"):
        Hub(ruta, "otra-passphrase")
    obj = json.loads(ruta.read_text("utf-8"))
    obj["datos"]["usuarios"]["Invitado123"]["rol"] = "propietario"
    ruta.write_text(json.dumps(obj), encoding="utf-8")
    with pytest.raises(HubError, match="HMAC"):
        Hub(ruta, PASSPHRASE)


def test_la_firma_sigue_siendo_valida_tras_recargar(tmp_path):
    reloj = {"t": 1_700_000_000}
    ruta = tmp_path / "datos.json"
    hub, owner, _guest = _casa(tmp_path, reloj=lambda: reloj["t"])
    owner.login("propietario", OWNER_PW)
    owner.enviar("autorizar", invitado="Invitado123", puerta="principal",
                 inicio=reloj["t"] - 10, fin=reloj["t"] + 3600)

    hub2 = Hub(ruta, PASSPHRASE, reloj=lambda: reloj["t"])
    owner2, guest2 = App(hub2), App(hub2)
    owner2.login("propietario", OWNER_PW)
    guest2.login("Invitado123", GUEST_PW)
    assert guest2.enviar("abrir", puerta="principal")["estado"] == "abierta"
    publica = cu.unb64(hub2.datos["usuarios"]["propietario"]["clave_publica"])
    registro = hub2.datos["autorizaciones"][0]
    assert cu.verify_signature(publica, cu.canonico(registro["datos"]), cu.unb64(registro["firma"]))


def test_el_invitado_no_escala_privilegios(tmp_path):
    hub, owner, guest = _casa(tmp_path)
    owner.login("propietario", OWNER_PW)
    guest.login("Invitado123", GUEST_PW)
    for comando, args in (
        ("alarma", {"estado": "off"}),
        ("autorizar", {"invitado": "Invitado123", "puerta": "principal", "inicio": 1, "fin": 2}),
        ("revocar", {"id": "no-existe"}),
        ("eventos", {}),
    ):
        with pytest.raises(HubError, match="solo el propietario"):
            guest.enviar(comando, **args)
    eventos = owner.enviar("eventos")["eventos"]
    assert eventos
    assert all(OWNER_PW not in linea and GUEST_PW not in linea for linea in eventos)


def test_demo_rechaza_firma_tag_y_hmac():
    resultado = subprocess.run(
        [sys.executable, "-u", "main.py", "demo"],
        cwd=ROOT, capture_output=True, text=True, timeout=60, check=False,
    )
    salida = resultado.stdout + resultado.stderr
    assert resultado.returncode == 0, salida
    assert "Autorización firmada" in salida
    assert "Apertura rechazada:" in salida
    assert "puerta principal: cerrada" in salida
    assert "FIRMA_INVALIDA" in salida
    assert "Descifrado rechazado:" in salida
    assert "tag GCM inválido" in salida
    assert "Fichero rechazado:" in salida
    assert "HMAC inválido" in salida
    assert "AES-GCM 256 bits" in salida
    assert "ECDSA P-256" in salida
    assert "HMAC-SHA256" in salida
    assert OWNER_PW not in salida
    assert GUEST_PW not in salida
    assert "passphrase-del-hub-demo" not in salida
    assert not (ROOT / "datos_hub.json").exists()
