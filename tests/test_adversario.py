"""Segunda revisión: bordes, persistencia, permisos y entradas mal formadas."""
import json
import sys
import threading
import types
import unicodedata
from pathlib import Path

import pytest

import crypto_utils as cu
import smarthome
from smarthome import App, Hub, HubError, identidad

PASSPHRASE = "hub-passphrase"
OWNER_PW = "Propietario#2026ok"
GUEST_PW = "Invitado#2026ok"


def _casa(tmp_path, reloj=None):
    marca = {"t": 1_700_000_000}
    kwargs = {"reloj": (lambda: marca["t"]) if reloj is None else reloj}
    if reloj is None:
        reloj_obj = marca
    else:
        reloj_obj = None
    hub = Hub(tmp_path / "datos.json", PASSPHRASE, **kwargs)
    owner, guest = App(hub), App(hub)
    owner.registrar("propietario", OWNER_PW)
    guest.registrar("Invitado123", GUEST_PW)
    owner.login("propietario", OWNER_PW)
    guest.login("Invitado123", GUEST_PW)
    return hub, owner, guest, marca if reloj is None else reloj_obj


def test_nfc_une_la_cuenta_y_el_bloqueo(tmp_path):
    compuesto = "Jos\u00e9"
    descompuesto = "Jos\u0065\u0301"
    assert unicodedata.normalize("NFC", descompuesto) == compuesto
    assert identidad(descompuesto) == compuesto
    reloj = {"t": 5_000_000}
    hub = Hub(tmp_path / "datos.json", PASSPHRASE, reloj=lambda: reloj["t"])
    assert hub.registrar(descompuesto, OWNER_PW) == "propietario"
    with pytest.raises(HubError, match="no disponible"):
        hub.registrar(compuesto, "otra-clave-valida")
    for _ in range(5):
        with pytest.raises(HubError, match="credenciales inválidas"):
            hub.login(descompuesto, "clave-incorrecta-1")
    with pytest.raises(HubError, match="demasiados intentos"):
        hub.login(compuesto, OWNER_PW)


def test_las_mayusculas_son_otra_cuenta(tmp_path):
    hub = Hub(tmp_path / "datos.json", PASSPHRASE)
    hub.registrar("Ana", "clave-de-ana-1")
    hub.registrar("ana", "clave-de-ana-2")
    for _ in range(5):
        with pytest.raises(HubError, match="credenciales inválidas"):
            hub.login("Ana", "clave-incorrecta-1")
    with pytest.raises(HubError, match="demasiados intentos"):
        hub.login("Ana", "clave-de-ana-1")
    token, _ = hub.login("ana", "clave-de-ana-2")
    assert hub.sesiones[token]["usuario"] == "ana"


def test_copia_antigua_no_deshace_la_revocacion(tmp_path):
    hub, owner, guest, reloj = _casa(tmp_path)
    datos = owner.enviar(
        "autorizar", invitado="Invitado123", puerta="principal",
        inicio=reloj["t"] - 10, fin=reloj["t"] + 3600,
    )
    assert guest.enviar("abrir", puerta="principal")["estado"] == "abierta"
    guest.enviar("cerrar", puerta="principal")
    copia = hub.ruta.read_bytes()
    owner.enviar("revocar", id=datos["id"])
    recargado = Hub(hub.ruta, PASSPHRASE, reloj=lambda: reloj["t"])
    assert datos["id"] in recargado.datos["revocadas"]
    hub.ruta.write_bytes(copia)
    with pytest.raises(HubError, match="copia antigua"):
        Hub(hub.ruta, PASSPHRASE, reloj=lambda: reloj["t"])


def test_fichero_truncado_vacio_o_sin_directorio(tmp_path):
    ruta = tmp_path / "datos.json"
    Hub(ruta, PASSPHRASE)
    ruta.write_text("{", encoding="utf-8")
    with pytest.raises(HubError, match="corrupto"):
        Hub(ruta, PASSPHRASE)
    ruta.write_text("", encoding="utf-8")
    with pytest.raises(HubError, match="corrupto"):
        Hub(ruta, PASSPHRASE)
    with pytest.raises(HubError, match="guardar"):
        Hub(tmp_path / "no-existe" / "datos.json", PASSPHRASE)
    with pytest.raises(HubError, match="passphrase"):
        Hub(tmp_path / "otro.json", None)


def test_sal_y_generacion_alteradas(tmp_path):
    hub, _owner, _guest, _reloj = _casa(tmp_path)
    ruta = hub.ruta
    obj = json.loads(ruta.read_text("utf-8"))
    obj["salt"] = cu.b64(b"\x11" * 16)
    ruta.write_text(json.dumps(obj), encoding="utf-8")
    with pytest.raises(HubError, match="HMAC|corrupto"):
        Hub(ruta, PASSPHRASE)
    carpeta = tmp_path / "b"
    carpeta.mkdir()
    hub2, *_resto = _casa(carpeta)
    control = json.loads(hub2.ruta_generacion().read_text("utf-8"))
    control["generacion"] = 1
    hub2.ruta_generacion().write_text(json.dumps(control), encoding="utf-8")
    with pytest.raises(HubError, match="corrupto"):
        Hub(hub2.ruta, PASSPHRASE)


def test_aad_ata_contador_token_y_sentido(tmp_path):
    hub, owner, _guest, _reloj = _casa(tmp_path)
    token, clave = owner.token, owner.clave
    rx = hub.sesiones[token]["rx"]
    contador = rx + 1
    cab = contador.to_bytes(8, "big")
    claro = cu.canonico({"cmd": "abrir", "args": {"puerta": "principal"}})
    aad = b"C" + token.encode() + cab
    blob = cab + cu.encrypt(clave, claro, aad)
    otra_cab = (contador + 3).to_bytes(8, "big")
    movido = otra_cab + blob[8:]
    with pytest.raises(HubError, match="orden rechazada"):
        hub.ejecutar(token, movido)
    assert hub.puertas["principal"] == "cerrada"
    ajeno = b"C" + (b"0" * 32) + cab
    with pytest.raises(cu.CryptoError):
        cu.decrypt(clave, blob[8:], ajeno)
    with pytest.raises(cu.CryptoError):
        cu.decrypt(clave, blob[8:], b"H" + token.encode() + cab)
    with pytest.raises(HubError, match="orden rechazada"):
        hub.ejecutar(token, b"corto")
    with pytest.raises(HubError, match="orden rechazada"):
        hub.ejecutar(token, "no-son-bytes")
    with pytest.raises(HubError, match="desconocida"):
        hub.ejecutar(1, blob)


def test_registro_mal_formado_no_bloquea_otra_autorizacion(tmp_path):
    hub, owner, guest, reloj = _casa(tmp_path)
    owner.enviar(
        "autorizar", invitado="Invitado123", puerta="principal",
        inicio=reloj["t"] - 5, fin=reloj["t"] + 50,
    )
    hub.datos["autorizaciones"].insert(0, {"datos": "basura"})
    hub.datos["autorizaciones"].insert(0, None)
    hub.datos["autorizaciones"].append({"datos": {"invitado": "Invitado123", "puerta": "principal", "id": "x"}})
    assert guest.enviar("abrir", puerta="principal")["estado"] == "abierta"
    reloj["t"] += 50
    guest.enviar("cerrar", puerta="principal")
    with pytest.raises(HubError, match="acceso denegado"):
        guest.enviar("abrir", puerta="principal")


def test_bordes_de_reloj_y_comando_desconocido(tmp_path):
    hub, owner, guest, reloj = _casa(tmp_path)
    owner.enviar(
        "autorizar", invitado="Invitado123", puerta="garaje",
        inicio=reloj["t"], fin=reloj["t"] + 10,
    )
    assert guest.enviar("abrir", puerta="garaje")["estado"] == "abierta"
    guest.enviar("cerrar", puerta="garaje")
    reloj["t"] += 10
    with pytest.raises(HubError, match="acceso denegado"):
        guest.enviar("abrir", puerta="garaje")
    with pytest.raises(HubError, match="desconocido"):
        owner.enviar("bailar")
    with pytest.raises(HubError, match="alarma"):
        owner.enviar("alarma", estado="QUIZAS")
    owner.hub.ejecutar = lambda *args, **kwargs: b"demasiado-corto"
    with pytest.raises(HubError, match="no válida"):
        owner.enviar("estado")


def test_fallo_de_escritura_no_deja_el_usuario_a_medias(tmp_path, monkeypatch):
    hub = Hub(tmp_path / "datos.json", PASSPHRASE)
    generacion = hub.datos["generacion"]

    def falla(*_args, **_kwargs):
        raise OSError("disco lleno")

    monkeypatch.setattr(smarthome, "_escribir_atomico", falla)
    with pytest.raises(HubError, match="guardar"):
        hub.registrar("Pepe", "clave-larga-ok")
    assert "Pepe" not in hub.datos["usuarios"]
    assert hub.datos["generacion"] == generacion


def test_rutas_con_espacios_y_permisos(tmp_path):
    ruta = tmp_path / "carpeta con espacios" / "datos.json"
    ruta.parent.mkdir()
    hub = Hub(ruta, PASSPHRASE)
    hub.registrar("propietario", OWNER_PW)
    assert smarthome.permisos_privados(ruta)
    assert smarthome.permisos_privados(hub.ruta_generacion())
    assert Hub(ruta, PASSPHRASE).datos["usuarios"]["propietario"]["rol"] == "propietario"


def test_guardados_concurrentes(tmp_path):
    hub, _owner, _guest, _reloj = _casa(tmp_path)
    errores = []

    def trabajo():
        try:
            hub._guardar()
        except Exception as exc:  # pragma: no cover - no debería saltar
            errores.append(exc)

    hilos = [threading.Thread(target=trabajo) for _ in range(4)]
    for hilo in hilos:
        hilo.start()
    for hilo in hilos:
        hilo.join()
    assert errores == []
    cargado = Hub(hub.ruta, PASSPHRASE)
    assert cargado.datos["generacion"] >= hub.datos["generacion"]


def test_restringir_y_bloqueo_en_windows(monkeypatch, tmp_path):
    ruta = tmp_path / "f.json"
    ruta.write_text("x", encoding="utf-8")
    hub = Hub(tmp_path / "casa.json", PASSPHRASE)
    ordenes = []

    def falso(cmd, **_kwargs):
        ordenes.append(list(cmd))

        class Resultado:
            returncode = 0
            stdout = "tester:(R,W)"
            stderr = ""

        return Resultado()

    modulo = types.ModuleType("msvcrt")
    modulo.LK_LOCK = 0
    modulo.LK_UNLCK = 1
    llamadas = []
    modulo.locking = lambda fd, modo, n: llamadas.append(modo)
    monkeypatch.setitem(sys.modules, "msvcrt", modulo)
    monkeypatch.setenv("USERNAME", "tester")
    monkeypatch.setattr(smarthome.subprocess, "run", falso)
    # os.name se cambia después de crear las rutas. En Linux, Path() con
    # os.name == "nt" construye una WindowsPath y escribiría en el directorio
    # de trabajo. El candado usa un fspath fijo.
    monkeypatch.setattr(smarthome.os, "name", "nt")

    class RutaFija:
        def __init__(self, valor, *_args, **_kwargs):
            self.valor = valor

        def __fspath__(self):
            return str(tmp_path / "candado.lock")

    monkeypatch.setattr(smarthome, "Path", RutaFija)
    smarthome.restringir(ruta)
    assert ordenes[0][0] == "icacls"
    assert "/inheritance:r" in ordenes[0]
    assert smarthome.permisos_privados(ruta)
    with hub._exclusion():
        pass
    assert modulo.LK_LOCK in llamadas
    ordenes.clear()

    def denegado(cmd, **_kwargs):
        ordenes.append(list(cmd))

        class Resultado:
            returncode = 1
            stdout = "Everyone:(R)"
            stderr = "fallo"
        return Resultado()

    monkeypatch.setattr(smarthome.subprocess, "run", denegado)
    with pytest.raises(OSError):
        smarthome.restringir(ruta)
    assert smarthome.permisos_privados(ruta) is False


def test_directorio_o_generacion_ausente(tmp_path):
    carpeta = tmp_path / "datos.json"
    carpeta.mkdir()
    with pytest.raises(HubError, match="leer"):
        Hub(carpeta, PASSPHRASE)
    hub = Hub(tmp_path / "bien.json", PASSPHRASE)
    hub.ruta_generacion().unlink()
    with pytest.raises(HubError, match="corrupto"):
        Hub(hub.ruta, PASSPHRASE)


def test_sesion_agotada(tmp_path):
    _hub, owner, _guest, _reloj = _casa(tmp_path)
    owner.tx = 2**64 - 1
    with pytest.raises(HubError, match="agotada"):
        owner.enviar("estado")
