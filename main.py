"""SmartHome Security.

    python main.py          # menú interactivo
    python main.py demo     # escenario automático con logs criptográficos
Variables: SMARTHOME_FILE (datos, por defecto datos_hub.json), SMARTHOME_PASSPHRASE.
"""
import getpass
import json
import logging
import os
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

import crypto_utils as cu
from smarthome import App, Hub, HubError
import smarthome


def hora_a_timestamp(texto):
    """'16:00' -> timestamp de hoy a esa hora."""
    h, m = (int(x) for x in texto.strip().split(":"))
    return int(datetime.now().replace(hour=h, minute=m, second=0, microsecond=0).timestamp())

def configurar_logs():
    """Muestra en pantalla los eventos y los detalles criptográficos (algoritmo, tamaños, resultado)."""
    logging.basicConfig(level=logging.INFO, format="%(name)-10s %(message)s")
    logging.getLogger("crypto").setLevel(logging.DEBUG)

def menu():
    configurar_logs()
    ruta = os.environ.get("SMARTHOME_FILE", "datos_hub.json")
    passphrase = os.environ.get("SMARTHOME_PASSPHRASE") or getpass.getpass("Passphrase del hub: ")
    try:
        hub = Hub(ruta, passphrase)
    except HubError as exc:
        sys.exit(f"Error: {exc}")
    app, rol = App(hub), None
    while True:
        try:
            if rol is None:
                op = input("\n[1] Registrar  [2] Login  [0] Salir > ").strip()
                if op == "0":
                    return
                usuario, pw = input("Usuario: "), getpass.getpass("Contraseña: ")
                if op == "1":
                    print("Registrado como", app.registrar(usuario, pw))
                elif op == "2":
                    app.login(usuario, pw)
                    rol = hub.sesiones[app.token]["rol"]
                    print("Sesión iniciada como", rol)
                continue
            texto = "[1] Estado [2] Abrir [3] Cerrar [4] Salir de la sesión"
            if rol == "propietario":
                texto += "\n[5] Alarma [6] Autorizar invitado [7] Revocar [8] Eventos"
            op = input(f"\n{texto}\n> ").strip()
            if op == "1":
                print(app.enviar("estado"))
            elif op in ("2", "3"):
                print(app.enviar("abrir" if op == "2" else "cerrar", puerta=input(f"Puerta {smarthome.PUERTAS}: ")))
            elif op == "4":
                app.enviar("logout")
                rol = None
            elif op == "5" and rol == "propietario":
                print(app.enviar("alarma", estado=input("on/off: ")))
            elif op == "6" and rol == "propietario":
                datos = app.enviar("autorizar", invitado=input("Invitado: "), puerta=input("Puerta: "),
                                   inicio=hora_a_timestamp(input("Inicio HH:MM (hoy): ")),
                                   fin=hora_a_timestamp(input("Fin HH:MM (hoy): ")))
                print("Autorización firmada, id:", datos["id"])
            elif op == "7" and rol == "propietario":
                print(app.enviar("revocar", id=input("Id: ")))
            elif op == "8" and rol == "propietario":
                print(*app.enviar("eventos")["eventos"], sep="\n")
        except (HubError, ValueError) as exc:
            print("Error:", exc)
        except (EOFError, KeyboardInterrupt):
            return

def demo():
    """Escenario automático. No pide datos y no deja datos_hub.json en el directorio de trabajo."""
    configurar_logs()
    with tempfile.TemporaryDirectory() as tmp:
        ruta = Path(tmp) / "datos.json"
        hub = Hub(ruta, "passphrase-del-hub-demo")
        dueno, invitado = App(hub), App(hub)
        print(">>> Registro:", dueno.registrar("propietario", "Propietario#2026ok"),
              "/", invitado.registrar("Invitado123", "Invitado#2026ok"))
        dueno.login("propietario", "Propietario#2026ok")
        ahora = int(time.time())
        auth = dueno.enviar("autorizar", invitado="Invitado123", puerta="principal",
                            inicio=ahora - 60, fin=ahora + 7200)
        print(">>> Autorización firmada, id:", auth["id"])
        invitado.login("Invitado123", "Invitado#2026ok")
        print(">>> Invitado abre la puerta principal:", invitado.enviar("abrir", puerta="principal"))
        try:
            invitado.enviar("abrir", puerta="garaje")
        except HubError as exc:
            print(">>> Invitado intenta abrir el garaje:", exc)

        invitado.enviar("cerrar", puerta="principal")
        print(">>> Prueba negativa: firma alterada")
        registro = hub.datos["autorizaciones"][0]
        firma = bytearray(cu.unb64(registro["firma"]))
        firma[0] ^= 0x01
        registro["firma"] = cu.b64(bytes(firma))
        try:
            print(invitado.enviar("abrir", puerta="principal"))
        except HubError as exc:
            print(">>> Apertura rechazada:", exc, "| puerta principal:", hub.puertas["principal"])

        print(">>> Prueba negativa: tag AES-GCM alterado")
        clave = os.urandom(32)
        blob = cu.encrypt(clave, b"orden-abrir-principal", b"aad-demo")
        alterado = blob[:-1] + bytes([blob[-1] ^ 0x01])
        try:
            cu.decrypt(clave, alterado, b"aad-demo")
        except cu.CryptoError as exc:
            print(">>> Descifrado rechazado:", exc)

        print(">>> Prueba negativa: HMAC del fichero (rol del invitado cambiado a propietario)")
        obj = json.loads(ruta.read_text("utf-8"))
        obj["datos"]["usuarios"]["Invitado123"]["rol"] = "propietario"
        ruta.write_text(json.dumps(obj), encoding="utf-8")
        try:
            Hub(ruta, "passphrase-del-hub-demo")
        except HubError as exc:
            print(">>> Fichero rechazado:", exc)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        demo()
    elif len(sys.argv) > 1:
        sys.exit("Uso: python main.py [demo]")
    else:
        menu()