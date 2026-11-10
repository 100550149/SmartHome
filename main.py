            elif op == "8" and rol == "propietario":
                print(*app.enviar("eventos")["eventos"], sep="\n")
            else:
                print("Opción no válida")
        except (HubError, ValueError) as exc:
            print("Error:", exc)
        except (EOFError, KeyboardInterrupt):
            print("\nSaliendo de SmartHome.")
            return


class RelojPrueba:
    """Reloj controlable para que la demo no tenga que esperar de verdad."""
    def __init__(self, instante: int = 1_800_000_000):
        self.wall = float(instante)
        self.mono = 0.0

    def avanzar(self, segundos: float) -> None:
        self.wall += segundos
        self.mono += segundos


def demo() -> None:
    """Demuestra casos normales y varios rechazos de seguridad."""
    configurar_logs()
    print("\n========== SMARTHOME SECURITY LAB ==========")

    with tempfile.TemporaryDirectory() as temporal:
        ruta = Path(temporal) / "datos_hub.json"
        reloj = RelojPrueba()
        passphrase_hub = "Passphrase-Hub-Demo-2026"
        hub = Hub(
            ruta, passphrase_hub,
            reloj=lambda: reloj.wall,
            reloj_monotonic=lambda: reloj.mono,
        )

        propietario = App(hub)
        invitado = App(hub)
        propietario.registrar("propietario", "Propietario#2026ok")
        invitado.registrar("Invitado123", "Invitado#2026ok")
        propietario.login("propietario", "Propietario#2026ok")
        ahora = int(reloj.wall)
        propietario.enviar(
            "autorizar", invitado="Invitado123", puerta="principal",
            inicio=ahora - 60, fin=ahora + 3600,
        )
        print("[PASS] Propietario registra y firma una autorización.")
        propietario.enviar("logout")

        invitado.login("Invitado123", "Invitado#2026ok")
        print("[PASS] Invitado inicia sesión.")
        print("[PASS] Puerta principal:", invitado.enviar("abrir", puerta="principal"))
        try:
            invitado.enviar("abrir", puerta="garaje")
        except HubError:
            print("[BLOCKED] Invitado sin permiso no abre el garaje.")

        # Ataque de alteración de un ciphertext: se cambia un bit del tag GCM.
        sesion = hub.sesiones[invitado.token]
        contador = sesion["rx"] + 1
        cabecera = contador.to_bytes(8, "big")
        blob = cu.encrypt(
            sesion["clave"], cu.canonico({"cmd": "estado", "args": {}}),
            b"C" + invitado.token.encode("ascii") + cabecera,
        )
        alterado = bytearray(cabecera + blob)
        alterado[-1] ^= 1
        try:
            hub.ejecutar(invitado.token, bytes(alterado))
        except HubError:
            print("[BLOCKED] AES-GCM rechaza el mensaje manipulado.")

        # Un mensaje correcto solo puede procesarse una vez.
        respuesta = hub.ejecutar(invitado.token, cabecera + blob)
        try:
            hub.ejecutar(invitado.token, cabecera + blob)
        except HubError:
            print("[BLOCKED] El contador rechaza la repetición (replay).")
        invitado.tx = contador
        invitado.rx = int.from_bytes(respuesta[:8], "big")

        # Se altera la firma de la autorización y se comprueba que el acceso cae.
        registro_aut = hub.datos["autorizaciones"][0]
        firma_original = registro_aut["firma"]
        firma_alterada = bytearray(cu.unb64(firma_original))
        firma_alterada[-1] ^= 1
        registro_aut["firma"] = cu.b64(bytes(firma_alterada))
        try:
            invitado.enviar("abrir", puerta="principal")
        except HubError:
            print("[BLOCKED] ECDSA rechaza la autorización modificada.")
        registro_aut["firma"] = firma_original

        # Cinco fallos en la ventana activa el primer bloqueo progresivo.
        print("\n--- Control de frecuencia de login ---")
        for intento in range(1, 6):
            try:
                hub.login("Invitado123", "contraseña-incorrecta")
            except HubError:
                print(f"Intento fallido {intento}/5")
        try:
            hub.login("Invitado123", "Invitado#2026ok")
        except HubError:
            print("[BLOCKED] La cuenta queda temporalmente limitada incluso con la contraseña correcta.")
        reloj.avanzar(31)
        hub.login("Invitado123", "Invitado#2026ok")
        print("[PASS] Tras finalizar el bloqueo, el login correcto vuelve a funcionar.")

        # Se altera una copia del JSON sin recalcular HMAC.
        datos_fichero = json.loads(ruta.read_text(encoding="utf-8"))
        datos_fichero["datos"]["usuarios"]["Invitado123"]["rol"] = "propietario"
        ruta.write_text(json.dumps(datos_fichero), encoding="utf-8")
        try:
            Hub(
                ruta, passphrase_hub,
                reloj=lambda: reloj.wall,
                reloj_monotonic=lambda: reloj.mono,
            )
        except HubError:
            print("[BLOCKED] HMAC detecta la modificación del fichero JSON.")

    print("\n========== FIN DE LA DEMOSTRACIÓN ==========")
    print("La demo utiliza un directorio temporal y no modifica datos reales.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].lower() == "demo":
