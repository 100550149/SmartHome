        if ses["rol"] == "invitado":
            if self.alarma:
                self._evento(f"ACCESO_DENEGADO {ses['usuario']} {puerta}: alarma activada")
                raise HubError("alarma activada: acceso denegado")
            autorizacion = self._autorizacion_valida(ses["usuario"], puerta)
            if autorizacion is None:
                self._evento(f"ACCESO_DENEGADO {ses['usuario']} {puerta}: sin autorización válida")
                raise HubError("acceso denegado")

        self.puertas[puerta] = "abierta"
        self._evento(f"ACCESO_CONCEDIDO {ses['usuario']} {puerta}")
        return {"puerta": puerta, "estado": "abierta"}

    # ------------------------------------------------------- firmas/autorización
    def _autorizar(self, ses: dict, args: dict):
        invitado = args.get("invitado")
        puerta = args.get("puerta")
        inicio, fin = args.get("inicio"), args.get("fin")
        destino = self.datos["usuarios"].get(invitado)

        if destino is None or destino["rol"] != "invitado":
            raise HubError("el invitado no existe")
        if puerta not in PUERTAS:
            raise HubError("puerta desconocida")
        if not all(isinstance(v, int) and not isinstance(v, bool) for v in (inicio, fin)):
            raise HubError("fechas inválidas")
        if not 0 < fin - inicio <= MAX_AUTORIZACION:
            raise HubError("intervalo inválido (máximo 24 h)")

        datos = {
            "id": secrets.token_hex(16),
            "propietario": ses["usuario"],
            "invitado": invitado,
            "puerta": puerta,
            "inicio": inicio,
            "fin": fin,
            "emitida": int(self.reloj()),
        }
        firma = cu.sign(ses["clave_firma"], cu.canonico(datos))
        self.datos["autorizaciones"].append({"datos": datos, "firma": cu.b64(firma)})
        self._guardar()
        self._evento(f"AUTORIZACION {invitado} {puerta} id={datos['id'][:8]}")
        return datos

    def _autorizacion_valida(self, invitado: str, puerta: str):
        ahora = self.reloj()
        for registro in self.datos["autorizaciones"]:
            try:
                datos = registro["datos"]
                if (
                    datos["invitado"] != invitado
                    or datos["puerta"] != puerta
                    or datos["id"] in self.datos["revocadas"]
                ):
                    continue
                propietario = self.datos["usuarios"].get(datos["propietario"])
                valida = (
                    bool(propietario)
                    and propietario["rol"] == "propietario"
                    and cu.verify_signature(
                        cu.unb64(propietario["clave_publica"]),
                        cu.canonico(datos),
                        cu.unb64(registro["firma"]),
                    )
                )
            except (KeyError, TypeError, ValueError, cu.CryptoError):
                valida = False
                datos = registro.get("datos", {})

            if not valida:
                ident = str(datos.get("id", "desconocido"))[:8]
                self._evento(f"FIRMA_INVALIDA autorización {ident} rechazada")
                continue
            if datos["inicio"] <= ahora < datos["fin"]:
                return datos
        return None


class App:
    """Interfaz lógica del usuario: cifra órdenes y verifica respuestas del Hub."""

    def __init__(self, hub: Hub):
        self.hub = hub
        self.token: str | None = None
        self.clave: bytes | None = None
        self.tx = 0
        self.rx = 0

    def registrar(self, usuario: str, password: str) -> str:
        return self.hub.registrar(usuario, password)

    def login(self, usuario: str, password: str) -> None:
        self.token = None
        self.clave = None
        token, salt = self.hub.login(usuario, password)
        self.token = token
        self.clave = cu.derive_key(password, salt)
        self.tx = self.rx = 0

    def enviar(self, cmd: str, **args):
        if self.token is None or self.clave is None:
            raise HubError("inicia sesión primero")

        self.tx += 1
        cabecera = self.tx.to_bytes(8, "big")
        orden = cu.encrypt(
            self.clave,
            cu.canonico({"cmd": cmd, "args": args}),
            b"C" + self.token.encode("ascii") + cabecera,
        )
        respuesta = self.hub.ejecutar(self.token, cabecera + orden)
        if len(respuesta) < 8 + cu.NONCE_LEN + cu.TAG_LEN:
            raise HubError("respuesta del Hub incompleta")

        cabecera_respuesta = respuesta[:8]
        contador = int.from_bytes(cabecera_respuesta, "big")
        if contador <= self.rx:
            raise HubError("respuesta repetida o antigua")
        try:
            texto = cu.decrypt(
                self.clave,
                respuesta[8:],
                b"H" + self.token.encode("ascii") + cabecera_respuesta,
            )
        except cu.CryptoError as exc:
            raise HubError("respuesta del Hub no válida") from exc

        self.rx = contador
