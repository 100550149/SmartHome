"""Lógica de SmartHome Security: el Hub (casa) y la App del usuario.
"""
import json
import logging
import os
import secrets
import time
from pathlib import Path

import crypto_utils as cu

log = logging.getLogger("smarthome")

PUERTAS = ("principal", "garaje", "trasera")
MIN_PASSWORD = 8
MAX_FALLOS = 5
#tiempos de bloquo en segundo en el caso de superar el max_fallos
BLOQUEO_SEG = 60
MAX_AUTORIZACION = 24 * 3600


class HubError(Exception):
    """Error de aplicación que se devuelve al usuario."""


class Hub:
    """El centro de control. Gestiona usuarios, comprueba permisos , controla las puertas y alarmas """
    def __init__(self, ruta, passphrase, reloj=time.time):
        #ruta: indica donde se guarda los datos
        #passphrase: contraseña de la administración
        #reloj: indica la hora actual
        self.ruta, self.reloj = Path(ruta), reloj
        #sesiones:
        #fallos: los fallos de accesos
        #eventos: los ultimos eventos de la aplicación
        self.sesiones, self._fallos, self.eventos = {}, {}, []
        #estado de las puertas de la casa
        self.puertas = {p: "cerrada" for p in PUERTAS}
        #estado de la alarma
        self.alarma = False
        self._dummy = cu.hash_password("contraseña-ficticia")  # iguala tiempos si el usuario no existe
        if self.ruta.exists():
            # si existe el archivo de datos carga los datos guardados
            self._cargar(passphrase)
        else:
            # si no existe pide un passphrase para crear uno
            if len(passphrase) < MIN_PASSWORD:
                raise HubError(f"la passphrase del hub necesita {MIN_PASSWORD}+ caracteres")
            # Establecer una protección criptográfica
            # Crear un salt para derivar la clave maestra
            self._salt = os.urandom(cu.SALT_LEN)
            self._clave_mac = cu.derive_key(passphrase, self._salt)
            self.datos = {"usuarios": {}, "autorizaciones": [], "revocadas": []}
            self._guardar()

    # ---------------------------------------------- almacén protegido (HMAC)
    def _cargar(self, passphrase):
        """leer el archivo JSON y recuperar información """
        try:
            fichero = json.loads(self.ruta.read_text("utf-8"))
            self._salt = cu.unb64(fichero["salt"])
            # Obtiene la clave derivada a partir de la contraseña maestra
            self._clave_mac = cu.derive_key(passphrase, self._salt)
            datos, tag = fichero["datos"], cu.unb64(fichero["mac"])
        except (ValueError, KeyError, TypeError, cu.CryptoError) as exc:
            raise HubError("fichero de datos corrupto") from exc
        #comprueba si los datod no hayan sido modificados y que la contraseña maestra sea correcta
        if not cu.hmac_ok(self._clave_mac, cu.canonico(datos), tag):
            raise HubError("datos alterados o passphrase incorrecta (HMAC inválido)")
        self.datos = datos

    def _guardar(self):
        """Guarda los datos en el archivo JSON"""
        fichero = {"salt": cu.b64(self._salt), "datos": self.datos,
                   "mac": cu.b64(cu.hmac_tag(self._clave_mac, cu.canonico(self.datos)))}
        #crea un archivo temporal
        tmp = self.ruta.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # permisos restrictivos
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            #Escribe el diccionario "fichero" en el archivo temporal
            json.dump(fichero, fh, indent=1)
        # Sustituye el archivo temporal por el nuevo
        os.replace(tmp, self.ruta)

    def _evento(self, texto):
        """Para añadir los eventos realizados"""
        self.eventos.append(f"{int(self.reloj())} {texto}")
        log.info("EVENTO %s", texto)

    # ------------------------------------------------- registro y login
    def registrar(self, usuario, password):
        if not isinstance(password, str):
            raise HubError("contraseña inválida")
        if len(password) < MIN_PASSWORD:
            raise HubError(f"contraseña débil: mínimo {MIN_PASSWORD} caracteres")
        # añadir nuevo usuario en en el base de datos
        usuarios = self.datos["usuarios"]
        if usuario in usuarios:
            #Contrala que no haya 2 usuarios iguales
            raise HubError("usuario no disponible")
        #El primer usuario registrado es propietario de la casa los demás se registran como invitados
        rol = "invitado" if any(u["rol"] == "propietario" for u in usuarios.values()) else "propietario"
        registro = {"rol": rol, "pw": cu.hash_password(password)}
        if rol == "propietario":
            # Par de claves de firma; la privada se guarda CIFRADA con una clave derivada de su contraseña
            #general una clave privada al propietario para crear la firma digital
            privada = cu.generate_signing_key()
            salt = os.urandom(cu.SALT_LEN)
            clave = cu.derive_key(password, salt)
            registro["clave_publica"] = cu.b64(cu.public_bytes(privada))
            registro["clave_privada"] = {
                "salt": cu.b64(salt),
                "datos": cu.b64(cu.encrypt(clave, cu.private_to_bytes(privada), usuario.encode()))}
        # añadir el usuario en el base de datos
        usuarios[usuario] = registro
        self._guardar()
        self._evento(f"REGISTRO {usuario} rol={rol}")
        return rol

    def login(self, usuario, password):
        """Permite que un usuario acceda al sistema"""
        ahora = self.reloj()
        #fallos: números de fallos accumulados
        #Hasta: hasta cuando se termina el bloqueo
        fallos, hasta = self._fallos.get(usuario, (0, 0))
        if ahora < hasta:
            self._evento(f"LOGIN_BLOQUEADO {usuario}")
            raise HubError("demasiados intentos, inténtalo más tarde")
        registro = self.datos["usuarios"].get(usuario)
        #verifica la contraseña del usuario, si el usuario no existe usaremos self._dummy
        correcto = cu.verify_password(password, registro["pw"] if registro else self._dummy)
        if not (correcto and registro):
            fallos += 1
            #Si el número de fallos superan a lo máximo, añade un tiempo de bloqueo
            self._fallos[usuario] = (fallos, ahora + BLOQUEO_SEG if fallos >= MAX_FALLOS else 0)
            self._evento(f"LOGIN_FALLIDO {usuario} intento={fallos}")
            raise HubError("credenciales inválidas")  # mensaje genérico
        #si la verificación es correcta
        self._fallos.pop(usuario, None)
        # Crea una sesion cuando el usuario se login para saber quién es, qué permiso tiene y qué claves utiliza para comunucarse
        # rx: contador de mensajes recibidos
        # tx: Contador de mensajes enciados
        # clave_firma : clave privada para firmar autorizaciones
        sesion = {"usuario": usuario, "rol": registro["rol"], "rx": 0, "tx": 0, "clave_firma": None}
        #Se evita utilizar siempre la misma clave para proteger las comunicaciones
        #Se genera una clave de comunidación en cada login
        salt_sesion = os.urandom(cu.SALT_LEN)  # sal nueva => clave de sesión nueva en cada login
        sesion["clave"] = cu.derive_key(password, salt_sesion)
        # solo el propirtario tendrá la clave privada para la firma
        if registro["rol"] == "propietario":
            kp = registro["clave_privada"]
            try:
                clave = cu.derive_key(password, cu.unb64(kp["salt"]))
                sesion["clave_firma"] = cu.private_from_bytes(
                    cu.decrypt(clave, cu.unb64(kp["datos"]), usuario.encode()))
            except cu.CryptoError as exc:
                raise HubError("no se pudo abrir la clave de firma") from exc
        #token identificador unico de la sesión
        # con secrets generamos un token seguro y aleatorio
        token = secrets.token_hex(16)
        self.sesiones[token] = sesion
        self._evento(f"LOGIN_OK {usuario}")
        return token, salt_sesion

    # ---------------------------------- órdenes cifradas y autenticadas
    def ejecutar(self, token, mensaje: bytes) -> bytes:
        # utiliza token para encontrar la sesion
        ses = self.sesiones.get(token)
        if ses is None:
            raise HubError("sesión desconocida")
        #obtener el counter y cambiarlos a integer con Big Endian de más significantivos a menos
        cabecera = mensaje[:8]
        contador = int.from_bytes(cabecera, "big")
        #Para evitar el ataque de repetición, es decir, se impide reutilizar una orden antigua que ya se había enciado
        try:
            if contador <= ses["rx"]:
                raise cu.CryptoError("orden repetida (replay)")
            # ADD：b"C" + token.encode() + cabecera
            texto = cu.decrypt(ses["clave"], mensaje[8:], b"C" + token.encode() + cabecera)
        except cu.CryptoError as exc:
            self._evento(f"ORDEN_RECHAZADA {ses['usuario']}: {exc}")  # fallo seguro: no se ejecuta nada
            raise HubError("orden rechazada") from exc
        ses["rx"] = contador  # solo se avanza tras autenticar
        try:
            orden = json.loads(texto)
            respuesta = {"ok": True, "datos": self._comando(token, ses, orden["cmd"], orden.get("args", {}))}
        except HubError as exc:
            respuesta = {"ok": False, "error": str(exc)}
        except (KeyError, TypeError, ValueError):
            respuesta = {"ok": False, "error": "orden inválida"}
        ses["tx"] += 1
        cab = ses["tx"].to_bytes(8, "big")
        return cab + cu.encrypt(ses["clave"], cu.canonico(respuesta), b"H" + token.encode() + cab)

    def _comando(self, token, ses, cmd, args):
        if not isinstance(args, dict):
            raise TypeError
        solo_propietario = {"alarma", "autorizar", "revocar", "eventos"}
        if cmd in solo_propietario and ses["rol"] != "propietario":
            raise HubError("solo el propietario puede hacer esto")
        if cmd == "estado":
            return {"puertas": dict(self.puertas), "alarma": self.alarma}
        if cmd in ("abrir", "cerrar"):
            return self._puerta(ses, cmd, args)
        if cmd == "alarma":
            if args.get("estado") not in ("on", "off"):
                raise HubError("estado de alarma inválido")
            self.alarma = args["estado"] == "on"
            self._evento(f"ALARMA {args['estado']} por {ses['usuario']}")
            return {"alarma": self.alarma}
        if cmd == "autorizar":
            return self._autorizar(ses, args)
        if cmd == "revocar":
            ident = args.get("id")
            if not any(a["datos"]["id"] == ident for a in self.datos["autorizaciones"]):
                raise HubError("autorización desconocida")
            if ident not in self.datos["revocadas"]:
                self.datos["revocadas"].append(ident)
                self._guardar()
            self._evento(f"REVOCADA {str(ident)[:8]}")
            return {"revocada": ident}
        if cmd == "eventos":
            return {"eventos": self.eventos[-10:]}
        if cmd == "logout":
            self.sesiones.pop(token, None)
            return {}
        raise HubError("comando desconocido")

    def _puerta(self, ses, cmd, args):
        puerta = args.get("puerta")
        if puerta not in PUERTAS:
            raise HubError("puerta desconocida")
        #cerrar la puerta
        if cmd == "cerrar":
            self.puertas[puerta] = "cerrada"
            return {"puerta": puerta, "estado": "cerrada"}
        if ses["rol"] == "invitado":
            #como invitado no puede cambiar el estado de la alarma
            if self.alarma:
                self._evento(f"ACCESO_DENEGADO {ses['usuario']} {puerta}: alarma activada")
                raise HubError("alarma activada: acceso denegado")
            auth = self._autorizacion_valida(ses["usuario"], puerta)
            if auth is None:
                #No se ha encontrado ningun autorizacion para dicho usuario
                self._evento(f"ACCESO_DENEGADO {ses['usuario']} {puerta}: sin autorización válida")
                raise HubError("acceso denegado")
        self.puertas[puerta] = "abierta"
        self._evento(f"ACCESO_CONCEDIDO {ses['usuario']} {puerta}")
        return {"puerta": puerta, "estado": "abierta"}

    # ------------------------------------------ autorizaciones firmadas
    def _autorizar(self, ses, args):
        invitado, puerta = args.get("invitado"), args.get("puerta")
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
        datos = {"id": secrets.token_hex(16), "propietario": ses["usuario"], "invitado": invitado,
                 "puerta": puerta, "inicio": inicio, "fin": fin, "emitida": int(self.reloj())}
        # crea una firma para la autorización
        firma = cu.sign(ses["clave_firma"], cu.canonico(datos))
        self.datos["autorizaciones"].append({"datos": datos, "firma": cu.b64(firma)})
        self._guardar()
        self._evento(f"AUTORIZACION {invitado} {puerta} id={datos['id'][:8]}")
        return datos

    def _autorizacion_valida(self, invitado, puerta):
        """Busca una autorización con firma válida, vigente y no revocada."""
        ahora = self.reloj()
        for registro in self.datos["autorizaciones"]:
            d = registro["datos"]
            if d["invitado"] != invitado or d["puerta"] != puerta or d["id"] in self.datos["revocadas"]:
                continue
            dueño = self.datos["usuarios"].get(d["propietario"])
            try:
                valida = bool(dueño) and dueño["rol"] == "propietario" and cu.verify_signature(
                    cu.unb64(dueño["clave_publica"]), cu.canonico(d), cu.unb64(registro["firma"]))
            except (KeyError, cu.CryptoError):
                valida = False
            if not valida:
                self._evento(f"FIRMA_INVALIDA autorización {d['id'][:8]} rechazada")
                continue
            if d["inicio"] <= ahora < d["fin"]:
                return d
        return None


class App:
    """App del usuario: cifra las órdenes y verifica las respuestas.
    Permite al usuario inicial session y enciar ordenes a Hub"""

    def __init__(self, hub: Hub):
        self.hub, self.token, self.clave = hub, None, None
        self.tx = self.rx = 0

    def registrar(self, usuario, password):
        return self.hub.registrar(usuario, password)

    def login(self, usuario, password):
        self.token, salt = self.hub.login(usuario, password)
        self.clave = cu.derive_key(password, salt)  # misma clave que el hub, sin enviarla
        self.tx = self.rx = 0

    def enviar(self, cmd, **args):
        if self.token is None:
            raise HubError("inicia sesión primero")
        self.tx += 1
        cab = self.tx.to_bytes(8, "big")
        orden = cu.encrypt(self.clave, cu.canonico({"cmd": cmd, "args": args}),
                           b"C" + self.token.encode() + cab)
        respuesta = self.hub.ejecutar(self.token, cab + orden)
        cab_r = respuesta[:8]
        contador = int.from_bytes(cab_r, "big")
        if contador <= self.rx:
            raise HubError("respuesta repetida")
        try:
            texto = cu.decrypt(self.clave, respuesta[8:], b"H" + self.token.encode() + cab_r)
        except cu.CryptoError as exc:
            raise HubError("respuesta del hub no válida") from exc
        self.rx = contador
        resultado = json.loads(texto)
        if cmd == "logout":
            self.token = self.clave = None
        if not resultado["ok"]:
            raise HubError(resultado["error"])
        return resultado["datos"]
