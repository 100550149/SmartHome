"""Lógica de SmartHome Security: el Hub (casa) y la App del usuario.
"""
import json
import logging
import os
import secrets
import subprocess
import time
import unicodedata
from contextlib import contextmanager
from pathlib import Path

import crypto_utils as cu

log = logging.getLogger("smarthome")

PUERTAS = ("principal", "garaje", "trasera")
MIN_PASSWORD = 8
MAX_PASSWORD = 128
MAX_USUARIO = 64
MAX_FALLOS = 5
# Tras MAX_FALLOS intentos fallidos la cuenta queda bloqueada estos segundos.
BLOQUEO_SEG = 60
MAX_AUTORIZACION = 24 * 3600


def identidad(usuario):
    """Nombre canónico: NFC, sin vacíos ni caracteres de control.

    «José» y la misma letra en forma descompuesta son la misma cuenta, así el
    bloqueo no se esquiva cambiando la forma unicode. Las mayúsculas no se
    pliegan: «Ana» y «ana» son cuentas distintas, cada una con su bloqueo.
    """
    if not isinstance(usuario, str):
        raise HubError("usuario inválido")
    normal = unicodedata.normalize("NFC", usuario)
    if not normal or normal != normal.strip() or len(normal) > MAX_USUARIO:
        raise HubError("usuario inválido")
    if any(ord(c) < 32 for c in normal):
        raise HubError("usuario inválido")
    return normal


def _validar_password(password):
    """Reglas del registro. En el login el mensaje es otro, y es genérico."""
    if not isinstance(password, str) or len(password) > MAX_PASSWORD:
        raise HubError("contraseña inválida")
    if len(password) < MIN_PASSWORD:
        raise HubError(f"contraseña débil: mínimo {MIN_PASSWORD} caracteres")


class HubError(Exception):
    """Error de aplicación que se devuelve al usuario."""


def ruta_generacion(ruta) -> Path:
    """Contador monótono junto al JSON. Impide reponer una copia antigua del fichero."""
    return Path(str(ruta) + ".gen")


def restringir(ruta) -> None:
    """Deja el fichero solo para el usuario actual.

    En POSIX, 0o600. En Windows ese modo no cambia la ACL: hay que quitar la
    herencia y conceder lectura y escritura únicamente al usuario actual.
    """
    ruta = Path(ruta)
    if os.name != "nt":
        os.chmod(ruta, 0o600)
        return
    usuario = os.environ.get("USERNAME") or os.environ.get("USER")
    if not usuario:
        raise OSError("no hay usuario para la ACL")
    resultado = subprocess.run(
        ["icacls", str(ruta), "/inheritance:r", "/grant:r", f"{usuario}:(R,W)"],
        capture_output=True, text=True, check=False,
    )
    if resultado.returncode != 0:
        raise OSError(resultado.stderr.strip() or "icacls falló")


def permisos_privados(ruta) -> bool:
    """True si el fichero no es legible por otros usuarios."""
    ruta = Path(ruta)
    if os.name != "nt":
        return (ruta.stat().st_mode & 0o777) == 0o600
    usuario = os.environ.get("USERNAME") or os.environ.get("USER") or ""
    resultado = subprocess.run(
        ["icacls", str(ruta)], capture_output=True, text=True, check=False,
    )
    if resultado.returncode != 0 or not usuario:
        return False
    texto = resultado.stdout
    # La salida lista cada ACE. El usuario actual tiene que aparecer y los
    # grupos amplios no pueden tener permiso.
    amplios = ("Everyone:", "Todos:", "BUILTIN\\Users:", "Usuarios autentificados:", "Authenticated Users:")
    return usuario in texto and not any(grupo in texto for grupo in amplios)


def _escribir_atomico(destino: Path, texto: str) -> None:
    """Escribe en un temporal, hace fsync y sustituye. Un corte no deja el destino a medias."""
    destino = Path(destino)
    tmp = Path(str(destino) + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        restringir(tmp)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fd = None
            fh.write(texto)
            fh.flush()
            os.fsync(fh.fileno())
    except Exception:
        if fd is not None:
            os.close(fd)
        tmp.unlink(missing_ok=True)
        raise
    os.replace(tmp, destino)
    restringir(destino)


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
            if not isinstance(passphrase, str) or not MIN_PASSWORD <= len(passphrase) <= MAX_PASSWORD:
                raise HubError(f"la passphrase del hub necesita {MIN_PASSWORD}+ caracteres")
            # Establecer una protección criptográfica
            # Crear un salt para derivar la clave maestra
            self._salt = os.urandom(cu.SALT_LEN)
            self._clave_mac = cu.derive_key(passphrase, self._salt)
            self.datos = {"usuarios": {}, "autorizaciones": [], "revocadas": []}
            try:
                self._guardar()
            except (OSError, cu.CryptoError, TypeError, ValueError) as exc:
                raise HubError("no se pudo guardar") from exc

    def ruta_generacion(self) -> Path:
        return ruta_generacion(self.ruta)

    @contextmanager
    def _exclusion(self):
        """Un solo escritor a la vez. flock en POSIX, msvcrt en Windows."""
        candado = Path(str(self.ruta) + ".lock")
        fd = os.open(candado, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            restringir(candado)
            if os.name == "nt":
                import msvcrt
                if os.fstat(fd).st_size == 0:
                    os.write(fd, b"\0")
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                if os.name == "nt":
                    import msvcrt
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _bytes_mac(self, datos) -> bytes:
        """La sal entra en el HMAC, no solo en la derivación de la clave."""
        return cu.canonico({"salt": cu.b64(self._salt), "datos": datos})

    def _bytes_gen(self, n: int) -> bytes:
        return b"smart-home-generacion:" + str(n).encode("ascii")

    def _escribir_generacion(self, n: int) -> None:
        cuerpo = {"generacion": n, "mac": cu.b64(cu.hmac_tag(self._clave_mac, self._bytes_gen(n)))}
        _escribir_atomico(self.ruta_generacion(), json.dumps(cuerpo, indent=1, ensure_ascii=True))

    # ---------------------------------------------- almacén protegido (HMAC)
    def _cargar(self, passphrase):
        """leer el archivo JSON y recuperar información """
        if not isinstance(passphrase, str):
            raise HubError("passphrase inválida")
        with self._exclusion():
            try:
                fichero = json.loads(self.ruta.read_text("utf-8"))
                self._salt = cu.unb64(fichero["salt"])
                # Obtiene la clave derivada a partir de la contraseña maestra
                self._clave_mac = cu.derive_key(passphrase, self._salt)
                datos, tag = fichero["datos"], cu.unb64(fichero["mac"])
                if not isinstance(datos, dict):
                    raise cu.CryptoError("datos")
                ok = cu.hmac_ok(self._clave_mac, self._bytes_mac(datos), tag)
            except OSError as exc:
                raise HubError("no se pudo leer el fichero") from exc
            except (ValueError, KeyError, TypeError, cu.CryptoError) as exc:
                raise HubError("fichero de datos corrupto") from exc
            #comprueba si los datod no hayan sido modificados y que la contraseña maestra sea correcta
            if not ok:
                raise HubError("datos alterados o passphrase incorrecta (HMAC inválido)")
            self._comprobar_generacion(datos)
            self.datos = datos

    def _comprobar_generacion(self, datos):
        """Rechaza un JSON auténtico pero más viejo que el último guardado."""
        gen = datos.get("generacion")
        if type(gen) is not int or gen < 1:
            raise HubError("fichero de datos corrupto")
        try:
            guardado = json.loads(self.ruta_generacion().read_text("utf-8"))
            n, mac = guardado["generacion"], cu.unb64(guardado["mac"])
        except (OSError, ValueError, KeyError, TypeError, cu.CryptoError) as exc:
            raise HubError("fichero de datos corrupto") from exc
        if type(n) is not int or not cu.hmac_ok(self._clave_mac, self._bytes_gen(n), mac):
            raise HubError("fichero de datos corrupto")
        if n > gen:
            raise HubError("copia antigua del fichero rechazada (generación inferior)")
        if n < gen:
            self._escribir_generacion(gen)

    def _guardar(self):
        """Guarda los datos en el archivo JSON y avanza la generación."""
        anterior = int(self.datos.get("generacion", 0) or 0)
        self.datos["generacion"] = anterior + 1
        json_escrito = False
        try:
            with self._exclusion():
                fichero = {"salt": cu.b64(self._salt), "datos": self.datos,
                           "mac": cu.b64(cu.hmac_tag(self._clave_mac, self._bytes_mac(self.datos)))}
                _escribir_atomico(self.ruta, json.dumps(
                    fichero, indent=1, ensure_ascii=True, allow_nan=False))
                json_escrito = True
                self._escribir_generacion(self.datos["generacion"])
        except (OSError, cu.CryptoError, TypeError, ValueError):
            if not json_escrito:
                self.datos["generacion"] = anterior
            raise

    def _evento(self, texto):
        """Para añadir los eventos realizados"""
        self.eventos.append(f"{int(self.reloj())} {texto}")
        log.info("EVENTO %s", texto)

    # ------------------------------------------------- registro y login
    def registrar(self, usuario, password):
        usuario = identidad(usuario)
        _validar_password(password)
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
        try:
            self._guardar()
        except (OSError, cu.CryptoError, TypeError, ValueError) as exc:
            del usuarios[usuario]
            raise HubError("no se pudo guardar") from exc
        self._evento(f"REGISTRO {usuario} rol={rol}")
        return rol

    def login(self, usuario, password):
        """Permite que un usuario acceda al sistema"""
        usuario = identidad(usuario)
        # Una contraseña que el registro nunca habría aceptado falla igual para todas las cuentas,
        # sin gastar Scrypt y sin decir si el usuario existe.
        if not isinstance(password, str) or not MIN_PASSWORD <= len(password) <= MAX_PASSWORD:
            raise HubError("credenciales inválidas")
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
            bruto = bytearray()
            try:
                clave = cu.derive_key(password, cu.unb64(kp["salt"]))
                bruto = bytearray(cu.decrypt(clave, cu.unb64(kp["datos"]), usuario.encode()))
                sesion["clave_firma"] = cu.private_from_bytes(bytes(bruto))
            except (cu.CryptoError, KeyError, TypeError, ValueError) as exc:
                raise HubError("no se pudo abrir la clave de firma") from exc
            finally:
                # La copia que aún tenga CPython no desaparece; esta sí se borra.
                for i in range(len(bruto)):
                    bruto[i] = 0
        #token identificador unico de la sesión
        # con secrets generamos un token seguro y aleatorio
        token = secrets.token_hex(16)
        self.sesiones[token] = sesion
        self._evento(f"LOGIN_OK {usuario}")
        return token, salt_sesion

    # ---------------------------------- órdenes cifradas y autenticadas
    def ejecutar(self, token, mensaje: bytes) -> bytes:
        # utiliza token para encontrar la sesion
        if not isinstance(token, str):
            raise HubError("sesión desconocida")
        ses = self.sesiones.get(token)
        if ses is None:
            raise HubError("sesión desconocida")
        if not isinstance(mensaje, (bytes, bytearray)) or len(mensaje) < 8 + 12 + 16:
            self._evento(f"ORDEN_RECHAZADA {ses['usuario']}: mensaje inválido")
            raise HubError("orden rechazada")
        #obtener el counter y cambiarlos a integer con Big Endian de más significantivos a menos
        cabecera = bytes(mensaje[:8])
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
        if ses["tx"] >= 2**64 - 1:
            raise HubError("sesión agotada")
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
                try:
                    self._guardar()
                except (OSError, cu.CryptoError, TypeError, ValueError) as exc:
                    self.datos["revocadas"].pop()
                    raise HubError("no se pudo guardar") from exc
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
        puerta = args.get("puerta")
        inicio, fin = args.get("inicio"), args.get("fin")
        try:
            invitado = identidad(args.get("invitado"))
        except HubError:
            raise HubError("el invitado no existe") from None
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
        if ses.get("clave_firma") is None:
            raise HubError("no se pudo abrir la clave de firma")
        firma = cu.sign(ses["clave_firma"], cu.canonico(datos))
        self.datos["autorizaciones"].append({"datos": datos, "firma": cu.b64(firma)})
        try:
            self._guardar()
        except (OSError, cu.CryptoError, TypeError, ValueError) as exc:
            self.datos["autorizaciones"].pop()
            raise HubError("no se pudo guardar") from exc
        self._evento(f"AUTORIZACION {invitado} {puerta} id={datos['id'][:8]}")
        return datos

    def _autorizacion_valida(self, invitado, puerta):
        """Busca una autorización con firma válida, vigente y no revocada."""
        ahora = self.reloj()
        for registro in self.datos.get("autorizaciones", []):
            if not isinstance(registro, dict):
                continue
            d = registro.get("datos")
            if not isinstance(d, dict):
                continue
            ident = d.get("id")
            try:
                if d.get("invitado") != invitado or d.get("puerta") != puerta:
                    continue
                if ident in self.datos.get("revocadas", []):
                    continue
                dueño = self.datos["usuarios"].get(d.get("propietario"))
                valida = (
                    isinstance(dueño, dict)
                    and dueño.get("rol") == "propietario"
                    and cu.verify_signature(
                        cu.unb64(dueño["clave_publica"]), cu.canonico(d), cu.unb64(registro.get("firma")))
                )
            except (KeyError, TypeError, ValueError, cu.CryptoError):
                valida = False
            if not valida:
                self._evento(f"FIRMA_INVALIDA autorización {str(ident)[:8]} rechazada")
                continue
            inicio, fin = d.get("inicio"), d.get("fin")
            if type(inicio) is int and type(fin) is int and inicio <= ahora < fin:
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
        if self.token is None or self.clave is None:
            raise HubError("inicia sesión primero")
        if self.tx >= 2**64 - 1:
            raise HubError("sesión agotada")
        self.tx += 1
        cab = self.tx.to_bytes(8, "big")
        orden = cu.encrypt(self.clave, cu.canonico({"cmd": cmd, "args": args}),
                           b"C" + self.token.encode() + cab)
        respuesta = self.hub.ejecutar(self.token, cab + orden)
        if not isinstance(respuesta, (bytes, bytearray)) or len(respuesta) < 8 + 12 + 16:
            raise HubError("respuesta del hub no válida")
        cab_r = bytes(respuesta[:8])
        contador = int.from_bytes(cab_r, "big")
        if contador <= self.rx:
            raise HubError("respuesta repetida")
        try:
            texto = cu.decrypt(self.clave, respuesta[8:], b"H" + self.token.encode() + cab_r)
            resultado = json.loads(texto)
            if not isinstance(resultado, dict) or "ok" not in resultado:
                raise cu.CryptoError("respuesta")
        except (cu.CryptoError, json.JSONDecodeError, TypeError, ValueError, UnicodeError) as exc:
            raise HubError("respuesta del hub no válida") from exc
        self.rx = contador
        if cmd == "logout":
            self.token = self.clave = None
        if not resultado["ok"]:
            raise HubError(resultado["error"])
        return resultado["datos"]
