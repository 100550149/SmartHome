"""Funciones criptográficas de SmartHome Security (librería `cryptography`).

Mismas herramientas vistas en clase: Scrypt (práctica 1), AES-GCM (práctica 2),
y además ECDSA (firma digital) y HMAC-SHA256.
Nunca se muestran claves, contraseñas ni secretos en los logs.
"""
import base64
import json
import logging
import os # para aleatoriedad segura

from cryptography.exceptions import InvalidKey, InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec #permite trabajar con criptografía de curva elíptica
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

log = logging.getLogger("crypto")

# Parámetros de scrypt (los mismos de la práctica 1) que protege a las contraseñas
#almacenando el hash de la contraseña del usuario
SCRYPT_N = 2 ** 14   # coste de CPU/memoria
SCRYPT_R = 8         # tamaño de bloque (memoria)
SCRYPT_P = 1         # paralelismo
SALT_LEN = 16        # 128 bits
KEY_LEN = 32         # 256 bits -> AES-256


class CryptoError(Exception):
    """Dato alterado, clave incorrecta o firma inválida."""


def b64(data: bytes) -> str:
    """Pasan bytes a texto y viceversa para guardarlos en Json """
    return base64.b64encode(data).decode()


def unb64(text: str) -> bytes:
    try:
        return base64.b64decode(text.encode(), validate=True)
    except (ValueError, UnicodeError, AttributeError) as exc:
        raise CryptoError("base64 inválido") from exc


def canonico(obj) -> bytes:
    """JSON determinista: claves ordenadas, UTF-8, sin NaN ni espacios.

    El mismo objeto produce los mismos bytes aunque el diccionario se haya
    construido en otro orden. Eso es lo que se firma y lo que entra en el HMAC.
    """
    try:
        texto = json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise CryptoError("datos no canónicos") from exc
    return texto.encode("utf-8")


# ------------------------------------------------------------ contraseñas
def _scrypt(salt: bytes) -> Scrypt:
    return Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)


def _utf8(password: str) -> bytes:
    if not isinstance(password, str):
        raise CryptoError("contraseña no codificable")
    try:
        return password.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CryptoError("contraseña no codificable") from exc


def hash_password(password: str) -> dict:
    """Guarda sal + hash scrypt (nunca la contraseña)."""
    #genera un salt aleatoria de 16 byte
    salt = os.urandom(SALT_LEN)
    #calcula el resultado de Scrypt
    digest = _scrypt(salt).derive(_utf8(password))
    log.debug("scrypt n=%d r=%d p=%d, sal=%d bits", SCRYPT_N, SCRYPT_R, SCRYPT_P, SALT_LEN * 8)
    #Convierte los bytes a texto Base64 para almacenarlos
    return {"salt": b64(salt), "hash": b64(digest)}


def verify_password(password: str, registro: dict) -> bool:
    """Verifica la contraseña introducida coincida con la que se registró"""
    try:
        _scrypt(unb64(registro["salt"])).verify(_utf8(password), unb64(registro["hash"]))
        return True
    except (InvalidKey, KeyError, TypeError, ValueError, CryptoError):
        return False


def derive_key(password: str, salt: bytes) -> bytes:
    """Clave de 256 bits derivada con Scrypt. Cada uso lleva su propia sal de 16 bytes."""
    if not isinstance(salt, (bytes, bytearray)) or len(salt) != SALT_LEN:
        raise CryptoError("no se puede derivar la clave")
    key = _scrypt(bytes(salt)).derive(_utf8(password))
    # Longitud y parámetros, nunca la clave ni la sal.
    log.debug("Derivación scrypt: clave de %d bits (n=%d, r=%d, p=%d, sal=%d bits)",
              len(key) * 8, SCRYPT_N, SCRYPT_R, SCRYPT_P, SALT_LEN * 8)
    return key


# ------------------------------------------------------------- AES-GCM
def _aes256(key: bytes) -> AESGCM:
    """Solo AES-256. Otra longitud se rechaza: no se degrada a AES-128."""
    if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_LEN:
        raise CryptoError("clave AES-256 inválida")
    return AESGCM(bytes(key))


def _bytes(nombre: str, valor) -> bytes:
    if not isinstance(valor, (bytes, bytearray)):
        raise CryptoError(f"{nombre} inválido")
    return bytes(valor)


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Protege información privada.
    AES-256-GCM. Devuelve nonce(12) + texto cifrado + tag."""
    cifrador = _aes256(key)
    plaintext, aad = _bytes("claro", plaintext), _bytes("aad", aad)
    nonce = os.urandom(12)  # nonce nuevo y aleatorio en cada cifrado; 96 bits, tamaño propio de GCM
    blob = nonce + cifrador.encrypt(nonce, plaintext, aad)
    # Algoritmo y tamaños. Nunca la clave, el nonce ni el texto en claro.
    log.debug("AES-GCM %d bits cifrado: %d bytes -> %d bytes (nonce 96 bits + tag 128 bits)",
              len(key) * 8, len(plaintext), len(blob))
    return blob


def decrypt(key: bytes, blob: bytes, aad: bytes) -> bytes:
    cifrador = _aes256(key)
    blob, aad = _bytes("mensaje", blob), _bytes("aad", aad)
    if len(blob) < 12 + 16:
        raise CryptoError("mensaje demasiado corto")
    try:
        plaintext = cifrador.decrypt(blob[:12], blob[12:], aad)
    except InvalidTag as exc:
        log.debug("AES-GCM descifrado FALLIDO: tag inválido (datos alterados o clave incorrecta)")
        raise CryptoError("tag GCM inválido: datos alterados o clave incorrecta") from exc
    log.debug("AES-GCM descifrado correcto: %d bytes, tag verificado", len(plaintext))
    return plaintext


# --------------------------------------------------------- firma digital
def generate_signing_key():
    """Genera una clave privada utilizando ECDSA y la curva P-256"""
    log.debug("Generando clave ECDSA P-256 (256 bits)")
    return ec.generate_private_key(ec.SECP256R1())


def private_to_bytes(key) -> bytes:
    """Convierte la clave privada en bytes para poder guardarla en un archivo o almacenarla cifrada"""
    return key.private_bytes(
        serialization.Encoding.DER, #formato binario para representar la clave
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())


def private_from_bytes(data: bytes):
    try:
        #recibe los buytes de una clave privada
        key = serialization.load_der_private_key(data, password=None)
    except ValueError as exc:
        #intenta reconstruir la clave
        raise CryptoError("clave privada inválida") from exc
    #comprueba que realmente sea una clave de curva el'iptica
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise CryptoError("se esperaba ECDSA P-256")
    if key.key_size != 256:
        raise CryptoError("se esperaba ECDSA P-256")
    return key


def public_bytes(key) -> bytes:
    """Obtener la clave pública correspondiente a la clave privada"""
    return key.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)


def sign(key, data: bytes) -> bytes:
    """Crea la firma digital"""
    log.debug("Firma ECDSA P-256 con SHA-256")
    # se utiliza ECDSA y SHA256 para calcular el resumen de los datos y genera la firma digital
    return key.sign(data, ec.ECDSA(hashes.SHA256()))


def verify_signature(public: bytes, data: bytes, signature: bytes) -> bool:
    """Verifica la firma digital
    public: clave publica del propietario
    data: el contenido de la autorización
    signature:la firma digital"""
    try:
        #Convierte los bytes recibidos en una clave pública
        pub = serialization.load_der_public_key(public)
        if not isinstance(pub, ec.EllipticCurvePublicKey) or not isinstance(pub.curve, ec.SECP256R1):
            raise InvalidSignature
        if not isinstance(data, (bytes, bytearray)) or not isinstance(signature, (bytes, bytearray)):
            raise InvalidSignature
        #comprueba si la firma corresponde exactamente a esos datos y a esa clave pública
        pub.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        log.debug("Verificación de firma: válida")
        return True
    except (InvalidSignature, ValueError, TypeError, AttributeError):
        log.debug("Verificación de firma: INVÁLIDA")
        return False


# ----------------------------------------------------------------- HMAC
def hmac_tag(key: bytes, data: bytes) -> bytes:
    key, data = _bytes("clave hmac", key), _bytes("datos hmac", data)
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    tag = h.finalize()
    log.debug("HMAC-SHA256: etiqueta calculada, clave de %d bits, entrada de %d bytes",
              len(key) * 8, len(data))
    return tag


def hmac_ok(key: bytes, data: bytes, tag: bytes) -> bool:
    try:
        key, data = _bytes("clave hmac", key), _bytes("datos hmac", data)
        etiqueta = _bytes("etiqueta", tag)
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(data)
        h.verify(etiqueta)  # comparación en tiempo constante
    except (InvalidSignature, CryptoError, ValueError, TypeError):
        bits = len(key) * 8 if isinstance(key, (bytes, bytearray)) else 0
        log.debug("HMAC-SHA256: verificación FALLIDA, clave de %d bits", bits)
        return False
    log.debug("HMAC-SHA256: verificación correcta, clave de %d bits", len(key) * 8)
    return True
