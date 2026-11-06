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
    """JSON determinista: es lo que se firma / autentica."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# ------------------------------------------------------------ contraseñas
def _scrypt(salt: bytes) -> Scrypt:
    return Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)


def hash_password(password: str) -> dict:
    """Guarda sal + hash scrypt (nunca la contraseña)."""
    #genera un salt aleatoria de 16 byte
    salt = os.urandom(SALT_LEN)
    #calcula el resultado de Scrypt
    digest = _scrypt(salt).derive(password.encode())
    log.debug("scrypt n=%d r=%d p=%d, sal=%d bits", SCRYPT_N, SCRYPT_R, SCRYPT_P, SALT_LEN * 8)
    #Convierte los bytes a texto Base64 para almacenarlos
    return {"salt": b64(salt), "hash": b64(digest)}


def verify_password(password: str, registro: dict) -> bool:
    """Verifica la contraseña introducida coincida con la que se registró"""
    try:
        _scrypt(unb64(registro["salt"])).verify(password.encode(), unb64(registro["hash"]))
        return True
    except (InvalidKey, KeyError, TypeError, ValueError, CryptoError):
        return False


def derive_key(password: str, salt: bytes) -> bytes:
    """Clave AES-256 derivada de una contraseña (scrypt) con una sal dada."""
    return _scrypt(salt).derive(password.encode())


# ------------------------------------------------------------- AES-GCM
def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Protege información pribada
    AES-256-GCM. Devuelve nonce(12) + texto cifrado + tag."""
    nonce = os.urandom(12)  # nonce nuevo y aleatorio en cada cifrado
    blob = nonce + AESGCM(key).encrypt(nonce, plaintext, aad)
    # Solo se muestran tamaños y el inicio del texto cifrado (es público); nunca clave ni texto en claro
    log.debug("AES-GCM %d bits cifrado: %d bytes -> %d bytes (nonce 96 bits + tag 128 bits)",
              len(key) * 8, len(plaintext), len(blob))
    return blob


def decrypt(key: bytes, blob: bytes, aad: bytes) -> bytes:
    if len(blob) < 12 + 16:
        raise CryptoError("mensaje demasiado corto")
    try:
        plaintext = AESGCM(key).decrypt(blob[:12], blob[12:], aad)
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
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise CryptoError("tipo de clave inesperado")
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
        #comprueba si la firma corresponde exactamente a esos datos y a esa clave pública
        pub.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        log.debug("Verificación de firma: válida")
        return True
    except (InvalidSignature, ValueError, TypeError, AttributeError):
        log.debug("Verificación de firma: INVÁLIDA")
        return False


# ----------------------------------------------------------------- HMAC
def hmac_tag(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def hmac_ok(key: bytes, data: bytes, tag: bytes) -> bool:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    try:
        h.verify(tag)  # comparación en tiempo constante
        return True
    except InvalidSignature:
        return False
