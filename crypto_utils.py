"""Herramientas criptográficas de SmartHome Security.

Algoritmos:
- Scrypt: almacenamiento de contraseñas y derivación de claves.
- AES-256-GCM: cifrado autenticado (AEAD).
- ECDSA P-256 + SHA-256: firma digital de autorizaciones.
- HMAC-SHA256: integridad/autenticidad del fichero de datos.

No se registran ni muestran claves, contraseñas o datos en claro.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from typing import Any

from cryptography.exceptions import InvalidKey, InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

log = logging.getLogger("crypto")

# Parámetros Scrypt
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1

SALT_LEN = 16       # 128 bits
KEY_LEN = 32        # 256 bits
NONCE_LEN = 12      # 96 bits
TAG_LEN = 16        # 128 bits


class CryptoError(Exception):
    """Error criptográfico controlado."""


def b64(data: bytes) -> str:
    """Codifica bytes en Base64 para almacenarlos en JSON."""
    if not isinstance(data, bytes):
        raise TypeError("b64 espera bytes")

    return base64.b64encode(data).decode("ascii")


def unb64(text: str) -> bytes:
    """Decodifica Base64 y rechaza representaciones no válidas."""
    try:
        if not isinstance(text, str):
            raise TypeError("Base64 debe ser texto")

        return base64.b64decode(
            text.encode("ascii"),
            validate=True
        )

    except (ValueError, UnicodeError, AttributeError, TypeError) as exc:
        raise CryptoError("Base64 inválido") from exc


def canonico(obj: Any) -> bytes:
    """Serialización JSON determinista para firmar o autenticar estructuras."""
    try:
        return json.dumps(
            obj,
            sort_keys=True,
            separators=(",", ":")
        ).encode("utf-8")

    except (TypeError, ValueError) as exc:
        raise CryptoError("objeto no serializable") from exc


# ---------------------------------------------------------------------------
# Scrypt: contraseñas y derivación de claves


def _scrypt(salt: bytes) -> Scrypt:
    if not isinstance(salt, bytes) or len(salt) < SALT_LEN:
        raise CryptoError(
            f"la salt debe tener al menos {SALT_LEN} bytes"
        )

    return Scrypt(
        salt=salt,
        length=KEY_LEN,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P
    )


def hash_password(password: str) -> dict[str, str]:
    """Devuelve salt + hash Scrypt; nunca almacena la contraseña original."""
    if not isinstance(password, str):
        raise CryptoError("contraseña inválida")

    salt = os.urandom(SALT_LEN)

    digest = _scrypt(salt).derive(
        password.encode("utf-8")
    )

    log.debug(
        "Scrypt n=%d r=%d p=%d salt=%d bits salida=%d bits",
        SCRYPT_N,
        SCRYPT_R,
        SCRYPT_P,
        SALT_LEN * 8,
        KEY_LEN * 8,
    )

    return {
        "salt": b64(salt),
        "hash": b64(digest)
    }


def verify_password(password: str, registro: dict[str, str]) -> bool:
    """Comprueba una contraseña mediante Scrypt."""
    try:
        if not isinstance(password, str) or not isinstance(registro, dict):
            return False

        _scrypt(unb64(registro["salt"])).verify(
            password.encode("utf-8"),
            unb64(registro["hash"])
        )

        return True

    except (InvalidKey, KeyError, TypeError, ValueError, CryptoError):
        return False


def derive_key(password: str, salt: bytes) -> bytes:
    """Deriva una clave de 256 bits mediante Scrypt."""
    if not isinstance(password, str):
        raise CryptoError("contraseña inválida para derivar la clave")

    return _scrypt(salt).derive(
        password.encode("utf-8")
    )


# ---------------------------------------------------------------------------
# AES-256-GCM: cifrado autenticado


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Cifra con AES-256-GCM y devuelve nonce || ciphertext || tag.

    El nonce se genera aleatoriamente en cada operación.
    No debe reutilizarse una pareja (clave, nonce) en GCM.
    """
    if not isinstance(key, bytes) or len(key) != KEY_LEN:
        raise CryptoError("AES-256-GCM requiere una clave de 32 bytes")

    if not isinstance(plaintext, bytes) or not isinstance(aad, bytes):
        raise CryptoError("plaintext y AAD deben ser bytes")

    nonce = os.urandom(NONCE_LEN)

    ciphertext_and_tag = AESGCM(key).encrypt(
        nonce,
        plaintext,
        aad
    )

    blob = nonce + ciphertext_and_tag

    log.debug(
        "AES-256-GCM cifrado: clave=%d bits nonce=%d bits tag=%d bits entrada=%d bytes",
        len(key) * 8,
        NONCE_LEN * 8,
        TAG_LEN * 8,
        len(plaintext),
    )

    return blob


def decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """Descifra y verifica el tag. Ante cualquier fallo no devuelve plaintext."""
    if not isinstance(key, bytes) or len(key) != KEY_LEN:
        raise CryptoError("clave AES-256 inválida")

    if not isinstance(blob, bytes) or len(blob) < NONCE_LEN + TAG_LEN:
        raise CryptoError("mensaje demasiado corto")

    if not isinstance(aad, bytes):
        raise CryptoError("AAD inválido")

    nonce = blob[:NONCE_LEN]
    ciphertext_and_tag = blob[NONCE_LEN:]

    try:
        plaintext = AESGCM(key).decrypt(
            nonce,
            ciphertext_and_tag,
            aad
        )

    except InvalidTag as exc:
        log.debug("AES-GCM rechazado: tag inválido o AAD incorrecto")

        raise CryptoError(
            "tag GCM inválido: datos alterados o clave incorrecta"
        ) from exc

    except (TypeError, ValueError) as exc:
        raise CryptoError("mensaje AES-GCM inválido") from exc

    log.debug(
        "AES-GCM descifrado correcto: %d bytes; tag verificado",
        len(plaintext)
    )

    return plaintext


# ---------------------------------------------------------------------------
# ECDSA P-256 + SHA-256: firma digital


def generate_signing_key() -> ec.EllipticCurvePrivateKey:
    """Genera una clave privada ECDSA sobre la curva NIST P-256."""
    log.debug("Generación de clave ECDSA P-256")

    return ec.generate_private_key(
        ec.SECP256R1()
    )


def private_to_bytes(key: ec.EllipticCurvePrivateKey) -> bytes:
    """Serializa una clave privada en DER/PKCS8.

    El resultado es material sensible en claro en memoria.
    El llamador debe cifrarlo antes de persistirlo.
    """
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise CryptoError(
            "se esperaba una clave privada de curva elíptica"
        )

    if key.curve.name != "secp256r1":
        raise CryptoError(
            "la clave de firma debe usar P-256"
        )

    return key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def private_from_bytes(data: bytes) -> ec.EllipticCurvePrivateKey:
    """Recupera una clave privada DER/PKCS8 previamente descifrada."""
    try:
        key = serialization.load_der_private_key(
            data,
            password=None
        )

    except (ValueError, TypeError) as exc:
        raise CryptoError("clave privada inválida") from exc

    if (
        not isinstance(key, ec.EllipticCurvePrivateKey)
        or key.curve.name != "secp256r1"
    ):
        raise CryptoError(
            "tipo o curva de clave privada inesperados"
        )

    return key


def public_bytes(key: ec.EllipticCurvePrivateKey) -> bytes:
    """Exporta la clave pública en DER/SubjectPublicKeyInfo."""
    if (
        not isinstance(key, ec.EllipticCurvePrivateKey)
        or key.curve.name != "secp256r1"
    ):
        raise CryptoError("clave privada ECDSA P-256 inválida")

    return key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def sign(key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """Firma datos con ECDSA P-256 y SHA-256."""
    if (
        not isinstance(key, ec.EllipticCurvePrivateKey)
        or key.curve.name != "secp256r1"
    ):
        raise CryptoError("clave de firma ECDSA P-256 inválida")

    if not isinstance(data, bytes):
        raise CryptoError("los datos a firmar deben ser bytes")

    log.debug("Firma ECDSA P-256 con SHA-256")

    return key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )


def verify_signature(
    public: bytes,
    data: bytes,
    signature: bytes
) -> bool:
    """Verifica una firma ECDSA P-256; devuelve False si no es válida."""
    try:
        pub = serialization.load_der_public_key(public)

        if (
            not isinstance(pub, ec.EllipticCurvePublicKey)
            or pub.curve.name != "secp256r1"
        ):
            return False

        pub.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256())
        )

        log.debug("Verificación de firma ECDSA: válida")

        return True

    except (InvalidSignature, ValueError, TypeError, AttributeError):
        log.debug("Verificación de firma ECDSA: INVÁLIDA")

        return False


# ---------------------------------------------------------------------------
# HMAC-SHA256: integridad y autenticidad de datos persistidos


def hmac_tag(key: bytes, data: bytes) -> bytes:
    """Genera una etiqueta HMAC-SHA256."""
    if not isinstance(key, bytes) or not key or not isinstance(data, bytes):
        raise CryptoError("parámetros HMAC inválidos")

    mac = hmac.HMAC(
        key,
        hashes.SHA256()
    )

    mac.update(data)

    return mac.finalize()


def hmac_ok(key: bytes, data: bytes, tag: bytes) -> bool:
    """Verifica HMAC usando la comparación segura de cryptography."""
    try:
        mac = hmac.HMAC(
            key,
            hashes.SHA256()
        )

        mac.update(data)
        mac.verify(tag)

        return True

    except (InvalidSignature, ValueError, TypeError, CryptoError):
        return False
