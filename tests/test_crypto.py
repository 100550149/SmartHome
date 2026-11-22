"""Pruebas de las primitivas: funcionamiento y rechazo ante datos manipulados."""
import logging
import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import crypto_utils as cu

PASSWORD = "Propietario#2026ok"


def test_scrypt_parametros_sal_y_verificacion():
    assert (cu.SCRYPT_N, cu.SCRYPT_R, cu.SCRYPT_P, cu.SALT_LEN, cu.KEY_LEN) == (2**14, 8, 1, 16, 32)
    registro = cu.hash_password(PASSWORD)
    assert len(cu.unb64(registro["salt"])) == 16
    assert len(cu.unb64(registro["hash"])) == 32
    assert cu.verify_password(PASSWORD, registro)
    assert cu.verify_password(PASSWORD + "x", registro) is False
    otra = cu.hash_password(PASSWORD)
    assert registro["salt"] != otra["salt"]
    assert registro["hash"] != otra["hash"]
    assert cu.verify_password(PASSWORD, {"salt": "@@@", "hash": "@@@"}) is False
    with pytest.raises(cu.CryptoError):
        cu.unb64("no es base64 !!!")
    with pytest.raises(cu.CryptoError):
        cu.derive_key(PASSWORD, b"sal-corta")


def test_aes_256_gcm_y_rechazo_de_tag():
    clave = os.urandom(32)
    claro = b"orden-abrir-principal"
    aad = b"C-token-contador"
    blob = cu.encrypt(clave, claro, aad)
    assert len(blob) == 12 + len(claro) + 16
    assert cu.decrypt(clave, blob, aad) == claro
    nonces = {cu.encrypt(clave, claro, aad)[:12] for _ in range(24)}
    assert len(nonces) == 24

    tag_malo = blob[:-1] + bytes([blob[-1] ^ 0x01])
    cifra_mala = blob[:12] + bytes([blob[12] ^ 0x01]) + blob[13:]
    with pytest.raises(cu.CryptoError, match="tag GCM"):
        cu.decrypt(clave, tag_malo, aad)
    with pytest.raises(cu.CryptoError, match="tag GCM"):
        cu.decrypt(clave, cifra_mala, aad)
    with pytest.raises(cu.CryptoError, match="tag GCM"):
        cu.decrypt(clave, blob, b"otro-aad")
    with pytest.raises(cu.CryptoError, match="tag GCM"):
        cu.decrypt(os.urandom(32), blob, aad)
    with pytest.raises(cu.CryptoError, match="demasiado corto"):
        cu.decrypt(clave, blob[:20], aad)
    with pytest.raises(cu.CryptoError, match="AES-256"):
        cu.encrypt(b"\x00" * 16, claro, aad)
    with pytest.raises(cu.CryptoError, match="AES-256"):
        cu.decrypt(b"\x00" * 16, blob, aad)


def test_hmac_sha256_acepta_y_rechaza():
    clave = os.urandom(32)
    etiqueta = cu.hmac_tag(clave, b"datos-del-hub")
    assert len(etiqueta) == 32
    assert cu.hmac_ok(clave, b"datos-del-hub", etiqueta)
    assert cu.hmac_ok(clave, b"datos-del-HUB", etiqueta) is False
    assert cu.hmac_ok(os.urandom(32), b"datos-del-hub", etiqueta) is False
    alterada = bytearray(etiqueta)
    alterada[0] ^= 0x01
    assert cu.hmac_ok(clave, b"datos-del-hub", bytes(alterada)) is False


def test_ecdsa_p256_y_clave_privada_cifrada():
    privada = cu.generate_signing_key()
    assert privada.curve.name == "secp256r1"
    assert privada.key_size == 256
    publica = cu.public_bytes(privada)
    datos = b'{"puerta":"principal"}'
    firma = cu.sign(privada, datos)
    assert cu.verify_signature(publica, datos, firma)
    firma_mala = bytearray(firma)
    firma_mala[0] ^= 0x01
    assert cu.verify_signature(publica, datos, bytes(firma_mala)) is False
    assert cu.verify_signature(publica, datos + b" ", firma) is False
    otra = cu.generate_signing_key()
    assert cu.verify_signature(cu.public_bytes(otra), datos, firma) is False
    assert cu.verify_signature(b"clave-publica-basura", datos, firma) is False

    sal = os.urandom(16)
    clave = cu.derive_key(PASSWORD, sal)
    blob = cu.encrypt(clave, cu.private_to_bytes(privada), b"propietario")
    recuperada = cu.private_from_bytes(cu.decrypt(clave, blob, b"propietario"))
    assert cu.verify_signature(cu.public_bytes(recuperada), datos, cu.sign(recuperada, datos))
    with pytest.raises(cu.CryptoError, match="tag GCM"):
        cu.decrypt(cu.derive_key("otra-clave-distinta", sal), blob, b"propietario")
    with pytest.raises(cu.CryptoError, match="tag GCM"):
        cu.decrypt(clave, blob, b"otro-usuario")
    assert cu.private_to_bytes(privada) not in blob


def test_logs_indican_algoritmo_y_no_el_secreto(caplog):
    caplog.set_level(logging.DEBUG, logger="crypto")
    sal = os.urandom(16)
    clave = cu.derive_key(PASSWORD, sal)
    blob = cu.encrypt(clave, b"texto-claro-SECRETO", b"aad")
    cu.decrypt(clave, blob, b"aad")
    malo = blob[:-1] + bytes([blob[-1] ^ 0x01])
    with pytest.raises(cu.CryptoError):
        cu.decrypt(clave, malo, b"aad")
    privada = cu.generate_signing_key()
    firma = cu.sign(privada, b"datos")
    assert cu.verify_signature(cu.public_bytes(privada), b"datos", firma)
    etiqueta = cu.hmac_tag(clave, b"datos")
    assert cu.hmac_ok(clave, b"datos", etiqueta)
    assert cu.hmac_ok(clave, b"datos-cambiados", etiqueta) is False

    texto = caplog.text
    assert "Derivación scrypt: clave de 256 bits" in texto
    assert "AES-GCM 256 bits" in texto
    assert "AES-GCM descifrado FALLIDO" in texto
    assert "HMAC-SHA256: verificación correcta, clave de 256 bits" in texto
    assert "HMAC-SHA256: verificación FALLIDA, clave de 256 bits" in texto
    assert "ECDSA P-256" in texto
    assert "Verificación de firma: válida" in texto
    assert PASSWORD not in texto
    assert clave.hex() not in texto
    assert sal.hex() not in texto
    assert "texto-claro-SECRETO" not in texto


def test_canonico_es_estable_y_rechaza_nan():
    assert cu.canonico({"b": 1, "a": {"d": 2, "c": 3}}) == cu.canonico({"a": {"c": 3, "d": 2}, "b": 1})
    assert cu.canonico({"nombre": "José"}) == b'{"nombre":"Jos\\u00e9"}'
    with pytest.raises(cu.CryptoError):
        cu.canonico({"x": float("nan")})
    with pytest.raises(cu.CryptoError):
        cu.canonico({"x": {1, 2}})


_CLAVE_FIJA = bytes(range(32))
_BLOB_FIJO = cu.encrypt(_CLAVE_FIJA, b"abcd", b"aad-fijo")
_TAG_FIJO = cu.hmac_tag(_CLAVE_FIJA, b"datos-fijos")


@pytest.mark.parametrize("posicion", range(len(_BLOB_FIJO)))
def test_voltear_cualquier_byte_del_mensaje_gcm(posicion):
    malo = bytearray(_BLOB_FIJO)
    malo[posicion] ^= 0x01
    with pytest.raises(cu.CryptoError):
        cu.decrypt(_CLAVE_FIJA, bytes(malo), b"aad-fijo")


@pytest.mark.parametrize("longitud", range(0, 12 + 16))
def test_mensaje_gcm_truncado(longitud):
    with pytest.raises(cu.CryptoError):
        cu.decrypt(_CLAVE_FIJA, _BLOB_FIJO[:longitud], b"aad-fijo")


@pytest.mark.parametrize("posicion", range(len(_TAG_FIJO)))
def test_voltear_cualquier_byte_del_hmac(posicion):
    malo = bytearray(_TAG_FIJO)
    malo[posicion] ^= 0x01
    assert cu.hmac_ok(_CLAVE_FIJA, b"datos-fijos", bytes(malo)) is False


@pytest.mark.parametrize("valor", [None, "texto", 1, 1.5, [], {}])
def test_tipos_invalidos_en_cifrado_y_hmac(valor):
    with pytest.raises(cu.CryptoError):
        cu.encrypt(_CLAVE_FIJA, valor, b"aad")
    with pytest.raises(cu.CryptoError):
        cu.encrypt(_CLAVE_FIJA, b"claro", valor)
    with pytest.raises(cu.CryptoError):
        cu.decrypt(_CLAVE_FIJA, valor, b"aad")
    assert cu.hmac_ok(valor, b"datos", _TAG_FIJO) is False
    assert cu.hmac_ok(_CLAVE_FIJA, b"datos", valor) is False
    assert cu.verify_password(valor, {"salt": "AAAA", "hash": "AAAA"}) is False


def test_cada_byte_de_la_firma_y_curva_distinta():
    privada = cu.generate_signing_key()
    publica = cu.public_bytes(privada)
    datos = b"autorizacion-fija"
    firma = cu.sign(privada, datos)
    assert firma
    for posicion in range(len(firma)):
        mala = bytearray(firma)
        mala[posicion] ^= 0x01
        assert cu.verify_signature(publica, datos, bytes(mala)) is False
    assert cu.verify_signature(publica, datos, b"") is False
    assert cu.verify_signature(publica, datos, None) is False
    otra = ec.generate_private_key(ec.SECP384R1())
    cruda = otra.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    with pytest.raises(cu.CryptoError, match="P-256"):
        cu.private_from_bytes(cruda)
    publica_384 = otra.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert cu.verify_signature(publica_384, datos, firma) is False


def test_clave_privada_ilegible():
    with pytest.raises(cu.CryptoError, match="inválida"):
        cu.private_from_bytes(b"esto-no-es-una-clave")


def test_contrasena_no_codificable():
    with pytest.raises(cu.CryptoError):
        cu.hash_password("\ud800")
    with pytest.raises(cu.CryptoError):
        cu.derive_key(1234, os.urandom(16))
