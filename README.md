# SmartHome

Simulación del control de acceso de una vivienda, para la práctica final de Criptografía y Seguridad Informática (UC3M).

El primer usuario registrado es el propietario. Los siguientes son invitados. El propietario abre y cierra puertas, activa la alarma y firma autorizaciones temporales. Un invitado solo abre una puerta con una autorización vigente, no revocada y con firma válida. Cerrar una puerta no concede acceso: puede hacerlo cualquier sesión autenticada.

Las contraseñas se guardan con Scrypt. Las órdenes y la clave privada de firma van con AES-256-GCM. El fichero de datos lleva HMAC-SHA256. Las autorizaciones se firman con ECDSA P-256 y SHA-256.

## Requisitos

Python 3.12. Las versiones de las librerías están fijadas en `requirements.txt`.

## Instalación en un entorno limpio

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Ejecución

```bash
python main.py          # menú interactivo
python main.py demo     # escenario automático, con rechazos de firma, tag y HMAC
```

El menú pide la passphrase del hub. Si todavía no existe el fichero, tiene que tener al menos 8 caracteres: con ella se deriva la clave HMAC y se crea el almacén. Por defecto el fichero es `datos_hub.json` en el directorio actual.

Variables opcionales:

- `SMARTHOME_FILE`: ruta del fichero de datos.
- `SMARTHOME_PASSPHRASE`: evita el prompt. Vale para una demostración local. En un equipo compartido la passphrase puede quedar visible en el entorno del proceso; el menú, sin esta variable, la pide con `getpass` y no la muestra.

`python main.py demo` usa un directorio temporal. No crea `datos_hub.json` en el directorio del proyecto.

## Pruebas

```bash
pytest -v
pytest -q --cov=crypto_utils --cov=smarthome --cov-report=term
```

La batería cubre el funcionamiento normal y los rechazos: tag o ciphertext alterados, HMAC inválido, firma alterada, contraseña incorrecta, repetición de una orden, autorización caducada o revocada, bloqueo de cuenta y entradas mal formadas.

## Ficheros

| Fichero | Papel |
| --- | --- |
| `crypto_utils.py` | Scrypt, AES-256-GCM, HMAC-SHA256, ECDSA P-256 |
| `smarthome.py` | Hub y App: usuarios, permisos, puertas, alarma, autorizaciones |
| `main.py` | Menú y demostración |
| `tests/` | Pruebas positivas y negativas |
| `docs/memoria.docx` | Memoria de la práctica |
| `docs/guia_defensa.md` | Decisiones y preguntas de la defensa oral |
| `docs/auditoria.md` | Comparación del código inicial con el enunciado |

`datos_hub.json`, el contador `datos_hub.json.gen`, el candado `*.lock` y los temporales `*.tmp` están en `.gitignore`. Contienen sales, hashes y la clave privada cifrada. No deben versionarse.

En Windows el modo `0600` no restringe la ACL. Al guardar, la aplicación llama a `icacls` para dejar cada fichero solo con el usuario actual. En Linux y macOS basta `chmod`. Las rutas van con `pathlib`, también si llevan espacios.
