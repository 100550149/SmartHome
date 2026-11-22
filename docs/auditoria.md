# Auditoría de SmartHome

Práctica final de Criptografía y Seguridad Informática (UC3M). Estado del repositorio **antes** de los cambios de esta entrega, contrastado con el enunciado (funciones obligatorias, «Otras consideraciones», calidad del software, rúbrica de implementación y memoria, y reglas del entregable).

Se leyó el código completo (`crypto_utils.py`, `smarthome.py`, `main.py`, `README.md`), el enunciado y `memoria_parcial.docx`. Se ejecutó el código (registro, login, autorización, firma alterada, HMAC, replay, tag GCM, bloqueo y validación de entradas). No había batería de pruebas ni forma de instalar las dependencias desde el propio repositorio.

El enlace del repositorio de esta copia es `https://github.com/100550149/SmartHome`. La memoria parcial apunta a `https://github.com/100550203-byte/SmartHome.git`. En la memoria final se usa el primero.

## 1. Lo que ya es correcto

No hace falta reescribir la arquitectura ni los algoritmos. La separación entre criptografía (`crypto_utils.py`) y lógica de la casa (`smarthome.py` / `main.py`) es la adecuada, y las primitivas son actuales.

### Autenticación (código real)

- Contraseñas nunca en claro. `hash_password` / `verify_password`: Scrypt con N = 2^14, r = 8, p = 1, sal de 16 bytes (`os.urandom`) y salida de 32 bytes. La sal y el hash se guardan en Base64. Comprobado en ejecución: sal 16, hash 32.
- `verify_password` devuelve `False` ante clave incorrecta, registro mal formado o Base64 inválido. No autentica por un error de formato.
- Usuario ficticio `_dummy` (`Hub.__init__`): si la cuenta no existe se ejecuta igualmente Scrypt. El mensaje de fallo es siempre `credenciales inválidas`, tanto para usuario desconocido como para contraseña mala. Comprobado.
- Un acierto borra el contador de fallos. La contraseña de registro exige al menos 8 caracteres.
- El primer registro es `propietario`; los siguientes, `invitado`.

### Cifrado

- AES-256-GCM (`AESGCM`). Clave de 32 bytes. Nonce de 12 bytes (96 bits) con `os.urandom` en cada cifrado. Tag de 128 bits (lo añade la librería; el blob es `nonce || ciphertext || tag`).
- Se usa donde hay confidencialidad: la clave privada ECDSA del propietario en reposo, y las órdenes y respuestas del canal App–Hub.
- AAD del canal: sentido (`C` o `H`) + token de sesión + contador de 8 bytes. Un mensaje reutilizado con otro contador no verifica.
- Tag inválido: `decrypt` lanza `CryptoError` y no devuelve texto claro. `Hub.ejecutar` lo convierte en `orden rechazada`, no ejecuta el comando y no avanza `rx`. Comprobado con un tag volteado y con una clave distinta (ambos rechazados).

### Integridad

- El fichero (`salt`, `datos`, `mac`) autentica `datos` con HMAC-SHA256. La clave es Scrypt de la passphrase del hub y no se guarda: solo se guarda la sal. Permisos del fichero `0o600` (comprobado).
- Escritura por fichero temporal y `os.replace`.
- Si el HMAC no cuadra (passphrase mala o `datos` editados) no se cargan los datos. El mensaje no distingue los dos casos: `datos alterados o passphrase incorrecta (HMAC inválido)`. Comprobado en los dos.
- `hmac_ok` usa `HMAC.verify` (comparación en tiempo constante de la librería).
- La sal queda autenticada de forma implícita: cambiarla cambia la clave derivada y el HMAC no verifica.

### Firma

- ECDSA sobre la curva P-256 (`SECP256R1`) con SHA-256. La firma cubre el JSON canónico de la autorización (id, propietario, invitado, puerta, inicio, fin, emitida).
- La privada se serializa en PKCS#8 DER sin cifrado de la librería y se envuelve con AES-256-GCM. La clave de envoltura sale de Scrypt(contraseña del propietario, sal propia). El AAD es el nombre de usuario. En el fichero solo están la sal y el ciphertext (166 bytes para una P-256: 138 de PKCS#8 + 12 de nonce + 16 de tag). La cabecera PKCS#8 no aparece en claro.
- La pública (SPKI DER) vive en el registro del propietario, dentro del fichero con HMAC. Ese fichero es el ancla de confianza local: no hay PKI porque las identidades no salen de esta aplicación.
- Firma alterada: `verify_signature` devuelve falso, se registra `FIRMA_INVALIDA`, no se concede el acceso y no se sigue como si la firma fuera válida. Comprobado.
- Revocación y caducidad se consultan antes de abrir. Una autorización fuera de `[inicio, fin)` no abre. Comprobado.

### Claves, IVs y nonces

- Aleatoriedad: `os.urandom` (sales, nonces GCM) y `secrets` (token de sesión de 128 bits, id de autorización). No hay nonces constantes ni `random` de propósito general.
- Claves separadas por uso y por sal: hash de contraseña, clave HMAC del hub, clave de sesión (sal nueva en cada login; no se persiste) y clave de envoltura de la privada. La clave de sesión no viaja: App y Hub la derivan de la contraseña y de la sal.
- El contador monótono del canal corta la repetición de órdenes. El contador solo avanza si el tag GCM verifica. Comprobado: un segundo envío del mismo blob lanza `orden rechazada`.
- Nonce GCM aleatorio de 96 bits. Para el volumen de esta aplicación (una clave de sesión por login, unos pocos mensajes) la probabilidad de repetición queda muy por debajo del límite 2^-32 de NIST SP 800-38D. No es un fallo. No se cambia el esquema.
- Los logs de AES-GCM y de ECDSA indican algoritmo y longitud (256 bits) y no imprimen clave, contraseña, nonce ni texto claro. Comprobado en la salida de depuración.

### Lógica de aplicación que encaja con el enunciado

- Puertas `principal`, `garaje`, `trasera`. Alarma. Autorización de como máximo 24 h. Eventos en memoria (el comando `eventos` devuelve los 10 últimos).
- Un invitado no puede autorizar, revocar, ver eventos ni cambiar la alarma.
- Con la alarma activa, el invitado no abre aunque la autorización sea válida; el propietario sí.
- Cerrar una puerta no exige autorización. Lo puede hacer cualquier sesión autenticada. No concede acceso: deja la puerta cerrada. La memoria parcial no lo decía; el código sí lo hace. Se documenta, no se cambia.
- El reloj es inyectable (`reloj=`), útil para probar caducidad y bloqueo sin esperas reales.

## 2. Lo que falta o está mal

| Requisito | Estado |
| --- | --- |
| Registro y autenticación con contraseñas almacenadas de forma adecuada | Hecho en código. La memoria parcial describe un bloqueo que el código no tiene (apartado 3). |
| Cifrado autenticado, comprobable, sin filtrar secretos | Hecho. Falta poder enseñarlo con `python main.py demo`: esa función está dentro de un literal que Python descarta, y `__main__` solo llama a `menu()`. |
| MAC o AEAD, y rechazo explícito si falla | Hecho en AES-GCM y en HMAC. HMAC no escribe en el log el algoritmo ni la longitud de la clave (el enunciado lo recomienda). `derive_key` tampoco. |
| Firma, verificación y rechazo de firmas inválidas; privada protegida | Hecho. No hay una prueba automatizada que lo deje fijado. |
| Claves / IV / nonces con CSPRNG, longitud adecuada, sin reutilización peligrosa | Hecho. Sin pruebas que lo demuestren. |
| Errores de verificación que no continúan el procesamiento | Hecho en los caminos normales. Un usuario que no es `str` rompe el menú con `TypeError` (abajo). |
| Pruebas negativas (tag, MAC, firma, clave o contraseña, repetición) | No existe ningún test. No hay `pytest` ni `tests/`. |
| Dependencias criptográficas con versión reproducible | No hay `requirements.txt`. El sistema tenía `cryptography` 41.0.7 sin fijar. |
| Instalación y ejecución desde un entorno limpio | El `README.md` son cuatro líneas, con erratas, y no dice cómo crear el venv, instalar ni probar. |
| Sin secretos versionados; ignorar datos generados | Ahora mismo no hay claves en el repositorio. No hay `.gitignore`: el primer `datos_hub.json` (hashes, privada cifrada) se puede colar en un commit. |
| Memoria: las siete preguntas, capturas, ≤ 13 páginas, Arial/Calibri/Times 11, interlineado simple | Solo hay borrador de las dos primeras. El interlineado del borrador es 1,15 (`line` 276), no simple. Faltan capturas porque no había salidas que capturar. |
| Calidad: validación de entradas y excepciones | Hueco real en el nombre de usuario. |

### Validación de entradas (fallo reproducido)

`Hub.registrar` no comprueba el tipo ni el contenido del usuario.

- `registrar("", "12345678")` se acepta y esa cuenta queda como **propietario**.
- `registrar("   ", ...)` también se acepta.
- `registrar(None, ...)` y `registrar(12, ...)` insertan la clave en el diccionario y después `canonico` → `json.dumps(..., sort_keys=True)` lanza `TypeError: '<' not supported between instances of 'NoneType' and 'str'`. El menú solo captura `HubError` y `ValueError`, así que el proceso se cae. El usuario a medias se queda en memoria.

Eso es validación y tratamiento de excepciones, no un cambio de diseño.

### Modo demo anunciado y muerto

La cabecera de `main.py` dice `python main.py demo`. El texto de la función está en un literal suelto (líneas 80-98) que no se ejecuta. `if __name__` siempre entra al menú, que pide passphrase por `getpass` y no sirve para una captura reproducible.

### Bloqueo de cuentas: el código y la memoria no dicen lo mismo

Código (`MAX_FALLOS = 5`, `BLOQUEO_SEG = 60`, `login`):

- No hay ventana móvil.
- No hay duraciones 30 / 60 / 120 / 240 / 300.
- Al quinto fallo seguido se arma un bloqueo de 60 segundos. Ese quinto intento responde todavía `credenciales inválidas`. Los siguientes, hasta que pasa el minuto, responden `demasiados intentos, inténtalo más tarde` aunque la contraseña sea buena.
- Pasado el minuto, la contraseña correcta entra. Otro fallo vuelve a bloquear 60 segundos, porque el contador no se pone a cero solo por esperar.
- Un acierto sí pone el contador a cero.
- El estado vive en `self._fallos` y se pierde al cerrar el proceso.

La memoria parcial afirma la ventana de 60 segundos y el backoff progresivo. Esa frase no se puede dejar: el enunciado pide que la memoria describa lo implementado. El bloqueo de 60 segundos ya es una defensa correcta frente a prueba online. No se reescribe `login` para que coincida con un texto que el código no cumple; se corrige el párrafo.

### Parámetros Scrypt frente a OWASP (decisión: no tocarlos)

N = 2^14, r = 8, p = 1 coinciden con la práctica 1 y con el ejemplo de la librería `cryptography`. La [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) de OWASP, consultada para esta auditoría, pide como mínimo, si no se usa Argon2id, una de estas configuraciones Scrypt: N = 2^17 con p = 1, o N = 2^14 con p = 5 (también lista puntos intermedios). Con p = 1 y N = 2^14 se está por debajo de ese mínimo.

Se mantienen los parámetros de la asignatura. Son un coste real (memoria y CPU) y no son un algoritmo roto. La memoria debe decir el límite en una frase, sin presentarlos como si fueran la recomendación actual de OWASP. Subir p o N cambiaría la tabla que el grupo ya escribió y el comportamiento que va a defender en la oral, para una mejora que el enunciado no exige.

### Nonce aleatorio (decisión: no cambiar el formato)

AES-GCM se rompe si se repite el par (clave, nonce). Aquí el nonce es de 96 bits y aleatorio, la clave de sesión cambia en cada login y la clave de envoltura cifra una sola vez. Cumple la condición de unicidad práctica del modo. Pasar a un nonce-contador sería otro diseño, no una corrección. Las pruebas comprobarán que dos cifrados no repiten nonce y que la sal de sesión cambia en cada login.

### Qué no es un fallo

- No cifrar el JSON entero. Los hashes no son reversibles, la pública no es secreta y la privada ya va en AES-GCM. El HMAC cubre la integridad. Encaja con el borrador.
- No hay cifrado asimétrico. La parte asimétrica es la firma. Es una decisión válida: hay que explicarla, no añadir RSA o ECIES.
- App y Hub están en el mismo proceso. El canal AEAD modela el mensaje que en un despliegue iría por la red. Quien pueda mutar la memoria del proceso se salta las comprobaciones, como en cualquier programa local. La frontera que la práctica protege es el fichero y el formato de las órdenes.
- Cerrar sin autorización, como se indicó arriba.
- La passphrase vía `SMARTHOME_PASSPHRASE` es una ayuda de demostración. Puede verse en el entorno del proceso. Se avisa en el README; no se quita, porque el menú sigue pudiendo pedirla por `getpass`.

## 3. Rúbrica de implementación y memoria, sobre el estado auditado

| Criterio | Máx. | Lectura del estado previo |
| --- | --- | --- |
| Autenticación de usuarios | 1,5 | Mecanismo sólido (Scrypt, sal, dummy, mensaje genérico, bloqueo simple). Sin pruebas. La memoria miente en el backoff. |
| Cifrado: algoritmos, modos, parámetros | 1,5 | AES-256-GCM bien elegido y bien usado. Poco demostrable: el demo no arranca y no hay tests. |
| Integridad / autenticación de mensajes | 1,0 | HMAC-SHA256 y tag GCM correctos y con rechazo. El log de HMAC no cita algoritmo ni longitud. |
| Firma: generación, verificación, errores | 1,5 | ECDSA P-256 + SHA-256, privada cifrada, rechazo comprobado a mano. Sin prueba automática ni captura. |
| Claves / IVs / nonces | 2,0 | Generación y separación correctas. Falta fijarlo con tests y citarlo en la memoria. |
| Calidad del software | 2,5 | Estructura legible y cripto separada de la lógica. Fallan validación, tests, dependencias fijadas, README y `.gitignore`. |
| Memoria (dentro de esos 10) | — | Dos preguntas de siete, sin capturas, interlineado 1,15, URL de otro repositorio. El límite de 13 páginas todavía no aplica: el texto es corto. |

La defensa (20 puntos) no se puntúa aquí. Sin una guía, el riesgo está en explicar de memoria parámetros que no son los del código (bloqueo progresivo, demo, URL).

## 4. Conjunto mínimo de cambios

Se deja como está: Scrypt (N, r, p, sal, longitud), AES-256-GCM (formato nonce || ciphertext || tag, AAD, tag de 128 bits), HMAC-SHA256 del JSON canónico, ECDSA P-256 / SHA-256, envoltura de la privada, usuario dummy, permisos `0o600`, contador anti-replay, papeles propietario/invitado, puertas, alarma y el hecho de que cerrar no exige autorización.

Cambios que sí hacen falta:

1. Validar usuario y contraseña antes de tocar el diccionario, y devolver `HubError` (no `TypeError`).
2. Log de depuración en `derive_key`, `hmac_tag` y `hmac_ok`: algoritmo y bits de clave, nunca el secreto. Rechazar en `encrypt` / `decrypt` una clave que no sea de 32 bytes con `CryptoError`, para no degradar a AES-128 ni dejar escapar un `ValueError`.
3. Restaurar `demo()` y el argumento `python main.py demo`, con el flujo que ya estaba escrito (registro, autorización, puerta permitida, puerta denegada) y tres rechazos que el enunciado pide enseñar: firma alterada, tag GCM, HMAC del fichero. Sin pedir datos y sin dejar `datos_hub.json` en el directorio de trabajo.
4. `requirements.txt` con versión fijada. `cryptography` 50.0.2 (la actual en el índice; la 41.0.7 del sistema es de 2023 y no está declarada). `pytest` 9.2.0 para la batería.
5. README con venv limpio, instalación, ejecución y pruebas. `.gitignore` para `datos_hub.json`, `*.tmp`, entornos y cachés.
6. Pruebas positivas y negativas de lo que el enunciado lista: tag y ciphertext alterados, AAD distinto, clave o contraseña incorrectas, HMAC inválido, firma alterada, repetición, autorización caducada y revocada, bloqueo, entrada mal formada. También que el fichero no contiene la contraseña ni la privada en claro, y que los logs no contienen la contraseña ni la clave.
7. Memoria en `docs/memoria.docx`: conservar datos del grupo y el texto cierto de las dos primeras respuestas; corregir solo el párrafo del bloqueo, la URL y el interlineado; responder el resto con los parámetros reales; capturas hechas a partir de la salida real del demo y de pytest. Portada aparte. Anexo con la tabla de la rúbrica, fuera de las 13 páginas. Arial 11, interlineado simple.
8. `docs/guia_defensa.md` para la oral: cada decisión, los límites (OWASP, mismo proceso, bloqueo en memoria) y las preguntas previsibles.

El identificador de grupo de prácticas se deja en blanco, como en el borrador.

## 5. Cambios aplicados

Hecho después de cerrar esta auditoría. No se ha tocado el diseño que el apartado 1 da por bueno.

- `smarthome.py`: `_validar_usuario` y `_validar_password` antes de modificar el diccionario. Un nombre vacío, con espacios o que no es texto devuelve `HubError`. El login de una contraseña que el registro nunca aceptaría responde «credenciales inválidas» sin decir si la cuenta existe.
- `crypto_utils.py`: log de depuración en `derive_key`, `hmac_tag` y `hmac_ok` (algoritmo y bits, nunca el secreto). `_aes256` rechaza una clave que no sea de 32 bytes.
- `main.py`: `python main.py demo` vuelve a existir. Recorre el caso normal y tres rechazos (firma volteada, tag GCM, HMAC tras cambiar el rol del invitado). Usa un directorio temporal.
- `tests/`: 15 pruebas. `pytest -v` termina en `15 passed` (3,61 s con Python 3.12.3 y `cryptography` 50.0.2).
- `requirements.txt`: `cryptography==50.0.2` y `pytest==9.2.0`.
- `README.md`: venv limpio, ejecución y pruebas. `.gitignore`: `datos_hub.json`, `*.tmp`, entornos y cachés.
- `docs/memoria.docx`: texto previo de propósito y de autenticación, con el párrafo del bloqueo corregido para que diga lo que hace `login` (5 fallos, 60 segundos, sin ventana ni backoff). URL `https://github.com/100550149/SmartHome`. Arial 11, interlineado simple. Portada en la página 1. Respuestas en las páginas 2 a 7 (6 páginas, por debajo de 13). Anexo con la rúbrica en la página 8. Las figuras salen de `docs/evidencias/demo.txt` y `docs/evidencias/pytest.txt`, sin reescribir líneas.
- `docs/guia_defensa.md`: decisiones, límites (OWASP, bloqueo en memoria, mismo proceso) y preguntas de la oral.

Comprobado en un venv nuevo: `pip install -r requirements.txt`, `python main.py demo` y `pytest -v`.

## 6. Segunda revisión

Relectura línea a línea de `crypto_utils.py`, `smarthome.py` y `main.py`, como examinador. Solo se ha cambiado lo que era un fallo real. Lo que ya estaba bien (AES-256-GCM, nonce aleatorio de 12 bytes, AAD con sentido + token + contador, Scrypt, ECDSA P-256, usuario ficticio, cierre de puerta sin autorización) no se ha rediseñado.

| Problema | Gravedad | Corrección | Prueba |
| --- | --- | --- | --- |
| Un JSON antiguo sigue siendo auténtico: reponerlo deshace una revocación. | Alta | Contador de generación dentro del HMAC y fichero `.gen` aparte. Si el JSON es más viejo, no se carga. | `test_copia_antigua_no_deshace_la_revocacion` |
| Un registro de autorización mal formado lanzaba `KeyError` y abortaba la búsqueda. | Media | Se salta ese registro y se sigue con los demás. | `test_registro_mal_formado_no_bloquea_otra_autorizacion` |
| `ejecutar` con un mensaje que no es `bytes`, o demasiado corto, salía por `TypeError`. | Media | Se rechaza la orden y no se ejecuta nada. | `test_aad_ata_contador_token_y_sentido` |
| En Windows `0o600` no quita permisos a otros usuarios. | Media | `icacls` deja el fichero solo al usuario actual. El test de permisos no asume POSIX. | `test_restringir_y_bloqueo_en_windows`, `test_rutas_con_espacios_y_permisos` |
| Un corte a mitad de `json.dump` podía dejar el destino a medias, y dos procesos podían pisarse. | Media | Temporal, `fsync`, `os.replace`, y un candado (`flock` o `msvcrt`). | `test_guardados_concurrentes`, `test_fallo_de_escritura_no_deja_el_usuario_a_medias` |
| Si fallaba el guardado, el usuario ya estaba en memoria. | Baja | Se deshace el alta y, si el JSON no llegó a sustituirse, también la generación. | `test_fallo_de_escritura_no_deja_el_usuario_a_medias` |
| «José» y la misma letra en forma descompuesta eran dos cuentas y dos bloqueos. | Baja | El nombre se normaliza a NFC. Las mayúsculas siguen siendo otra cuenta: no es un bypass. | `test_nfc_une_la_cuenta_y_el_bloqueo`, `test_las_mayusculas_son_otra_cuenta` |
| `canonico` aceptaba NaN y no fijaba la codificación. | Baja | `allow_nan=False`, `ensure_ascii=True`, UTF-8. La sal entra también en el HMAC. | `test_canonico_es_estable_y_rechaza_nan` |
| Al cargar una clave no se exigía la curva P-256. | Baja | Privada y pública que no sean P-256 se rechazan. | `test_cada_byte_de_la_firma_y_curva_distinta` |
| El menú no recortaba entradas y una opción rara no decía nada. La hora `99:99` petaba con un error de `datetime`. | Baja | Se recorta, se avisa, y la hora se valida antes. | `test_menu_rechaza_opcion_y_recorre_el_flujo`, `test_hora_invalida` |
| Tras descifrar la privada, los bytes quedaban en un `bytes` sin borrarse. | Baja | Se copian a un `bytearray` y se ponen a cero. Python puede conservar otra copia; no se promete más. | Inspección de `Hub.login` (no hay aserción de la memoria del intérprete) |
| Un fichero truncado, vacío o que es un directorio, o sin el `.gen`, salía por una traza. | Baja | `HubError` genérico, sin seguir. | `test_fichero_truncado_vacio_o_sin_directorio`, `test_directorio_o_generacion_ausente` |
| `hmac_ok` y `decrypt` dejaban escapar `TypeError` si el tipo no era `bytes`. | Baja | Devuelven fallo o `CryptoError`, y no hay texto claro. | `test_tipos_invalidos_en_cifrado_y_hmac` |

Revisado y no cambiado, porque no era un fallo:

- El nonce aleatorio de 96 bits con clave de sesión nueva en cada login. El volumen no se acerca al límite de NIST SP 800-38D.
- El AAD ya ata sentido, token y contador. La orden va dentro del texto autenticado, no hace falta repetirla en el AAD. La prueba `test_aad_ata_contador_token_y_sentido` lo comprueba.
- El contador de órdenes vive en la sesión. Al cerrar el proceso muere la clave de sesión, así que reponer el fichero no reinyecta órdenes viejas. El rollback que sí importaba era el de las revocaciones.
- «Ana» y «ana» son cuentas distintas. Bloquear una no abre la otra. Los espacios alrededor ya se rechazaban.
- Cerrar una puerta sin autorización sigue siendo a propósito.
