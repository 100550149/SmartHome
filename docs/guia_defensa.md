# Guía para la defensa

La defensa vale 20 de 30 puntos: demostración (7), justificación de las decisiones (7) y preguntas, incluidos errores y ataques (6). Esta guía sigue el código que hay en el repositorio, no el borrador de la memoria. Si una frase de aquí y una del código no coinciden, manda el código.

Repositorio que hay que enseñar: https://github.com/100550149/SmartHome

El identificador de grupo de prácticas se dejó en blanco a propósito. El grupo es el 81.

## Cómo abrir

En un minuto, sin leer transparencias:

SmartHome simula el acceso a una casa. El primer usuario es el propietario y el resto son invitados. Un invitado solo abre una puerta si el propietario ha firmado una autorización vigente y no revocada. Hay cuatro piezas criptográficas, cada una con un trabajo distinto: Scrypt para las contraseñas y para derivar claves, AES-256-GCM para lo que es secreto, HMAC-SHA256 para que el fichero no se pueda retocar, y ECDSA P-256 para las autorizaciones.

App y Hub están en el mismo proceso. El cifrado modela el mensaje que iría por la red. Quien pueda escribir en la memoria del proceso se salta las comprobaciones, como en cualquier programa local. Lo que sí está protegido es el fichero en disco y el formato de las órdenes.

## Dónde señalar en el código

| Si preguntan por… | Abrir |
| --- | --- |
| Parámetros Scrypt | `crypto_utils.py`, constantes `SCRYPT_N`, `SCRYPT_R`, `SCRYPT_P`, `SALT_LEN`, `KEY_LEN` |
| Hash y verificación | `hash_password`, `verify_password` |
| Derivación de claves | `derive_key` |
| AES-GCM | `encrypt`, `decrypt`, `_aes256` |
| HMAC | `hmac_tag`, `hmac_ok`; en el Hub, `_guardar` y `_cargar` |
| Firma | `generate_signing_key`, `sign`, `verify_signature`; en el Hub, `_autorizar` y `_autorizacion_valida` |
| Login, dummy y bloqueo | `Hub.__init__` (`self._dummy`), `Hub.login` |
| Canal cifrado y anti-replay | `App.enviar`, `Hub.ejecutar` |
| Permisos de fichero | `Hub._guardar`, `os.open(..., 0o600)` |
| Validación | `_validar_usuario`, `_validar_password` |
| Demo | `main.demo` |

## Chuleta de parámetros

Hay que poder decirlos sin mirar, y que coincidan con el fichero.

- Scrypt: N = 2^14, r = 8, p = 1, sal de 16 bytes, salida de 32 bytes. Sal con `os.urandom`. La contraseña no se guarda.
- Bloqueo: 5 fallos (`MAX_FALLOS`), 60 segundos (`BLOQUEO_SEG`). En memoria. No es progresivo y no hay ventana móvil.
- Contraseña: mínimo 8, máximo 128. Usuario: texto, 1 a 64 caracteres, sin espacios alrededor ni caracteres de control.
- AES-256-GCM: clave de 32 bytes, nonce de 12 bytes aleatorio por mensaje, tag de 16 bytes. Mensaje = nonce || texto cifrado || tag.
- AAD del canal: `C` o `H`, más el token de sesión, más el contador de 8 bytes en big-endian.
- AAD de la clave privada: el nombre de usuario en UTF-8.
- HMAC-SHA256: clave de 32 bytes derivada de la passphrase del hub. Se autentica el JSON canónico de `datos`, no los bytes crudos del fichero.
- ECDSA: curva P-256 (`secp256r1`), hash SHA-256, clave de 256 bits. Privada en PKCS#8 DER y luego dentro de AES-256-GCM. Pública en SPKI DER.
- Token de sesión: `secrets.token_hex(16)`, 128 bits. Identificador de autorización: otros 128 bits.
- Fichero: modo `0600`.
- Librerías: `cryptography` 50.0.2 y `pytest` 9.2.0. Python de la prueba: 3.12.3.

## Decisiones, y qué se descartó

### Contraseñas con Scrypt, no con SHA-256 ni con cifrado

SHA-256 es rápida. Con una GPU se prueban contraseñas a un ritmo que Scrypt no permite, porque Scrypt pide memoria además de CPU. Cifrar la contraseña sería reversible: quien tenga la clave lee todas. Un hash con sal no se invierte. La sal impide tablas precalculadas y hace que dos usuarios con la misma contraseña no dejen el mismo registro.

No usamos Argon2id, que es la primera recomendación actual de OWASP, ni subimos el coste de Scrypt. Los parámetros son los de la práctica 1 y los del ejemplo de la librería. Con N = 2^14 y r = 8, OWASP pide p = 5 para un coste equivalente, o N = 2^17 con p = 1. Nosotros tenemos p = 1. Hay que decirlo antes de que lo pregunten: es una decisión de la práctica, no la configuración de un servicio real. En producción se subiría N o p.

Bcrypt se descartó porque no es memory-hard y porque la asignatura ya había usado Scrypt. PBKDF2 solo tendría sentido si nos exigieran FIPS.

### Usuario ficticio

Si el usuario no existe y volvemos al momento, la respuesta es más rápida y se puede enumerar cuentas. `_dummy` es un hash Scrypt generado al arrancar el Hub. El login de un desconocido verifica contra ese hash. El mensaje es siempre «credenciales inválidas».

No afirmamos que los tiempos sean iguales al microsegundo. Afirmamos que no nos saltamos Scrypt, que es lo que domina el tiempo. El resto del `if` es despreciable al lado.

Detalle que pueden cazar: la contraseña interna del dummy es `contraseña-ficticia`. Si alguien la escribe y el usuario no existe, `verify_password` devuelve verdadero, pero `correcto and registro` sigue siendo falso porque no hay cuenta. No hay bypass. Si la pregunta sale, se señala esa línea de `login`.

### Bloqueo simple, no progresivo

El borrador de la memoria hablaba de una ventana de 60 segundos y de bloqueos de 30, 60, 120, 240 y 300 segundos. El código no hace eso. Hace esto:

1. Cada fallo suma uno, sin ventana.
2. Al quinto, la respuesta sigue siendo «credenciales inválidas» y se arma un bloqueo hasta `ahora + 60`.
3. Mientras dura, también se rechaza la contraseña buena, con «demasiados intentos, inténtalo más tarde».
4. Pasado el minuto, la contraseña buena entra y borra el contador.
5. Si en vez de acertar se falla otra vez, el contador ya vale 5 o más y el bloqueo de 60 segundos vuelve a armarse.
6. Al morir el proceso, `self._fallos` desaparece.

El mensaje de bloqueo sí distingue, a partir del sexto intento, una cuenta que ya falló cinco veces. Antes de eso, el mensaje no dice si el usuario existe. Un usuario que no existe también se bloquea: el contador es por nombre, no solo por cuentas reales.

No está en disco. Reiniciar el programa lo borra. En un servicio expuesto haría falta persistirlo y limitar también por origen. Aquí el cliente y el servidor son el mismo proceso.

### AES-256-GCM, no CBC con HMAC, no ChaCha20 en este código

CBC solo no autentica. CBC y después HMAC es correcto si el orden es cifrar y luego autenticar, y si no se descifra antes de verificar. Es fácil hacerlo mal. GCM lo deja en una llamada y, si el tag falla, la librería no devuelve claro. Ese es el camino de `decrypt`: `InvalidTag` se convierte en `CryptoError` y no hay `return` con datos.

ChaCha20-Poly1305 sería igual de defendible. Nos quedamos en AES-GCM porque es el de la práctica 2 y ya estaba integrado. La clave es de 256 bits. `_aes256` rechaza otra longitud: no queremos un fallo silencioso que baje a AES-128.

El tag es de 128 bits. No se trunca. Truncarlo solo debilitaría la autenticación.

### Nonce aleatorio de 12 bytes

GCM exige que el par (clave, nonce) no se repita. Si se repite, se recupera la XOR de los claros y se pueden falsificar tags. El nonce va en claro delante del mensaje: no es secreto, es único.

12 bytes es el tamaño nativo. Con otra longitud, GCM tiene que hacer un paso extra y la regla de unicidad cambia. `os.urandom(12)` en cada `encrypt`.

No pasamos a un nonce-contador porque el aleatorio ya cumple el límite práctico. NIST SP 800-38D pide que la probabilidad de repetir clave y nonce quede por debajo de 2^-32. Con 96 bits aleatorios eso se mantiene hasta del orden de 2^32 mensajes por clave. Una sesión tiene un puñado, y cada login deriva una clave nueva (sal nueva). La envoltura de la privada cifra una sola vez.

La prueba `test_aes_256_gcm_y_rechazo_de_tag` cifra 24 veces con la misma clave y exige 24 nonces distintos. Eso no demuestra el límite de NIST; demuestra que no estamos fijando el nonce.

### HMAC en el fichero y GCM en el canal, no las dos cosas sobre lo mismo

El canal necesita secreto e integridad: GCM. El fichero necesita integridad. Los hashes y la clave pública no son secretos, y la privada ya va cifrada aparte. Por eso el JSON lleva HMAC y no va cifrado entero.

No se pone un HMAC adicional sobre el texto cifrado de GCM. El tag ya cubre el texto cifrado y el AAD. Un MAC de más, en el orden equivocado, es un fallo clásico, no defensa en profundidad.

La etiqueta HMAC se calcula sobre `canonico(datos)`: JSON con las claves ordenadas y sin espacios. El fichero se guarda indentado. Darle formato no rompe el HMAC, porque al cargar se parsea y se vuelve a canonicalizar. Cambiar un valor sí lo rompe. La sal del fichero no entra en el JSON autenticado; entra en la derivación de la clave. Cambiar la sal cambia la clave y la etiqueta no verifica.

Passphrase mala y fichero retocado dan el mismo error. No decimos cuál de las dos cosas ha pasado.

### Firma ECDSA P-256, y por qué no sobra aunque exista el HMAC

El HMAC dice «este fichero lo escribió quien sabe la passphrase del hub». La firma dice «esta autorización la emitió la clave del propietario». Son dos titulares.

La comprobación está en `_autorizacion_valida`, sobre el registro ya cargado en memoria. La prueba voltea un byte de la firma sin tocar el disco: la puerta no se abre y aparece `FIRMA_INVALIDA`. Eso el HMAC no lo ve, porque el HMAC ya se comprobó al arrancar. Al revés, cambiar el rol dentro del JSON y volver a abrir el fichero falla en `_cargar`, antes de mirar ninguna firma.

No hay certificados. La pública vive en el registro del propietario, dentro del fichero con HMAC. Unirla a otra identidad no hace falta: no hay usuarios fuera de esta aplicación. Si alguien sustituye la pública, el HMAC no cuadra.

La privada no se guarda con el cifrado de PKCS#8 (`BestAvailableEncryption`). Se exporta sin cifrar y se envuelve con nuestro AES-256-GCM, con AAD igual al nombre de usuario. Así el cifrado se ve en el código y el AAD ata el blob a esa cuenta. La clave de envoltura no es el hash de la contraseña: es Scrypt de la misma contraseña con otra sal. Robar el hash no descifra la privada.

El nonce k de ECDSA lo genera OpenSSL. No lo implementamos nosotros. Si k se repite o es predecible, de dos firmas se saca la clave privada. Por eso la firma no está hecha a mano.

Ed25519 o RSA-3072 habrían servido. P-256 es más corta que RSA para el mismo margen, y es la que el enunciado pone de ejemplo. La verificación falsa devuelve `False`; no lanza hacia el usuario. Quien llama, `_autorizacion_valida`, no abre la puerta si es falso.

### Cerrar la puerta no pide autorización

Cualquier sesión autenticada puede cerrar. Abrir, si eres invitado, pide autorización, plazo, no revocación, firma válida y alarma apagada. Cerrar deja la puerta en un estado más seguro. El propietario puede abrir con la alarma puesta; el invitado no, aunque la firma sea buena. El orden está en `_puerta`: primero la alarma, después la autorización.

### Misma clave de sesión en los dos sentidos

La clave de App hacia Hub y la de Hub hacia App es la misma. El AAD lleva `C` o `H`, así que un blob de un sentido no verifica en el otro. Eso no evita por sí solo un choque de nonces: en GCM el flujo depende de la clave y del nonce, no del AAD. El choque sigue siendo el de un nonce aleatorio de 96 bits, con muy pocos mensajes. Si lo preguntan, se dice así, sin adornarlo. Un diseño más estricto habría derivado dos claves, una por sentido. No hacía falta para el volumen de la práctica y no se cambió algo que ya era correcto.

## Qué ocurre cuando algo falla

| Qué se toca | Qué ve el usuario | Qué no ocurre |
| --- | --- | --- |
| Contraseña mala o usuario desconocido | credenciales inválidas | No hay sesión. En el desconocido sí se ha ejecutado Scrypt. |
| Sexto intento dentro del minuto | demasiados intentos, inténtalo más tarde | No se mira la contraseña buena como un acierto. |
| Tag, texto cifrado, AAD o clave de un mensaje | orden rechazada, o respuesta del hub no válida | No hay texto claro. El contador no avanza. La puerta no se mueve. |
| Clave AES que no es de 32 bytes | CryptoError, clave AES-256 inválida | No se cifra con AES-128. |
| Contador repetido | orden rechazada | No se vuelve a ejecutar la orden. |
| Passphrase mala o JSON cambiado | datos alterados o passphrase incorrecta (HMAC inválido) | No se cargan usuarios ni autorizaciones. |
| Firma mala | acceso denegado, y en el log FIRMA_INVALIDA | La puerta sigue como estaba. |
| Autorización caducada o revocada | acceso denegado | No se abre. |
| Invitado pide alarma, autorizar, revocar o eventos | solo el propietario puede hacer esto | No se ejecuta. |
| Usuario vacío, None, o con salto de línea | usuario inválido | No se inserta en el diccionario y no hay TypeError. |

Los logs de depuración dicen el algoritmo y los bits: «AES-GCM 256 bits», «HMAC-SHA256 … clave de 256 bits», «ECDSA P-256», «Derivación scrypt: clave de 256 bits». No imprimen la clave, la sal, la contraseña, el nonce ni el claro. La prueba `test_logs_indican_algoritmo_y_no_el_secreto` lo comprueba. El demo, igual: en su salida no están `Propietario#2026ok`, `Invitado#2026ok` ni `passphrase-del-hub-demo`.

## Preguntas probables

**¿Por qué Scrypt y no un simple hash?** Porque la contraseña tiene poca entropía. Hace falta una función lenta y con coste de memoria, más una sal por usuario.

**¿Qué es N, r y p?** N es el coste, potencia de dos, y marca la memoria y las iteraciones. r es el tamaño de bloque. p es el paralelismo. Con r = 8 y N = 2^14 el uso de memoria ronda los 16 MiB. Subir N una unidad duplica memoria y CPU.

**¿Dónde está la sal y por qué no es secreta?** Va junto al hash, en Base64. El atacante que roba el fichero ya la ve. Su función no es esconderse: es que cada hash sea único y no valgan las tablas hechas de antemano.

**¿Dos usuarios con la misma contraseña?** Dos sales, dos hashes. Está en `test_registro_roles_password_y_usuario_invalido`.

**¿El hash sirve para descifrar la clave privada?** No. Son dos llamadas a Scrypt con dos sales. Hace falta la contraseña otra vez.

**¿Qué pasa si el tag falla?** `AESGCM.decrypt` lanza `InvalidTag`. Nosotros lanzamos `CryptoError` y no devolvemos bytes. El Hub no ejecuta la orden y no incrementa `rx`. Si incrementara el contador antes de verificar, un atacante podría avanzar el contador con basura. Se incrementa después.

**¿Cómo es el ataque de repetición?** El atacante guarda una orden de «abrir principal» ya cifrada y la vuelve a enviar. El contador es menor o igual que `rx`, así que se rechaza antes de aceptar el comando. Si cambia el contador de la cabecera, el AAD es otro y el tag no sale.

**¿Y si repite el nonce?** Con la misma clave, GCM se rompe. No lo detectamos con un error de tag: las dos operaciones fueron legítimas. Lo evitamos generando un nonce nuevo cada vez y cambiando la clave de sesión en cada login. No hay un registro eterno de nonces. Si preguntan «¿lo detectáis?», la respuesta honesta es: no hace falta detectarlo si no se reutiliza; GCM no avisa de que el nonce ya se usó.

**¿Por qué el nonce va en claro?** El receptor lo necesita para descifrar. El secreto es la clave.

**¿Qué es el AAD?** Datos que no se cifran pero sí entran en el tag. Aquí atan el mensaje a la sesión, al sentido y al contador. Se pueden leer. No se pueden cambiar sin romper el tag.

**¿Por qué HMAC si ya tenéis GCM?** Porque el fichero no va cifrado. GCM no protege lo que no se cifra. HMAC sí.

**¿La comparación del HMAC es en tiempo constante?** Sí, `HMAC.verify` de la librería. No comparamos con `==`.

**¿Dónde está la clave HMAC?** No está. En disco está la sal. La clave se deriva de la passphrase al arrancar y vive en memoria.

**¿Sustituyo el fichero entero por otro mío?** Con otra passphrase, la del dueño no lo abre. No hay un «aceptar el fichero nuevo» silencioso.

**¿Por qué ECDSA y no RSA?** Misma idea de seguridad con una clave mucho más corta, y es el ejemplo del enunciado. La verificación rechaza una firma alterada: se puede enseñar el test y el demo.

**¿La firma evita que edite el JSON?** El HMAC es quien evita que el fichero editado se cargue. La firma evita que una autorización ya cargada, si alguien le cambia el cuerpo o la firma en memoria, se dé por buena. Hay que separar las dos frases. Si se mezclan, la pregunta siguiente es fácil.

**¿Qué se firma exactamente?** El JSON canónico del diccionario: id, propietario, invitado, puerta, inicio, fin, emitida. No se firma un texto con espacios variables. Por eso, al guardar y volver a cargar, la firma sigue cuadrando. Lo enseña `test_la_firma_sigue_siendo_valida_tras_recargar`.

**¿Caducidad y revocación están firmadas?** El intervalo sí, porque `inicio` y `fin` van dentro de lo firmado. La revocación es una lista de ids en el mismo fichero, bajo el HMAC, no una segunda firma. Quitar un id de esa lista rompe el HMAC.

**¿Reloj?** El Hub recibe `reloj`. En producción es `time.time`. En las pruebas es una función nuestra, para caducar una autorización sin esperar y para el bloqueo de 60 segundos sin dormir.

**¿Por qué 24 horas?** Una autorización de invitado es temporal. Un plazo más largo se rechaza en `_autorizar`. No es una propiedad criptográfica; es una regla de la aplicación.

**¿El invitado presenta la autorización?** No. Pide «abrir» y el Hub busca en su almacén. La firma se verifica allí. El invitado no puede colar un JSON firmado por él en el canal: el canal solo transporta la orden, y la orden va cifrada con la clave de su sesión.

**¿App y Hub en el mismo proceso no anulan el cifrado?** Anulan el ataque de red, porque no hay red. No anulan el diseño: las funciones que habría al otro lado del cable ya comprueban tag, contador y firma. Sirve para demostrar esas comprobaciones. No hay que venderlo como un protocolo desplegado.

**¿Se puede enumerar usuarios?** En el login, no por el mensaje, y el dummy evita saltarse Scrypt. En el registro, «usuario no disponible» sí dice que el nombre existe. Es lo habitual al crear una cuenta. El bloqueo, a partir del sexto fallo, también deja ver que ese nombre ya acumuló cinco fallos.

**¿Contraseña `12345678`?** El registro la acepta. Cumple el mínimo y no hay reglas de complejidad. Scrypt la hace más cara de probar, no la hace buena. Hay que decirlo.

**¿Qué hay en el log de eventos?** Instantes, nombres de usuario, puertas, ids cortos de autorización. No hay contraseñas. `eventos` devuelve las diez últimas y solo las pide el propietario.

**¿Permisos del fichero?** `0o600` en el `open` del temporal, y `os.replace` conserva ese modo. La prueba lo mira. En Windows ese modo no significa lo mismo; el desarrollo es POSIX.

**¿`SMARTHOME_PASSPHRASE`?** Evita el prompt en una demo. Queda en el entorno del proceso. El camino normal es `getpass`, que no muestra lo tecleado. No está puesta en el código con un valor real.

**¿Qué versión y cómo se instala?** `cryptography==50.0.2` y `pytest==9.2.0` en `requirements.txt`. Entorno virtual, `pip install -r requirements.txt`, `python main.py demo`, `pytest -v`. No hay más librerías criptográficas.

**¿Habéis commiteado claves?** No. `.gitignore` deja fuera `datos_hub.json` y `*.tmp`. El demo usa un directorio temporal. Las contraseñas del demo son de ejemplo.

## Guion de la demo, por si hay proyector

Desde un venv ya instalado, en el directorio del proyecto:

```bash
python main.py demo
pytest -v
```

En el demo, señalar tres líneas y nada más:

1. `Verificación de firma: INVÁLIDA` y, debajo, `Apertura rechazada` con la puerta principal cerrada.
2. `AES-GCM descifrado FALLIDO: tag inválido` y `Descifrado rechazado`.
3. `HMAC-SHA256: verificación FALLIDA` después de haber cambiado el rol del invitado a propietario, y `Fichero rechazado`.

Si piden el caso feliz, está encima: `Firma ECDSA P-256 con SHA-256`, `Verificación de firma: válida` y la puerta principal abierta. El garaje, sin autorización, sale denegado.

`pytest -v` tiene que acabar en 15 passed. Si una falla, no se improvisa: se lee el nombre del test, que dice qué rechazo se ha roto.

No hace falta entrar en el menú. Si insisten, passphrase de mentira de al menos 8 caracteres y usuarios de mentira. No se abre un `datos_hub.json` que no sea de esa sesión.

## Qué no afirmar

- No decir que el bloqueo es progresivo ni que hay una ventana de 60 segundos. Eso estaba en el borrador y no está en el código.
- No decir que cumplimos el mínimo de OWASP para Scrypt. No lo cumplimos, y la memoria lo dice.
- No decir que el nonce es imposible de repetir. Decir que la probabilidad, para este uso, queda por debajo del límite del modo.
- No decir que la firma sustituye al HMAC, ni al revés.
- No decir que hay cifrado asimétrico. Hay firma asimétrica.
- No decir que App y Hub son un canal de red real.
- No decir que el fichero va cifrado. Va autenticado. La privada, dentro, sí va cifrada.
- No leer en voz alta una clave, una sal ni una contraseña. Los logs no las tienen; no hace falta enseñar el JSON de un usuario real.
- No atribuir el repositorio a la URL antigua `100550203-byte`. La de esta entrega es `https://github.com/100550149/SmartHome`.

## Si se quedan sin pregunta

Tres límites, en este orden, dan mejor impresión que esperar a que los encuentren:

1. El coste Scrypt es el de la práctica, no el de OWASP.
2. El bloqueo vive en memoria y es por nombre de cuenta, no por origen.
3. El cifrado del canal demuestra el formato del mensaje; no hay un socket.

Y una frase de cierre: cuando un tag, un HMAC o una firma fallan, no hay texto claro, no se carga el fichero y no se abre la puerta.

## Preguntas de la segunda revisión

**Si copio un `datos_hub.json` de ayer, ¿vuelve una autorización revocada?** No, si el fichero `.gen` sigue en el valor nuevo. El JSON antiguo tiene un HMAC válido, pero su generación es menor y se rechaza con «copia antigua del fichero rechazada». Si copian los dos ficheros a la vez, la pareja es coherente y entra: no hay un contador fuera del disco. Hay que decir ese límite.

**¿El nonce se reutiliza?** No a propósito. Cada `encrypt` pide 12 bytes a `os.urandom`. La clave de sesión cambia en cada login. No llevamos un registro eterno de nonces. GCM no avisa si, por azar, un nonce se repitiera.

**¿La orden va en el AAD?** No. Va cifrada, y el tag la autentica. En el AAD van el sentido (`C` o `H`), el token y el contador, que viajan en claro y tienen que quedar atados al mensaje. Cambiar el contador de la cabecera sin rehacer el tag falla. Está en `test_aad_ata_contador_token_y_sentido`.

**¿Por qué HMAC y no cifrar el JSON entero?** Porque los hashes y la clave pública no son secretos, y la privada ya va en AES-GCM. El HMAC cubre integridad. La sal entra en el cálculo, no solo en la derivación de la clave.

**¿Qué pasa con José escrito de dos formas?** Se normaliza a NFC. Es la misma cuenta y el mismo bloqueo. «Ana» y «ana» no se pliegan: son dos cuentas. Bloquear una no entra en la otra.

**En Windows, ¿basta el 0600?** No. Ese modo no toca la ACL. Se llama a `icacls /inheritance:r /grant:r USUARIO:(R,W)`. En POSIX se hace `chmod 0600`. Las pruebas de rutas usan `pathlib`, también con espacios.

**¿Un registro de autorización roto tira el programa?** No. Se salta y se miran las demás. Si ninguna vale, la puerta no se abre.

**¿Qué pasa si el disco se llena a mitad de un alta?** El temporal no sustituye al fichero bueno. El usuario no se queda a medias en memoria. Dos procesos no escriben a la vez: hay un candado, `flock` o `msvcrt`.

**¿Habéis volteado solo el último byte?** No. Cada posición del mensaje GCM, del tag HMAC y de la firma. También mensajes truncados y tipos que no son `bytes`.

**¿La cobertura?** `pytest-cov` sobre `crypto_utils.py` y `smarthome.py`. En la última ejecución de esta entrega, por encima del 90 % en los dos. La cifra exacta está en la figura de la memoria; no hace falta memorizarla si se sabe cómo se obtiene.
