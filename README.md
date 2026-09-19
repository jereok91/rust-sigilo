# RustSigilo

Aplicación de escritorio pequeña para **cifrar y descifrar texto con AES-256**
usando un secreto de 32 bytes en Base64. Está pensada para trabajar con
secretos MFA/TOTP u otros valores guardados cifrados en una base de datos:
pegas la clave y el texto cifrado, y obtienes el texto en claro (o al revés).

Está hecha con [Tauri 2](https://tauri.app): la lógica criptográfica está en
Rust y la interfaz en HTML/CSS/JS, sin frameworks.

Todo ocurre **localmente**. La app no usa la red, no guarda nada en disco y
no registra claves ni textos.

---

## Funciones

- **Descifrar**: detecta sola el modo (GCM o CBC) y el formato del texto cifrado.
- **Cifrar**: genera el texto cifrado en uno de tres formatos a elegir.
- El campo del secreto está oculto por defecto, con un botón para mostrarlo.
- Tiene un botón para copiar el resultado al portapapeles.
- Al cambiar de pestaña, el último resultado pasa a ser la nueva entrada, así puedes cifrar y comprobar al instante.
- Atajo `Ctrl + Enter` para ejecutar.
- Tema claro y oscuro según el sistema.

---

## La clave (secreto)

AES-256 necesita una clave de **exactamente 32 bytes**. Genera una así:

```bash
openssl rand -base64 32
# ej: 16MI/yMffwNf4fmFt57i94HLkg0n/VkfmSoGwBFPun8=
```

Formatos de clave aceptados:

| Formato | Ejemplo |
|---|---|
| Base64 (estándar o URL-safe, con o sin `=`) | `16MI/yMffwNf4fmFt57i94HLkg0n/VkfmSoGwBFPun8=` |
| Base64 con prefijo `base64:` (estilo Laravel) | `base64:16MI/yMf...` |
| Hex de 64 caracteres | `d7a308ff231f7f035fe1f985...` |

Si la clave no mide 32 bytes, la app avisa con cuántos bytes tiene.

---

## Cómo se usa

### Descifrar

1. Abre la pestaña **Descifrar**.
2. Pega el **secreto**.
3. Pega el **texto cifrado**. Los espacios y saltos de línea se ignoran.
4. Pulsa **Descifrar**.
5. Aparece el texto en claro, y debajo, en verde, el formato que se detectó
   (por ejemplo `AES-256-GCM (nonce12 || ciphertext || tag)`).

Si la clave no corresponde o el formato no se reconoce, sale un mensaje de error en rojo.

### Cifrar

1. Abre la pestaña **Cifrar**.
2. Pega el **secreto**.
3. Escribe el **texto en claro**.
4. Elige el **formato de salida** (ver tabla abajo).
5. Pulsa **Cifrar** y copia el resultado.

> Cada cifrado usa un nonce/IV aleatorio nuevo. Por eso **el mismo texto da
> un resultado distinto cada vez**, y es lo correcto: todos se descifran igual.

---

## Formatos soportados

### Al cifrar (salida)

| Opción | Estructura | Uso típico |
|---|---|---|
| **AES-256-GCM · Base64** (por defecto) | `Base64( nonce[12] ‖ cifrado ‖ tag[16] )` | Recomendado: autenticado y compacto |
| AES-256-GCM · hex | `hex(iv):hex(tag):hex(cifrado)` | Implementaciones en Node.js con `crypto` |
| AES-256-CBC · Base64 | `Base64( iv[16] ‖ cifrado )`, relleno PKCS7 | Sistemas antiguos que usan CBC |

### Al descifrar (detección automática)

Las partes pueden venir en **Base64 o hex**, separadas por `:` o `.`:

| Estructura | Modo |
|---|---|
| `nonce[12 o 16] ‖ cifrado ‖ tag[16]` (un solo bloque) | GCM |
| `nonce[12 o 16] ‖ tag[16] ‖ cifrado` (un solo bloque) | GCM |
| `iv:tag:cifrado` o `iv:cifrado:tag` | GCM |
| `iv:cifrado` (con el tag al final del cifrado) | GCM |
| `iv[16] ‖ cifrado` (un solo bloque) | CBC |
| `iv:cifrado` | CBC |
| JSON en Base64 estilo Laravel `{"iv","value","tag"?}` | GCM si tiene `tag`, si no CBC |

**Cómo decide:** primero prueba todas las variantes GCM. GCM está
autenticado, así que si una funciona, la clave y el formato son correctos
con total seguridad. Después prueba CBC. Como CBC no está autenticado, solo
acepta el resultado si el relleno es válido **y** el texto es UTF-8 válido;
así se evitan falsos positivos.

---

## Requisitos

- **Rust** (stable) y **Cargo**
- **Node.js** con `npm` o `pnpm` (solo para el CLI de Tauri)
- En Linux: `webkit2gtk-4.1` y `gtk3`. En Arch/CachyOS:
  ```bash
  sudo pacman -S webkit2gtk-4.1 gtk3 base-devel
  ```

## Ejecutar y compilar

```bash
pnpm install          # o npm install

pnpm run dev          # modo desarrollo (recarga al cambiar el código)
pnpm run build        # genera paquetes .deb / .rpm / AppImage en src-tauri/target/release/bundle/
npx tauri build --no-bundle   # solo el ejecutable: src-tauri/target/release/RustSigilo
```

## Pruebas

```bash
cd src-tauri
cargo test --lib
```

Las pruebas cubren:
- descifrado GCM (bloque Base64 y formato `iv:tag:ct` en hex),
- descifrado CBC,
- rechazo con una clave incorrecta,
- validación del largo de la clave,
- ida y vuelta (cifrar → descifrar) en los tres formatos, con acentos y emojis.

También se comprobó la compatibilidad con herramientas externas: textos
cifrados con `openssl enc -aes-256-cbc` y con el `crypto` de Node.js se
descifran bien, y lo que cifra la app lo descifran esas mismas herramientas.

---

## Estructura del proyecto

```
RustSigilo/
├── package.json              # CLI de Tauri y scripts (dev / build)
├── src/                      # Interfaz (sin bundler)
│   ├── index.html            # Pestañas, campos y botones
│   ├── main.js               # Llama a los comandos Rust vía window.__TAURI__
│   └── styles.css            # Estilos, tema claro/oscuro
└── src-tauri/
    ├── Cargo.toml            # Dependencias: tauri, aes-gcm, cbc, base64, hex
    ├── tauri.conf.json       # Ventana, CSP, bundle
    ├── capabilities/         # Permisos de Tauri (solo core:default)
    ├── icons/
    └── src/
        ├── main.rs           # Punto de entrada y arreglo Wayland/NVIDIA
        ├── lib.rs            # Comandos Tauri: decrypt y encrypt
        └── crypto.rs         # Lógica AES-256 (GCM/CBC), formatos y pruebas
```

### Flujo interno

```
 Interfaz (main.js)                        Rust (lib.rs → crypto.rs)
 ───────────────────                       ─────────────────────────
 invoke("decrypt", {key, ciphertext}) ──►  parse_key → candidates → probar GCM → probar CBC
                                      ◄──  { plaintext, method }  |  error

 invoke("encrypt", {key, plaintext,   ──►  parse_key → nonce/IV aleatorio (OsRng) → cifrar
                    format})          ◄──  texto cifrado          |  error
```

---

## Solución de problemas

**`Gdk-Message: Error 71 (Error de protocolo) dispatching to Wayland display`**
Es un fallo conocido de WebKitGTK con NVIDIA en Wayland. La app ya lo evita:
pone `WEBKIT_DISABLE_DMABUF_RENDERER=1` al arrancar. Si aun así falla,
fuerza el uso de XWayland:

```bash
GDK_BACKEND=x11 pnpm run dev
```

**"No se pudo descifrar"**
- Verifica que el secreto sea la misma clave con la que se cifró.
- Asegúrate de haber copiado el texto cifrado completo.
- Si el formato es otro (otro orden de partes, AAD, otro largo de nonce), hay que agregarlo en `candidates()` dentro de `src-tauri/src/crypto.rs`.

---

## Notas de seguridad

- **Prefiere GCM**: detecta si el texto cifrado fue alterado. CBC no lo hace.
- **No reutilices la clave** en otros sistemas, y guárdala fuera del código (variables de entorno, un gestor de secretos).
- Si pegas el secreto, puede quedar en el historial del portapapeles de tu sistema.
