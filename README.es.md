<p align="center">
  <a href="README.ja.md">日本語</a> | <a href="README.zh.md">中文</a> | <a href="README.md">English</a> | <a href="README.fr.md">Français</a> | <a href="README.hi.md">हिन्दी</a> | <a href="README.it.md">Italiano</a> | <a href="README.pt-BR.md">Português (BR)</a>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/mcp-tool-shop-org/brand/main/logos/nullout/readme.png" width="400" alt="NullOut">
</p>

<p align="center">
  <a href="https://github.com/mcp-tool-shop-org/nullout/actions/workflows/ci.yml"><img src="https://github.com/mcp-tool-shop-org/nullout/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://codecov.io/gh/mcp-tool-shop-org/nullout"><img src="https://codecov.io/gh/mcp-tool-shop-org/nullout/branch/main/graph/badge.svg" alt="Coverage"></a>
  <a href="https://github.com/mcp-tool-shop-org/nullout/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT License"></a>
  <a href="https://mcp-tool-shop-org.github.io/nullout/"><img src="https://img.shields.io/badge/Landing_Page-live-blue" alt="Landing Page"></a>
</p>

Servidor MCP que encuentra y elimina de forma segura archivos "indelebles" en Windows.

Windows reserva nombres de dispositivos como `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9` y `LPT1`-`LPT9` en la capa Win32. Los archivos con estos nombres pueden existir en NTFS (creados a través de WSL, herramientas de Linux o API de bajo nivel), pero se vuelven imposibles de renombrar, mover o eliminar a través de Explorador o comandos de shell normales.

NullOut escanea estas entradas peligrosas y las elimina de forma segura utilizando el espacio de nombres de ruta extendido `\\?\`, con un flujo de trabajo de confirmación de dos fases diseñado para hosts MCP.

## Cómo funciona

1. **Escanea** un directorio especificado para detectar colisiones de nombres reservados, puntos/espacios al final y rutas demasiado largas.
2. **Planifica** la limpieza: NullOut genera un token de confirmación para cada entrada, vinculado a la identidad del archivo (número de serie del volumen + ID del archivo).
3. **Elimina** con el token: NullOut vuelve a verificar que el archivo no haya cambiado (protección TOCTOU) antes de eliminarlo a través del espacio de nombres extendido.

## Modelo de seguridad

- **Solo raíces especificadas** — las operaciones se limitan a los directorios que configure explícitamente.
- **Sin rutas directas en llamadas destructivas** — la función de eliminación solo acepta los ID de hallazgos emitidos por el servidor y los tokens de confirmación.
- **Política de denegación total para puntos de análisis** — las uniones, los enlaces simbólicos y los puntos de montaje nunca se recorren ni se eliminan.
- **Vinculación de la identidad del archivo** — los tokens están firmados con HMAC y vinculados al número de serie del volumen + ID del archivo; cualquier cambio entre el escaneo y la eliminación se rechaza.
- **Solo directorios vacíos** — la versión 1 se niega a eliminar directorios que no estén vacíos.
- **Errores estructurados** — cada fallo devuelve un código legible por máquina con sugerencias para el siguiente paso.

## Herramientas MCP

| Herramienta | Tipo | Propósito |
|------|------|---------|
| `list_allowed_roots` | solo lectura | Mostrar las raíces de escaneo configuradas. |
| `scan_reserved_names` | solo lectura | Encontrar entradas peligrosas en una raíz. |
| `get_finding` | solo lectura | Obtener detalles completos de un hallazgo. |
| `plan_cleanup` | solo lectura | Generar un plan de eliminación con tokens de confirmación. |
| `delete_entry` | destructiva | Eliminar un archivo o un directorio vacío (requiere token). |
| `who_is_using` | solo lectura | Identificar los procesos que bloquean un archivo (Administrador de reinicio). |
| `get_server_info` | solo lectura | Metadatos del servidor, políticas y capacidades. |

## Configuración

Establecer las raíces especificadas a través de la variable de entorno:

```
NULLOUT_ROOTS=C:\Users\me\Downloads;C:\temp\cleanup
```

Secreto de firma de tokens (generar un valor aleatorio):

```
NULLOUT_TOKEN_SECRET=your-random-secret-here
```

## Modelo de amenazas

NullOut se defiende contra:

- **Uso destructivo** — la función de eliminación requiere un token de confirmación emitido por el servidor; no se aceptan rutas directas.
- **Recorrido de rutas** — todas las operaciones se limitan a las raíces especificadas; las secuencias de escape ".." se resuelven y se rechazan.
- **Escapes de puntos de análisis** — las uniones, los enlaces simbólicos y los puntos de montaje nunca se recorren ni se eliminan (denegación total).
- **Carreras TOCTOU** — los tokens están vinculados con HMAC al número de serie del volumen + ID del archivo; cualquier cambio de identidad entre el escaneo y la eliminación se rechaza.
- **Trucos de espacio de nombres** — las operaciones destructivas utilizan el prefijo de ruta extendido `\\?\` para evitar el análisis de nombres de Win32.
- **Archivos bloqueados** — la atribución del Administrador de reinicio es de solo lectura; NullOut nunca finaliza procesos.
- **Directorios no vacíos** — se rechazan por política; solo se pueden eliminar los directorios vacíos.

**Datos a los que se accede:** metadatos del sistema de archivos (nombres, ID de archivos, números de serie de volúmenes), metadatos del proceso (PID, nombres de aplicaciones a través del Administrador de reinicio).
**Datos a los que NO se accede:** contenido de los archivos, red, credenciales, registro de Windows.
**No se recopila ni se envía** ninguna telemetría.

## Requisitos

- Windows 10/11
- Python 3.10+

---

Creado por <a href="https://mcp-tool-shop.github.io/">MCP Tool Shop</a
