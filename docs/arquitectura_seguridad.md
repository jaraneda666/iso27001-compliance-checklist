# Arquitectura Técnica y Modelo de Protección Anti-Alteración

## 1. Visión General de la Arquitectura

La aplicación `index.html` adopta el patrón de diseño **Single-File SPA (Single Page Application)** con enfoque *offline-first*. Su arquitectura garantiza autonomía operativa, portabilidad y resistencia contra manipulaciones no autorizadas en entornos locales.

```
+-----------------------------------------------------------------------+
|                 ARCHIVO ÚNICO MONOLÍTICO (index.html)                 |
|                                                                       |
|  +--------------------+  +--------------------+  +-----------------+  |
|  |     ESTILOS CSS    |  |     CATÁLOGO DE    |  |  MOTOR REACTIVO |  |
|  |     EMBEBIDOS      |  |    CONTROLES JSON  |  |    JAVASCRIPT   |  |
|  |  (Dark/Light Mode, |  |  (105 Controles:   |  | (Filtros, KPIs, |  |
|  |  Layout Responsivo,|  |  ISO 27001, 42001, |  |   Métricas SoA, |  |
|  |   Estilos Print)   |  |    Ley 21.719)     |  |   Persistencia) |  |
|  +--------------------+  +--------------------+  +-----------------+  |
|                                                                       |
|  +-----------------------------------------------------------------+  |
|  |              CAPA DE SEGURIDAD CLIENT-SIDE INTEGRADA             |  |
|  |   - Verificación de Integridad del Catálogo (Checksum SHA-256)   |  |
|  |   - Autenticación Criptográfica con Web Crypto API (SubtleCrypto)|  |
|  |   - Bloqueo de Estado y Modo Solo Lectura por Defecto            |  |
|  +-----------------------------------------------------------------+  |
+-----------------------------------------------------------------------+
                                  |
                                  v
                  Almacenamiento Local (localStorage)
```

---

## 2. Mecanismos de Seguridad Implementados

### 2.1 Cero Almacenamiento de Claves en Texto Plano
La clave de administración no se encuentra escrita de forma literal en el código fuente. Durante la compilación con `compilador_checklist_iso.py`, la contraseña ingresada se procesa mediante una función hash unidireccional SHA-256. El HTML almacena únicamente la huella criptográfica resultante de 64 caracteres hexadecimales.

### 2.2 Autenticación Criptográfica con Web Crypto API
Al momento del desbloqueo, el navegador ejecuta la API criptográfica nativa del estándar W3C (`crypto.subtle.digest("SHA-256", ...)`):
1. Convierte la cadena ingresada por el usuario en un arreglo de bytes UTF-8.
2. Calcula el digesto criptográfico en memoria volátil (RAM).
3. Compara el hash calculado contra la huella almacenada en tiempo constante.
4. Solo ante coincidencia matemática exacta habilita los eventos de edición del DOM.

### 2.3 Modo Auditoría de Solo Lectura por Defecto
Todos los elementos interactivos del formulario (`<select>`, `<input>`, `<textarea>`) nacen con el atributo `disabled`. Esta contención previene modificaciones involuntarias por parte de auditores externos, revisores o usuarios que visualicen el informe.

### 2.4 Control de Integridad del Catálogo (Anti-Tamper)
El aplicativo incorpora una firma de control del catálogo canónico de controles. Si un actor altera manualmente las descripciones de los controles o inyecta elementos maliciosos dentro del archivo HTML en disco, la función de integridad detecta la discrepancia matemática y emite una advertencia de seguridad en la consola del navegador.

### 2.5 Aislamiento de Red (Zero Network Dependencies)
El archivo no realiza solicitudes HTTP a dominios externos ni descarga librerías mediante redes de distribución de contenido (CDN). Esta condición neutraliza vectores de ataque comunes en aplicaciones web, tales como envenenamiento de dependencias (Supply Chain Attacks) o seguimiento de telemetría de terceros.

---

## 3. Instrucciones de Recompilación y Endurecimiento

Para generar una versión personalizada con una nueva contraseña y parámetros específicos, ejecute desde la raíz del workspace:

```bash
python tools/global/compilador_checklist_iso.py \
    --csv "ISO_27001_Checklist_App/referencias/iso-27001-annex-a-checklist.csv" \
    --output "ISO_27001_Checklist_App/output/index.html" \
    --password "TuClavePersonalizada2026!" \
    --title "Portal de Auditoría y Cumplimiento ISO 27001 / 42001"
```

