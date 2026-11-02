# Manual de Usuario: Sistema de Gestión Integrado y Checklist de Controles

## Introducción

La aplicación `index.html` es una herramienta monolítica de auditoría interna, autoevaluación y gobernanza para la creación y mantenimiento de un **Sistema de Gestión Integrado (SGI)** que unifica:
1. **ISO/IEC 27001:2022:** Seguridad de la información (93 controles del Anexo A).
2. **ISO/IEC 42001:2023 e ISO/IEC 27090:** Gestión ética y ciberseguridad en Inteligencia Artificial (6 controles especializados).
3. **Ley N° 21.719 de Chile:** Protección de datos personales y derechos ARCOP (6 controles especializados).
4. **Módulo Troncal del SGI:** Estructura de Alto Nivel (Cláusulas 4 a 10 de las normas ISO) para diseñar y formalizar el Sistema de Gestión Integrado.

El aplicativo funciona de forma autónoma fuera de línea (offline), sin dependencias de servidores web externos ni conexión a internet. Todos los componentes y estilos residen dentro del archivo.

---

## 1. Apertura y Primer Uso

1. Ubique el archivo ejecutable web en la carpeta:
   `ISO_27001_Checklist_App/output/index.html`
2. Haga doble clic sobre el archivo para abrirlo en su navegador predeterminado (Google Chrome, Microsoft Edge, Mozilla Firefox o Brave).
3. La aplicación se inicia automáticamente en **Modo Auditoría (Lectura)**. En este estado, los selectores de cumplimiento, campos de texto y notas se encuentran protegidos contra alteraciones accidentales o no autorizadas.

---

## 2. Autenticación y Desbloqueo de Edición

Para modificar el estado de los controles, asignar responsables o redactar evidencias:

1. Haga clic en el botón superior **Desbloquear Edición**.
2. En la ventana emergente, ingrese la clave maestra de administración.
   - **Clave maestra predeterminada de fábrica:** `iso27001admin`
3. Presione **Autenticar** o la tecla `Enter`.
4. El indicador superior cambiará a **Edición Habilitada** (en color verde) y se activarán todos los controles del formulario y campos del SGI.
5. Al finalizar su sesión de trabajo, presione **Bloquear Edición** para volver a proteger el aplicativo.

---

## 3. Navegación por Normas (Pestañas de Nivel 1)

El menú superior organiza el aplicativo en cuatro entornos dedicados:

- **🛡️ ISO/IEC 27001:2022 (Seguridad):** Despliega los 93 controles de la norma con sus 4 dominios oficiales:
  - *Organizacional (A.5):* 37 controles de políticas, activos, roles y proveedores.
  - *Personas (A.6):* 8 controles de concientización, contratos y teletrabajo.
  - *Físico (A.7):* 14 controles de perímetros, accesos y mantenimiento.
  - *Tecnológico (A.8):* 34 controles de criptografía, redes, autenticación y respaldos.
- **🤖 ISO/IEC 42001 & 27090 (Inteligencia Artificial):** Controles de gobernanza ética, supervisión humana, mitigación de riesgos de modelos (OWASP LLM) y linaje de datos de entrenamiento.
- **🔒 Ley N° 21.719 (Protección de Datos):** Requisitos de licitud, derechos ARCOP, notificación de brechas en 72 horas ante la autoridad y rol del Delegado de Protección de Datos (DPO).
- **🏛️ Creación del Sistema de Gestión Integrado (SGI):** Asistente metodológico interactivo para documentar las Cláusulas 4 a 10 de la organización.

---

## 4. Creación y Documentación del SGI (Cláusulas 4 a 10)

En la pestaña **Creación del SGI**, el auditor o líder de cumplimiento puede completar y ajustar las fases clave del sistema:
- **Fase 1: Contexto de la Organización (Cláusula 4):** Nombre y sector, alcance formal, partes interesadas relevantes y matriz FODA/PESTEL integrada.
- **Fase 2: Liderazgo y Compromiso (Cláusula 5):** Declaración formal de la Política Integrada del SGI y asignación de la matriz de roles y responsabilidades (CISO, DPO, Comité de IA).
- **Fase 3: Planificación y Gestión de Riesgos (Cláusula 6):** Metodología unificada de riesgos (ISO 31000 / 27005) y formulación de objetivos anuales SMART.
- **Fase 4: Soporte y Control Operacional (Cláusulas 7 y 8):** Programa anual de concientización y procedimientos operacionales vigentes.
- **Fase 5: Evaluación del Desempeño y Auditoría (Cláusula 9):** Programa anual de auditorías internas (ISO 19011) e indicadores de desempeño (KPIs).
- **Fase 6: Mejora Continua (Cláusula 10):** Procedimiento de tratamiento de no conformidades, análisis de causa raíz y planes de acción correctiva.

> [!TIP]
> Presione el botón **📄 Descargar Acta y Manual del SGI** para exportar automáticamente un documento formal con toda la estructura de gobernanza diligenciada.

---

## 5. Respaldo, Portabilidad e Informes

- **Guardado Automático:** Cada modificación se sincroniza inmediatamente en el almacenamiento local del navegador (`localStorage`).
- **Exportar JSON:** Genera una copia de seguridad descargable con fecha, estadísticas consolidadas, el estado completo de los 105 controles y los datos documentados del SGI.
- **Importar JSON:** Permite cargar auditorías previas o consolidar evaluaciones de distintos auditores.
- **Imprimir / Guardar PDF:** Al presionar el botón de impresión o `Ctrl+P`, la aplicación aplica una hoja de estilos optimizada para documentos ejecutivos, ocultando botones y barras de búsqueda para generar un reporte limpio en formato PDF o papel.
