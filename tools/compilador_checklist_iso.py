# Tool: compilador_checklist_iso.py

## Metadata
# - Nombre: compilador_checklist_iso.py
# - Versión: 2.0
# - Lenguaje: Python
# - Creada en proyecto: ISO_27001_Checklist_App
# - Fecha de creación: 2026-10-27
# - Descripción: Compilador de la aplicación web SPA monolítica (Single-File HTML) con soporte estricto en español, navegación de normas por pestañas dedicadas (ISO 27001:2022, ISO 42001/27090, Ley 21.719), módulo interactivo para Creación y Documentación de un SGI (Cláusulas 4 a 10), dashboard de métricas, persistencia local y protección criptográfica anti-alteración.
# - Parámetros: --json-es, --output, --password, --title
# - Dependencias: json, hashlib, pathlib, argparse, sys

## Código
import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Dict, List, Any

# Controles complementarios de ISO/IEC 42001:2023, ISO/IEC 27090 y Ley N° 21.719 (Chile)
CONTROLES_IA = [
    {
        "control_id": "IA.1.1",
        "control_name": "Política y Gobernanza del Sistema de Gestión de Inteligencia Artificial (SGIA)",
        "theme": "Gobernanza IA",
        "norma_id": "ISO_42001",
        "norma": "ISO/IEC 42001:2023",
        "description": "Establecer, formalizar y comunicar políticas de gobernanza que definan los principios éticos, límites operacionales, responsabilidades y uso seguro de modelos de inteligencia artificial y agentes autónomos dentro de la organización.",
        "status": "",
        "owner": "",
        "evidence_notes": "",
        "guide_url": "https://www.iso.org/standard/81230.html"
    },
    {
        "control_id": "IA.1.2",
        "control_name": "Gestión Continua de Riesgos en Modelos e Inferencia de IA",
        "theme": "Gobernanza IA",
        "norma_id": "ISO_42001",
        "norma": "ISO/IEC 42001:2023 / ISO 27090",
        "description": "Identificar, evaluar y tratar sistemáticamente riesgos específicos de sistemas de IA, incluyendo alucinaciones, sesgos algorítmicos, inyección de prompts, extracción no autorizada de modelos y envenenamiento de datos según el marco OWASP Top 10 for LLM.",
        "status": "",
        "owner": "",
        "evidence_notes": "",
        "guide_url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
    },
    {
        "control_id": "IA.1.3",
        "control_name": "Trazabilidad, Linaje y Calidad de Conjuntos de Datos",
        "theme": "Gobernanza IA",
        "norma_id": "ISO_42001",
        "norma": "ISO/IEC 42001:2023",
        "description": "Documentar la procedencia, integridad y derechos de propiedad intelectual de los datos utilizados en el entrenamiento, ajuste fino (fine-tuning) y pruebas de modelos de IA, verificando la ausencia de datos personales sin consentimiento.",
        "status": "",
        "owner": "",
        "evidence_notes": "",
        "guide_url": "https://www.iso.org/standard/81230.html"
    },
    {
        "control_id": "IA.1.4",
        "control_name": "Supervisión Humana y Explicabilidad (Human-in-the-Loop)",
        "theme": "Gobernanza IA",
        "norma_id": "ISO_42001",
        "norma": "ISO/IEC 42001:2023",
        "description": "Implementar compuertas obligatorias de supervisión, validación y control humano antes de ejecutar decisiones automatizadas que generen impacto financiero, operativo, pericial o legal en personas u organizaciones.",
        "status": "",
        "owner": "",
        "evidence_notes": "",
        "guide_url": "https://www.iso.org/standard/81230.html"
    },
    {
        "control_id": "IA.1.5",
        "control_name": "Ciberseguridad y Aislamiento en Arquitecturas de IA (ISO 27090)",
        "theme": "Gobernanza IA",
        "norma_id": "ISO_42001",
        "norma": "ISO/IEC 27090",
        "description": "Aplicar controles defensivos sobre pipelines de inferencia, endpoints de APIs de LLMs locales y servidores MCP, incluyendo contenedores en modo solo lectura, descarte de privilegios (cap_drop), listas blancas de red y monitoreo de llamadas anómalas.",
        "status": "",
        "owner": "",
        "evidence_notes": "",
        "guide_url": "https://www.iso.org/standard/27090"
    },
    {
        "control_id": "IA.1.6",
        "control_name": "Evaluación de Impacto Algorítmico y Transparencia con el Usuario",
        "theme": "Gobernanza IA",
        "norma_id": "ISO_42001",
        "norma": "ISO/IEC 42001:2023",
        "description": "Informar expresamente a los usuarios cuando interactúen con agentes o contenidos generados por inteligencia artificial, y mantener registros auditables de las evaluaciones de impacto sobre derechos fundamentales.",
        "status": "",
        "owner": "",
        "evidence_notes": "",
        "guide_url": "https://www.iso.org/standard/81230.html"
    }
]

CONTROLES_LEY_21719 = [
    {
        "control_id": "LPDP.1",
        "control_name": "Principios de Licitud, Lealtad, Finalidad y Proporcionalidad de Datos",
        "theme": "Privacidad y Datos",
        "norma_id": "LEY_21719",
        "norma": "Ley N° 21.719 (Chile)",
        "description": "Garantizar que todo tratamiento de datos personales cuente con una base de licitud legalmente acreditada, limitando la recolección exclusivamente a lo indispensable para el fin explícito y legítimo comunicado al titular.",
        "status": "",
        "owner": "",
        "evidence_notes": "",
        "guide_url": "https://www.bcn.cl/leychile/navegar?idNorma=1208945"
    },
    {
        "control_id": "LPDP.2",
        "control_name": "Protección Reforzada y Consentimiento Expreso para Datos Sensibles",
        "theme": "Privacidad y Datos",
        "norma_id": "LEY_21719",
        "norma": "Ley N° 21.719 (Chile)",
        "description": "Establecer salvaguardas técnicas rigurosas de cifrado (AES-256) y seudonimización sobre datos biométricos, de salud, perfiles genéticos y datos de menores de edad, requiriendo consentimiento expreso, informado e inequívoco.",
        "status": "",
        "owner": "",
        "evidence_notes": "",
        "guide_url": "https://www.bcn.cl/leychile/navegar?idNorma=1208945"
    },
    {
        "control_id": "LPDP.3",
        "control_name": "Gestión Operativa de Derechos ARCOP (Acceso, Rectificación, Supresión, Oposición y Portabilidad)",
        "theme": "Privacidad y Datos",
        "norma_id": "LEY_21719",
        "norma": "Ley N° 21.719 (Chile)",
        "description": "Implementar canales expeditos, gratuitos y con trazabilidad auditable que permitan a los titulares ejercer oportunamente sus derechos de acceso, rectificación, supresión, oposición y portabilidad de datos personales.",
        "status": "",
        "owner": "",
        "evidence_notes": "",
        "guide_url": "https://www.bcn.cl/leychile/navegar?idNorma=1208945"
    },
    {
        "control_id": "LPDP.4",
        "control_name": "Protocolo de Notificación de Brechas de Seguridad a la Agencia de Datos (72h)",
        "theme": "Privacidad y Datos",
        "norma_id": "LEY_21719",
        "norma": "Ley N° 21.719 (Chile)",
        "description": "Definir y operar un procedimiento formal para reportar incidentes de seguridad que afecten datos personales ante la Agencia Nacional de Protección de Datos en un plazo máximo de 72 horas desde su detección, informando medidas de mitigación.",
        "status": "",
        "owner": "",
        "evidence_notes": "",
        "guide_url": "https://www.bcn.cl/leychile/navegar?idNorma=1208945"
    },
    {
        "control_id": "LPDP.5",
        "control_name": "Evaluación de Impacto en la Protección de Datos Personales (EIPD / DPIA)",
        "theme": "Privacidad y Datos",
        "norma_id": "LEY_21719",
        "norma": "Ley N° 21.719 (Chile)",
        "description": "Realizar evaluaciones de impacto previas a la puesta en marcha de tratamientos de datos a gran escala, monitoreo sistemático, tecnologías de perfilamiento o tratamiento masivo de categorías sensibles.",
        "status": "",
        "owner": "",
        "evidence_notes": "",
        "guide_url": "https://www.bcn.cl/leychile/navegar?idNorma=1208945"
    },
    {
        "control_id": "LPDP.6",
        "control_name": "Designación y Funciones del Delegado de Protección de Datos (DPO)",
        "theme": "Privacidad y Datos",
        "norma_id": "LEY_21719",
        "norma": "Ley N° 21.719 (Chile)",
        "description": "Designar formalmente a un Oficial o Delegado de Protección de Datos con autonomía técnica, reporte directo al máximo órgano de gobierno corporativo y registro ante la autoridad reguladora.",
        "status": "",
        "owner": "",
        "evidence_notes": "",
        "guide_url": "https://www.bcn.cl/leychile/navegar?idNorma=1208945"
    }
]

# Estructura del Sistema de Gestión Integrado (SGI) - Cláusulas 4 a 10 (Anexo SL)
MODULOS_SGI_BASE = [
    {
        "id": "sgi_clausula_4",
        "fase": "Fase 1: Contexto de la Organización",
        "titulo": "Cláusula 4: Contexto de la Organización y Alcance",
        "clausulas": "4.1, 4.2, 4.3, 4.4",
        "descripcion": "Determinación del entorno estratégico, partes interesadas y límites del Sistema de Gestión Integrado.",
        "campos": [
            {
                "id": "sgi_organizacion",
                "label": "Nombre de la Organización y Sector",
                "tipo": "text",
                "default": "Banco / Empresa de Servicios Tecnológicos"
            },
            {
                "id": "sgi_alcance",
                "label": "Declaración Formal del Alcance del SGI",
                "tipo": "textarea",
                "default": "El Sistema de Gestión Integrado cubre los procesos de negocio de la plataforma digital, servicios en la nube, infraestructura on-premise, modelos de lenguaje y sistemas de inteligencia artificial, abarcando las sedes centrales y centros de datos principales."
            },
            {
                "id": "sgi_partes_interesadas",
                "label": "Partes Interesadas Relevantes y sus Expectativas",
                "tipo": "textarea",
                "default": "• Clientes: Privacidad, disponibilidad y confidencialidad de datos transaccionales.\n• Reguladores (CMF / Agencia de Datos): Cumplimiento de Ley 21.719, ISO 27001 y normativas de riesgo operativo.\n• Colaboradores: Entornos seguros de trabajo y capacitación continua en seguridad de la información."
            },
            {
                "id": "sgi_factores_contexto",
                "label": "Factores Internos y Externos (Análisis FODA / PESTEL)",
                "tipo": "textarea",
                "default": "Factores Externos: Crecimiento de amenazas cibernéticas avanzadas (Ransomware), nueva regulación de protección de datos (Ley 21.719) y estandarización de IA (ISO 42001).\nFactores Internos: Transformación digital acelerada, teletrabajo y despliegue de modelos LLM locales."
            }
        ]
    },
    {
        "id": "sgi_clausula_5",
        "fase": "Fase 2: Liderazgo y Compromiso",
        "titulo": "Cláusula 5: Liderazgo, Política y Roles RACI",
        "clausulas": "5.1, 5.2, 5.3",
        "descripcion": "Compromiso de la alta dirección, emisión de la política unificada y distribución de responsabilidades.",
        "campos": [
            {
                "id": "sgi_politica_integrada",
                "label": "Política Integrada del SGI (Seguridad, IA y Privacidad)",
                "tipo": "textarea",
                "default": "La organización se compromete a preservar la confidencialidad, integridad y disponibilidad de la información, garantizar el uso ético y transparente de la inteligencia artificial, y salvaguardar los datos personales bajo estricto apego a las normas ISO/IEC 27001, ISO/IEC 42001 y Ley N° 21.719, promoviendo la mejora continua y la gestión proactiva de riesgos."
            },
            {
                "id": "sgi_roles_raci",
                "label": "Estructura de Roles y Responsabilidades Clave",
                "tipo": "textarea",
                "default": "• Alta Dirección: Aprueba presupuestos, nombra al CISO y DPO, y revisa el SGI anualmente.\n• CISO (Oficial de Seguridad): Diseña, opera y audita las salvaguardas del SGSI (ISO 27001).\n• DPO (Delegado de Protección de Datos): Vela por el cumplimiento de la Ley 21.719 y atiende derechos ARCOP.\n• Comité de Ética e IA: Valida evaluaciones de impacto algorítmico y autoriza despliegues de modelos.\n• Custodios de Activos: Aplican controles técnicos y reportan incidentes."
            }
        ]
    },
    {
        "id": "sgi_clausula_6",
        "fase": "Fase 3: Planificación y Gestión de Riesgos",
        "titulo": "Cláusula 6: Planificación, Metodología de Riesgos y SoA",
        "clausulas": "6.1, 6.2, 6.3",
        "descripcion": "Enfoque metodológico unificado para valoración de riesgos en activos, IA y datos personales.",
        "campos": [
            {
                "id": "sgi_metodologia_riesgo",
                "label": "Metodología Integrada de Riesgos (ISO 31000 / ISO 27005)",
                "tipo": "textarea",
                "default": "Matriz de 5x5: Nivel de Riesgo = Probabilidad (1 a 5) x Impacto (1 a 5). Se evalúan impactos sobre la Confidencialidad, Integridad, Disponibilidad, Privacidad del Titular y Transparencia Algorítmica. Criterio de aceptación: Riesgos con puntaje igual o superior a 12 requieren plan de tratamiento obligatorio."
            },
            {
                "id": "sgi_objetivos_smart",
                "label": "Objetivos Estratégicos del SGI para el Período",
                "tipo": "textarea",
                "default": "1. Mantener el 100% de los controles del Anexo A de ISO 27001 implementados o con tratamiento antes de Q4.\n2. Completar las Evaluaciones de Impacto (EIPD) en el 100% de las bases de datos con información sensible.\n3. Asegurar que el 100% de los sistemas de IA cuenten con supervisión humana (Human-in-the-Loop) certificada.\n4. Lograr un 95% de aprobación en el programa anual de concientización sobre ciberseguridad."
            }
        ]
    },
    {
        "id": "sgi_clausula_7_8",
        "fase": "Fase 4: Soporte y Control Operacional",
        "titulo": "Cláusulas 7 y 8: Soporte, Concientización y Operación",
        "clausulas": "7.1 a 7.5, 8.1 a 8.3",
        "descripcion": "Gestión de recursos, competencias, control documental y ejecución de salvaguardas operacionales.",
        "campos": [
            {
                "id": "sgi_programa_concientizacion",
                "label": "Programa Anual de Concientización y Capacitación",
                "tipo": "textarea",
                "default": "Talleres trimestrales sobre prevención de phishing, manejo seguro de contraseñas, directrices de uso ético de modelos de lenguaje generativo y procedimiento de reporte de brechas de datos personales en menos de 72 horas."
            },
            {
                "id": "sgi_control_operacional",
                "label": "Procedimientos Operacionales Clave Implementados",
                "tipo": "textarea",
                "default": "• Procedimiento de Gestión de Cambios e Integración Continua (CI/CD Seguro).\n• Procedimiento de Copias de Respaldo Inmutables y Pruebas Periódicas de Restauración.\n• Procedimiento de Homologación y Evaluación de Seguridad en Proveedores y Cadena de Suministro."
            }
        ]
    },
    {
        "id": "sgi_clausula_9",
        "fase": "Fase 5: Evaluación del Desempeño y Auditoría",
        "titulo": "Cláusula 9: Auditoría Interna y Revisión por la Dirección",
        "clausulas": "9.1, 9.2, 9.3",
        "descripcion": "Medición cuantitativa del desempeño, programa de auditoría independiente e informe a la dirección.",
        "campos": [
            {
                "id": "sgi_plan_auditoria",
                "label": "Programa de Auditoría Interna Integrada (ISO 19011)",
                "tipo": "textarea",
                "default": "Auditoría interna semestral ejecutada por auditores certificados independientes del área evaluada. Alcance: Revisión de la aplicabilidad del Anexo A de ISO 27001, controles de IA (ISO 42001) y protocolos ARCOP de Ley 21.719."
            },
            {
                "id": "sgi_indicadores_kpi",
                "label": "Indicadores Clave de Desempeño del SGI (KPIs)",
                "tipo": "textarea",
                "default": "• Porcentaje de cumplimiento global de controles del SGI (Meta: >= 85%).\n• Tiempo medio de respuesta y resolución ante incidentes de seguridad (MTTR).\n• Número de solicitudes de derechos ARCOP resueltas dentro de los plazos legales.\n• Tasa de falsos positivos y desvíos de alineación en modelos de IA en producción."
            }
        ]
    },
    {
        "id": "sgi_clausula_10",
        "fase": "Fase 6: Mejora Continua y No Conformidades",
        "titulo": "Cláusula 10: No Conformidades y Acciones Correctivas",
        "clausulas": "10.1, 10.2",
        "descripcion": "Tratamiento sistemático de desvíos, análisis de causa raíz y cierre verificable de hallazgos.",
        "campos": [
            {
                "id": "sgi_gestion_nc",
                "label": "Procedimiento de Tratamiento de No Conformidades y Causa Raíz",
                "tipo": "textarea",
                "default": "Toda no conformidad identificada en auditorías internas o incidentes se registra en la bitácora centralizada. Se aplica análisis de causa raíz (Metodología de los 5 Porqués o Diagrama de Ishikawa), se formula un plan de acción correctiva con responsable y fecha límite, y se evalúa la eficacia de la acción a los 60 días."
            }
        ]
    }
]

def calcular_hash_sha256(texto: str) -> str:
    """Calcula el hash SHA-256 de una cadena de texto."""
    return hashlib.sha256(texto.encode("utf-8")).hexdigest()

def cargar_controles_completos(ruta_json_es: Path) -> List[Dict[str, Any]]:
    """Carga los 93 controles de ISO 27001:2022 en español y añade los controles complementarios."""
    with open(ruta_json_es, mode="r", encoding="utf-8") as f:
        controles_27001 = json.load(f)

    # Normalizar campos de ISO 27001
    for c in controles_27001:
        c["norma_id"] = "ISO_27001"
        c["status"] = c.get("status", "")
        c["owner"] = c.get("owner", "")
        c["evidence_notes"] = c.get("evidence_notes", "")
        cid_slug = c["control_id"].lower().replace(".", "-")
        c["guide_url"] = f"https://controlstack.au/controls/iso27001-annex-{cid_slug}/"

    todos = controles_27001 + CONTROLES_IA + CONTROLES_LEY_21719
    return todos

def generar_html_v2(controles: List[Dict[str, Any]], modulos_sgi: List[Dict[str, Any]], password_hash: str, title: str) -> str:
    """Genera la aplicación web monolítica V2 con separación estricta por pestañas de norma y módulo SGI."""
    controles_json = json.dumps(controles, ensure_ascii=False)
    modulos_sgi_json = json.dumps(modulos_sgi, ensure_ascii=False)
    catalogo_hash = calcular_hash_sha256(controles_json)

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        :root {{
            --bg-primary: #0b1329;
            --bg-secondary: #132247;
            --bg-card: #182b59;
            --bg-card-hover: #1f3770;
            --border-color: #264282;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent: #38bdf8;
            --accent-hover: #0284c7;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --neutral: #64748b;
            --font-stack: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            --radius-md: 10px;
            --radius-lg: 14px;
            --shadow-sm: 0 2px 4px rgba(0,0,0,0.3);
            --shadow-md: 0 6px 12px rgba(0,0,0,0.4);
        }}

        [data-theme="light"] {{
            --bg-primary: #f8fafc;
            --bg-secondary: #ffffff;
            --bg-card: #ffffff;
            --bg-card-hover: #f1f5f9;
            --border-color: #cbd5e1;
            --text-primary: #0f172a;
            --text-secondary: #475569;
            --text-muted: #94a3b8;
            --accent: #0284c7;
            --accent-hover: #0369a1;
            --shadow-sm: 0 1px 3px rgba(0,0,0,0.08);
            --shadow-md: 0 4px 8px rgba(0,0,0,0.12);
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: var(--font-stack);
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.5;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            transition: background-color 0.2s ease, color 0.2s ease;
        }}

        /* Header Principal */
        header {{
            background-color: var(--bg-secondary);
            border-bottom: 2px solid var(--border-color);
            padding: 0.85rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
            position: sticky;
            top: 0;
            z-index: 50;
            box-shadow: var(--shadow-sm);
        }}

        .brand {{
            display: flex;
            align-items: center;
            gap: 0.85rem;
        }}

        .brand-logo {{
            width: 38px;
            height: 38px;
            background: linear-gradient(135deg, #0ea5e9, #2563eb);
            border-radius: 9px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #ffffff;
            font-weight: 800;
            font-size: 1.15rem;
            box-shadow: 0 2px 5px rgba(14, 165, 233, 0.4);
        }}

        .brand-info h1 {{
            font-size: 1.25rem;
            font-weight: 700;
            letter-spacing: -0.02em;
        }}

        .brand-info p {{
            font-size: 0.78rem;
            color: var(--text-secondary);
        }}

        .header-actions {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            flex-wrap: wrap;
        }}

        .btn {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 0.45rem 0.85rem;
            border-radius: var(--radius-md);
            font-size: 0.84rem;
            font-weight: 600;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
            transition: all 0.15s ease;
        }}

        .btn:hover {{
            background-color: var(--bg-card-hover);
            border-color: var(--accent);
        }}

        .btn-primary {{
            background-color: var(--accent);
            color: #0b1329;
            border-color: var(--accent);
            font-weight: 700;
        }}

        .btn-primary:hover {{
            background-color: var(--accent-hover);
            color: #ffffff;
        }}

        .btn-danger {{
            background-color: rgba(239, 68, 68, 0.15);
            color: var(--danger);
            border-color: rgba(239, 68, 68, 0.3);
        }}

        .btn-danger:hover {{
            background-color: var(--danger);
            color: #ffffff;
        }}

        .lock-indicator {{
            display: flex;
            align-items: center;
            gap: 0.4rem;
            font-size: 0.82rem;
            padding: 0.35rem 0.75rem;
            border-radius: 9999px;
            font-weight: 600;
        }}

        .locked {{
            background-color: rgba(245, 158, 11, 0.15);
            color: var(--warning);
            border: 1px solid rgba(245, 158, 11, 0.3);
        }}

        .unlocked {{
            background-color: rgba(16, 185, 129, 0.15);
            color: var(--success);
            border: 1px solid rgba(16, 185, 129, 0.3);
        }}

        /* Pestañas de Nivel 1 (Normas y SGI) */
        .norma-nav {{
            background-color: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            padding: 0 2rem;
            display: flex;
            gap: 0.5rem;
            overflow-x: auto;
            scrollbar-width: thin;
        }}

        .norma-tab-btn {{
            background: none;
            border: none;
            border-bottom: 3px solid transparent;
            color: var(--text-secondary);
            padding: 0.85rem 1.1rem;
            font-size: 0.92rem;
            font-weight: 700;
            cursor: pointer;
            white-space: nowrap;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            transition: all 0.15s ease;
        }}

        .norma-tab-btn:hover {{
            color: var(--text-primary);
            background-color: rgba(255, 255, 255, 0.03);
        }}

        .norma-tab-btn.active {{
            color: var(--accent);
            border-bottom-color: var(--accent);
        }}

        /* Contenedor Principal */
        main {{
            max-width: 1440px;
            margin: 0 auto;
            padding: 1.5rem 2rem;
            width: 100%;
            flex: 1;
        }}

        /* Métricas y KPIs */
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }}

        .metric-card {{
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            padding: 1.15rem;
            display: flex;
            flex-direction: column;
            gap: 0.35rem;
            box-shadow: var(--shadow-sm);
        }}

        .metric-label {{
            font-size: 0.78rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-weight: 700;
        }}

        .metric-value {{
            font-size: 1.9rem;
            font-weight: 800;
            line-height: 1.1;
        }}

        .progress-bar-container {{
            width: 100%;
            height: 8px;
            background-color: var(--border-color);
            border-radius: 9999px;
            overflow: hidden;
            margin-top: 0.35rem;
        }}

        .progress-bar-fill {{
            height: 100%;
            background: linear-gradient(90deg, #10b981, #38bdf8);
            border-radius: 9999px;
            transition: width 0.3s ease;
        }}

        /* Barra de Herramientas y Filtros Sub-temáticos */
        .controls-toolbar {{
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            padding: 1rem;
            margin-bottom: 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 0.85rem;
            box-shadow: var(--shadow-sm);
        }}

        .search-row {{
            display: flex;
            gap: 0.75rem;
            flex-wrap: wrap;
        }}

        .search-input {{
            flex: 1;
            min-width: 280px;
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 0.55rem 1rem;
            border-radius: var(--radius-md);
            font-size: 0.9rem;
            outline: none;
            transition: border-color 0.15s ease;
        }}

        .search-input:focus {{
            border-color: var(--accent);
        }}

        .subtheme-tabs {{
            display: flex;
            gap: 0.4rem;
            overflow-x: auto;
            padding-bottom: 0.25rem;
            scrollbar-width: thin;
        }}

        .subtab-btn {{
            background-color: transparent;
            border: 1px solid transparent;
            color: var(--text-secondary);
            padding: 0.4rem 0.8rem;
            border-radius: var(--radius-md);
            font-size: 0.82rem;
            font-weight: 600;
            cursor: pointer;
            white-space: nowrap;
            transition: all 0.15s ease;
        }}

        .subtab-btn:hover {{
            background-color: var(--bg-card-hover);
            color: var(--text-primary);
        }}

        .subtab-btn.active {{
            background-color: var(--bg-card-hover);
            color: var(--accent);
            border-color: var(--border-color);
        }}

        /* Tarjetas de Controles */
        .checklist-container {{
            display: flex;
            flex-direction: column;
            gap: 0.85rem;
        }}

        .control-card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            padding: 1.25rem;
            display: flex;
            flex-direction: column;
            gap: 0.85rem;
            box-shadow: var(--shadow-sm);
            transition: border-color 0.15s ease, background-color 0.15s ease;
        }}

        .control-card:hover {{
            border-color: var(--accent);
            background-color: var(--bg-card-hover);
        }}

        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 1rem;
            flex-wrap: wrap;
        }}

        .card-title-group {{
            display: flex;
            align-items: baseline;
            gap: 0.6rem;
            flex-wrap: wrap;
            flex: 1;
        }}

        .control-badge {{
            font-size: 0.86rem;
            font-weight: 800;
            padding: 0.2rem 0.55rem;
            border-radius: 6px;
            background-color: rgba(56, 189, 248, 0.15);
            color: var(--accent);
            border: 1px solid rgba(56, 189, 248, 0.3);
            font-family: monospace;
        }}

        .theme-badge {{
            font-size: 0.72rem;
            font-weight: 700;
            padding: 0.2rem 0.55rem;
            border-radius: 6px;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }}

        .control-name {{
            font-size: 1.05rem;
            font-weight: 700;
            color: var(--text-primary);
            flex: 1;
            min-width: 250px;
        }}

        .control-desc {{
            font-size: 0.88rem;
            color: var(--text-secondary);
            line-height: 1.5;
            background-color: rgba(0, 0, 0, 0.15);
            padding: 0.75rem 1rem;
            border-radius: var(--radius-md);
            border-left: 3px solid var(--border-color);
        }}

        .card-form-grid {{
            display: grid;
            grid-template-columns: 210px 230px 1fr;
            gap: 0.85rem;
            align-items: flex-start;
        }}

        @media (max-width: 960px) {{
            .card-form-grid {{
                grid-template-columns: 1fr;
            }}
        }}

        .field-group {{
            display: flex;
            flex-direction: column;
            gap: 0.35rem;
        }}

        .field-label {{
            font-size: 0.74rem;
            font-weight: 700;
            color: var(--text-muted);
            text-transform: uppercase;
        }}

        .select-status {{
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 0.5rem 0.65rem;
            border-radius: var(--radius-md);
            font-size: 0.85rem;
            font-weight: 700;
            outline: none;
            cursor: pointer;
        }}

        .select-status[data-status="Implementado"] {{
            border-color: var(--success);
            color: var(--success);
        }}

        .select-status[data-status="En progreso"] {{
            border-color: var(--warning);
            color: var(--warning);
        }}

        .select-status[data-status="No implementado"] {{
            border-color: var(--danger);
            color: var(--danger);
        }}

        .select-status[data-status="No aplica"] {{
            border-color: var(--neutral);
            color: var(--neutral);
        }}

        .text-input, .textarea-input {{
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 0.5rem 0.75rem;
            border-radius: var(--radius-md);
            font-size: 0.85rem;
            outline: none;
            width: 100%;
        }}

        .text-input:focus, .textarea-input:focus, .select-status:focus {{
            border-color: var(--accent);
        }}

        .textarea-input {{
            resize: vertical;
            min-height: 42px;
            height: 42px;
            font-family: inherit;
        }}

        .card-footer {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.78rem;
            color: var(--text-muted);
            border-top: 1px solid var(--border-color);
            padding-top: 0.6rem;
            margin-top: 0.2rem;
        }}

        .guide-link {{
            color: var(--accent);
            text-decoration: none;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 0.25rem;
        }}

        .guide-link:hover {{
            text-decoration: underline;
        }}

        /* Sección SGI (Sistema de Gestión Integrado) */
        .sgi-container {{
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
        }}

        .sgi-hero {{
            background: linear-gradient(135deg, var(--bg-secondary), var(--bg-card));
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            padding: 1.75rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }}

        .sgi-hero-text h2 {{
            font-size: 1.4rem;
            font-weight: 800;
            margin-bottom: 0.35rem;
        }}

        .sgi-hero-text p {{
            font-size: 0.9rem;
            color: var(--text-secondary);
            max-width: 850px;
        }}

        .sgi-module-card {{
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 1.1rem;
            box-shadow: var(--shadow-sm);
        }}

        .sgi-module-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            flex-wrap: wrap;
            gap: 0.5rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 0.75rem;
        }}

        .sgi-module-header h3 {{
            font-size: 1.15rem;
            font-weight: 700;
        }}

        .sgi-fase-badge {{
            font-size: 0.75rem;
            font-weight: 800;
            padding: 0.25rem 0.65rem;
            border-radius: 9999px;
            background-color: rgba(56, 189, 248, 0.15);
            color: var(--accent);
            border: 1px solid rgba(56, 189, 248, 0.3);
        }}

        .sgi-fields-grid {{
            display: grid;
            grid-template-columns: 1fr;
            gap: 1rem;
        }}

        .sgi-textarea {{
            min-height: 80px;
            height: 90px;
        }}

        /* Modal de Autenticación */
        .modal-overlay {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.7);
            backdrop-filter: blur(4px);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 100;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.2s ease;
        }}

        .modal-overlay.active {{
            opacity: 1;
            pointer-events: auto;
        }}

        .modal-box {{
            background-color: var(--bg-secondary);
            border: 2px solid var(--border-color);
            border-radius: var(--radius-lg);
            padding: 1.85rem;
            max-width: 440px;
            width: 90%;
            box-shadow: var(--shadow-md);
            display: flex;
            flex-direction: column;
            gap: 1.1rem;
        }}

        .modal-header h3 {{
            font-size: 1.2rem;
            font-weight: 800;
        }}

        .modal-body p {{
            font-size: 0.88rem;
            color: var(--text-secondary);
            margin-bottom: 0.75rem;
            line-height: 1.5;
        }}

        .modal-footer {{
            display: flex;
            justify-content: flex-end;
            gap: 0.5rem;
        }}

        /* Estilos de Impresión Ejecutiva */
        @media print {{
            header, .norma-nav, .controls-toolbar, .btn, .modal-overlay, .guide-link, .sgi-hero .btn {{
                display: none !important;
            }}
            body {{
                background: #ffffff !important;
                color: #000000 !important;
            }}
            .control-card, .sgi-module-card {{
                border: 1px solid #999999 !important;
                background: #ffffff !important;
                color: #000000 !important;
                page-break-inside: avoid;
                margin-bottom: 1.2rem;
            }}
            .progress-bar-container {{
                border: 1px solid #666666;
            }}
            .control-desc {{
                background: #f1f5f9 !important;
                color: #000000 !important;
                border-left-color: #0284c7 !important;
            }}
        }}
    </style>
</head>
<body data-theme="dark">

    <!-- Header Principal -->
    <header>
        <div class="brand">
            <div class="brand-logo">SGI</div>
            <div class="brand-info">
                <h1>{title}</h1>
                <p>ISO/IEC 27001:2022 • ISO/IEC 42001 (IA) • Ley N° 21.719 • Sistema de Gestión Integrado</p>
            </div>
        </div>

        <div class="header-actions">
            <div id="lockBadge" class="lock-indicator locked">
                <span>🔒 Modo Auditoría (Lectura)</span>
            </div>
            <button id="btnToggleLock" class="btn btn-primary" onclick="alternarModalBloqueo()">Desbloquear Edición</button>
            <button class="btn" onclick="exportarAuditoriaJSON()">📥 Exportar Auditoría JSON</button>
            <button class="btn" onclick="document.getElementById('fileInput').click()">📤 Importar JSON</button>
            <input type="file" id="fileInput" style="display:none" accept=".json" onchange="importarAuditoriaJSON(event)">
            <button class="btn" onclick="window.print()">🖨️ Imprimir / Guardar PDF</button>
            <button class="btn" onclick="alternarTema()" title="Cambiar tema">🌓</button>
        </div>
    </header>

    <!-- Navegación de Nivel 1: Pestañas Principales por Norma y SGI -->
    <nav class="norma-nav">
        <button class="norma-tab-btn active" onclick="seleccionarNorma('ISO_27001', this)">
            <span>🛡️ ISO/IEC 27001:2022 (Seguridad)</span>
            <span class="control-badge" id="badgeCount27001">93</span>
        </button>
        <button class="norma-tab-btn" onclick="seleccionarNorma('ISO_42001', this)">
            <span>🤖 ISO/IEC 42001 & 27090 (Inteligencia Artificial)</span>
            <span class="control-badge" id="badgeCount42001">6</span>
        </button>
        <button class="norma-tab-btn" onclick="seleccionarNorma('LEY_21719', this)">
            <span>🔒 Ley N° 21.719 (Protección de Datos)</span>
            <span class="control-badge" id="badgeCount21719">6</span>
        </button>
        <button class="norma-tab-btn" onclick="seleccionarNorma('SGI_CREACION', this)">
            <span>🏛️ Creación del Sistema de Gestión Integrado (SGI)</span>
            <span class="control-badge">Fases 1-6</span>
        </button>
    </nav>

    <!-- Contenedor Dinámico Principal -->
    <main>
        <!-- Vista 1: Controles de Normas (Checklists) -->
        <div id="viewChecklist">
            <!-- Métricas y KPIs de la norma activa -->
            <section class="metrics-grid">
                <div class="metric-card">
                    <span class="metric-label">Cumplimiento de la Norma</span>
                    <span id="metricPercent" class="metric-value" style="color: var(--accent);">0%</span>
                    <div class="progress-bar-container">
                        <div id="progressBar" class="progress-bar-fill" style="width: 0%;"></div>
                    </div>
                </div>
                <div class="metric-card">
                    <span class="metric-label">Implementados</span>
                    <span id="metricImplemented" class="metric-value" style="color: var(--success);">0</span>
                    <span class="metric-label" id="metricTotalControls">de 0 aplicables</span>
                </div>
                <div class="metric-card">
                    <span class="metric-label">En Progreso</span>
                    <span id="metricInProgress" class="metric-value" style="color: var(--warning);">0</span>
                    <span class="metric-label">planes de tratamiento</span>
                </div>
                <div class="metric-card">
                    <span class="metric-label">No Implementados</span>
                    <span id="metricNotImplemented" class="metric-value" style="color: var(--danger);">0</span>
                    <span class="metric-label">brechas detectadas</span>
                </div>
                <div class="metric-card">
                    <span class="metric-label">No Aplica (Justificados)</span>
                    <span id="metricNotApplicable" class="metric-value" style="color: var(--neutral);">0</span>
                    <span class="metric-label">exclusiones en SoA</span>
                </div>
            </section>

            <!-- Barra de Búsqueda y Sub-filtros -->
            <section class="controls-toolbar">
                <div class="search-row">
                    <input type="text" id="searchInput" class="search-input" placeholder="🔍 Buscar por código (ej. A.5.1, IA.1.2), nombre, responsable o evidencia..." oninput="filtrarControles()">
                    <select id="statusFilter" class="select-status" style="width: auto;" onchange="filtrarControles()">
                        <option value="TODOS">Todos los Estados</option>
                        <option value="Implementado">Implementado</option>
                        <option value="En progreso">En progreso</option>
                        <option value="No implementado">No implementado</option>
                        <option value="No aplica">No aplica</option>
                        <option value="SIN_EVALUAR">Sin evaluar</option>
                    </select>
                </div>

                <!-- Sub-pestañas temáticas para ISO 27001 -->
                <div class="subtheme-tabs" id="subthemeTabs">
                    <button class="subtab-btn active" onclick="cambiarSubtema('TODOS', this)">Todos los Controles (<span id="countSubAll">0</span>)</button>
                    <button class="subtab-btn" onclick="cambiarSubtema('Organizacional', this)">Organizacional A.5 (<span id="countSubOrg">0</span>)</button>
                    <button class="subtab-btn" onclick="cambiarSubtema('Personas', this)">Personas A.6 (<span id="countSubPeople">0</span>)</button>
                    <button class="subtab-btn" onclick="cambiarSubtema('Fisico', this)">Físico A.7 (<span id="countSubPhysical">0</span>)</button>
                    <button class="subtab-btn" onclick="cambiarSubtema('Tecnologico', this)">Tecnológico A.8 (<span id="countSubTech">0</span>)</button>
                </div>
            </section>

            <!-- Listado de Tarjetas de Controles -->
            <section class="checklist-container" id="checklistContainer">
                <!-- Generado dinámicamente -->
            </section>
        </div>

        <!-- Vista 2: Creación del Sistema de Gestión Integrado (SGI) -->
        <div id="viewSGI" style="display: none;">
            <div class="sgi-container">
                <div class="sgi-hero">
                    <div class="sgi-hero-text">
                        <h2>🏛️ Sistema de Gestión Integrado (SGI)</h2>
                        <p>Plataforma para estructurar, formalizar y mantener el Sistema de Gestión Integrado conforme a la Estructura de Alto Nivel (Anexo SL): Contexto, Liderazgo, Planificación, Soporte, Operación, Auditoría y Mejora Continua para Ciberseguridad (ISO 27001), Inteligencia Artificial (ISO 42001) y Privacidad de Datos (Ley 21.719).</p>
                    </div>
                    <button class="btn btn-primary" onclick="exportarActaSGI()">📄 Descargar Acta y Manual del SGI</button>
                </div>

                <!-- Módulos de Cláusulas 4 a 10 -->
                <div id="sgiModulesContainer" style="display: flex; flex-direction: column; gap: 1.25rem;">
                    <!-- Inyectado dinámicamente -->
                </div>
            </div>
        </div>
    </main>

    <!-- Modal de Desbloqueo / Clave Maestra -->
    <div class="modal-overlay" id="lockModal">
        <div class="modal-box">
            <div class="modal-header">
                <h3>Desbloquear Modo de Edición</h3>
            </div>
            <div class="modal-body">
                <p>El aplicativo opera en <strong>Modo Auditoría Protegido</strong> para garantizar la integridad de las evaluaciones y el modelo del SGI.</p>
                <p>Ingresa la clave maestra para habilitar la edición de estados, responsables, evidencias y campos del SGI:</p>
                <input type="password" id="passwordInput" class="text-input" placeholder="Contraseña de administrador..." onkeydown="if(event.key==='Enter') autenticarEdicion()">
                <div id="authErrorMsg" style="color: var(--danger); font-size: 0.82rem; margin-top: 0.5rem; display: none;">Contraseña incorrecta. Acceso denegado.</div>
            </div>
            <div class="modal-footer">
                <button class="btn" onclick="alternarModalBloqueo()">Cancelar</button>
                <button class="btn btn-primary" onclick="autenticarEdicion()">Autenticar</button>
            </div>
        </div>
    </div>

    <!-- Script de Lógica Reactiva, Criptografía y Persistencia -->
    <script>
        // Datos Canónicos
        const HASH_CLAVE_MAESTRA = "{password_hash}";
        const CATALOGO_HASH = "{catalogo_hash}";
        const CONTROLES_CANONICOS = {controles_json};
        const MODULOS_SGI_CANONICOS = {modulos_sgi_json};

        // Estado en Memoria
        let controles = [];
        let datosSGI = {{}};
        let normaActiva = "ISO_27001";
        let subtemaActivo = "TODOS";
        let busquedaActiva = "";
        let filtroEstadoActivo = "TODOS";
        let modoEdicion = false;

        const STORAGE_CONTROLES = "sgi_controles_estado_v2";
        const STORAGE_SGI_DATA = "sgi_modulos_documentacion_v2";
        const STORAGE_AUTH = "sgi_sesion_autenticada";

        // Inicialización
        window.addEventListener("DOMContentLoaded", () => {{
            cargarPersistencia();
            actualizarMetricas();
            renderizarControles();
            renderizarModulosSGI();
        }});

        function cargarPersistencia() {{
            // Cargar estado de controles
            const savedControles = localStorage.getItem(STORAGE_CONTROLES);
            if (savedControles) {{
                try {{
                    const parsed = JSON.parse(savedControles);
                    controles = CONTROLES_CANONICOS.map(c => {{
                        const match = parsed.find(p => p.control_id === c.control_id);
                        if (match) {{
                            return {{
                                ...c,
                                status: match.status || "",
                                owner: match.owner || "",
                                evidence_notes: match.evidence_notes || ""
                            }};
                        }}
                        return {{ ...c }};
                    }});
                }} catch (e) {{
                    controles = JSON.parse(JSON.stringify(CONTROLES_CANONICOS));
                }}
            }} else {{
                controles = JSON.parse(JSON.stringify(CONTROLES_CANONICOS));
            }}

            // Cargar datos del SGI
            const savedSGI = localStorage.getItem(STORAGE_SGI_DATA);
            if (savedSGI) {{
                try {{
                    datosSGI = JSON.parse(savedSGI);
                }} catch (e) {{
                    datosSGI = {{}};
                }}
            }}

            // Inicializar defaults de SGI si no existen
            MODULOS_SGI_CANONICOS.forEach(mod => {{
                mod.campos.forEach(campo => {{
                    if (datosSGI[campo.id] === undefined) {{
                        datosSGI[campo.id] = campo.default;
                    }}
                }});
            }});

            if (sessionStorage.getItem(STORAGE_AUTH) === "true") {{
                activarModoEdicion();
            }}
        }}

        function guardarPersistencia() {{
            if (!modoEdicion) return;
            const simplificado = controles.map(c => ({{
                control_id: c.control_id,
                status: c.status,
                owner: c.owner,
                evidence_notes: c.evidence_notes
            }}));
            localStorage.setItem(STORAGE_CONTROLES, JSON.stringify(simplificado));
            localStorage.setItem(STORAGE_SGI_DATA, JSON.stringify(datosSGI));
        }}

        async function sha256(str) {{
            const buffer = new TextEncoder().encode(str);
            const digest = await crypto.subtle.digest("SHA-256", buffer);
            return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("");
        }}

        // Control de Modos y Seguridad
        function alternarModalBloqueo() {{
            if (modoEdicion) {{
                bloquearModoEdicion();
                return;
            }}
            const modal = document.getElementById("lockModal");
            const input = document.getElementById("passwordInput");
            const err = document.getElementById("authErrorMsg");
            err.style.display = "none";
            input.value = "";
            modal.classList.toggle("active");
            if (modal.classList.contains("active")) {{
                setTimeout(() => input.focus(), 100);
            }}
        }}

        async function autenticarEdicion() {{
            const input = document.getElementById("passwordInput");
            const err = document.getElementById("authErrorMsg");
            const typedHash = await sha256(input.value.trim());

            if (typedHash === HASH_CLAVE_MAESTRA) {{
                sessionStorage.setItem(STORAGE_AUTH, "true");
                activarModoEdicion();
                document.getElementById("lockModal").classList.remove("active");
            }} else {{
                err.style.display = "block";
                input.select();
            }}
        }}

        function activarModoEdicion() {{
            modoEdicion = true;
            const badge = document.getElementById("lockBadge");
            const btn = document.getElementById("btnToggleLock");
            badge.className = "lock-indicator unlocked";
            badge.innerHTML = "<span>🔓 Edición Habilitada</span>";
            btn.textContent = "Bloquear Edición";
            btn.className = "btn btn-danger";
            renderizarControles();
            renderizarModulosSGI();
        }}

        function bloquearModoEdicion() {{
            modoEdicion = false;
            sessionStorage.removeItem(STORAGE_AUTH);
            const badge = document.getElementById("lockBadge");
            const btn = document.getElementById("btnToggleLock");
            badge.className = "lock-indicator locked";
            badge.innerHTML = "<span>🔒 Modo Auditoría (Lectura)</span>";
            btn.textContent = "Desbloquear Edición";
            btn.className = "btn btn-primary";
            renderizarControles();
            renderizarModulosSGI();
        }}

        // Navegación por Norma y SGI
        function seleccionarNorma(norma, btn) {{
            normaActiva = norma;
            subtemaActivo = "TODOS";
            document.querySelectorAll(".norma-tab-btn").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");

            const viewChecklist = document.getElementById("viewChecklist");
            const viewSGI = document.getElementById("viewSGI");
            const subthemeTabs = document.getElementById("subthemeTabs");

            if (norma === "SGI_CREACION") {{
                viewChecklist.style.display = "none";
                viewSGI.style.display = "block";
            }} else {{
                viewChecklist.style.display = "block";
                viewSGI.style.display = "none";

                // Mostrar sub-pestañas temáticas solo para ISO 27001
                if (norma === "ISO_27001") {{
                    subthemeTabs.style.display = "flex";
                }} else {{
                    subthemeTabs.style.display = "none";
                }}

                document.querySelectorAll(".subtab-btn").forEach(b => b.classList.remove("active"));
                if (subthemeTabs.firstElementChild) {{
                    subthemeTabs.firstElementChild.classList.add("active");
                }}

                actualizarMetricas();
                renderizarControles();
            }}
        }}

        function cambiarSubtema(subtema, btn) {{
            subtemaActivo = subtema;
            document.querySelectorAll(".subtab-btn").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            renderizarControles();
        }}

        function filtrarControles() {{
            busquedaActiva = document.getElementById("searchInput").value.trim().toLowerCase();
            filtroEstadoActivo = document.getElementById("statusFilter").value;
            renderizarControles();
        }}

        // Renderizado de Controles
        function renderizarControles() {{
            const container = document.getElementById("checklistContainer");
            container.innerHTML = "";

            const filtrados = controles.filter(c => {{
                // Filtrar por norma activa
                if (c.norma_id !== normaActiva) return false;

                // Filtrar por subtema en ISO 27001
                if (normaActiva === "ISO_27001" && subtemaActivo !== "TODOS") {{
                    if (c.theme !== subtemaActivo) return false;
                }}

                // Filtrar por estado
                if (filtroEstadoActivo !== "TODOS") {{
                    if (filtroEstadoActivo === "SIN_EVALUAR" && c.status) return false;
                    if (filtroEstadoActivo !== "SIN_EVALUAR" && c.status !== filtroEstadoActivo) return false;
                }}

                // Búsqueda
                if (busquedaActiva) {{
                    const mId = c.control_id.toLowerCase().includes(busquedaActiva);
                    const mName = c.control_name.toLowerCase().includes(busquedaActiva);
                    const mDesc = c.description.toLowerCase().includes(busquedaActiva);
                    const mOwner = (c.owner || "").toLowerCase().includes(busquedaActiva);
                    const mEv = (c.evidence_notes || "").toLowerCase().includes(busquedaActiva);
                    if (!mId && !mName && !mDesc && !mOwner && !mEv) return false;
                }}

                return true;
            }});

            if (filtrados.length === 0) {{
                container.innerHTML = `<div style="text-align: center; padding: 3rem; background: var(--bg-card); border-radius: var(--radius-lg); border: 1px solid var(--border-color); color: var(--text-muted);">
                    <p style="font-size: 1.1rem; font-weight: 700;">No se encontraron controles con los filtros seleccionados.</p>
                    <p style="font-size: 0.85rem; margin-top: 0.35rem;">Ajuste el texto de búsqueda o el filtro de estado.</p>
                </div>`;
                return;
            }}

            const fragment = document.createDocumentFragment();

            filtrados.forEach(c => {{
                const card = document.createElement("div");
                card.className = "control-card";
                card.id = `card-${{c.control_id}}`;

                const colorTema = obtenerColorTema(c.theme);

                card.innerHTML = `
                    <div class="card-header">
                        <div class="card-title-group">
                            <span class="control-badge">${{c.control_id}}</span>
                            <span class="theme-badge" style="background: ${{colorTema}}22; color: ${{colorTema}}; border: 1px solid ${{colorTema}}44;">${{c.theme}}</span>
                            <h2 class="control-name">${{c.control_name}}</h2>
                        </div>
                    </div>

                    <div class="control-desc">${{c.description}}</div>

                    <div class="card-form-grid">
                        <div class="field-group">
                            <label class="field-label">Estado de Cumplimiento</label>
                            <select class="select-status" data-status="${{c.status || ''}}" ${{modoEdicion ? '' : 'disabled'}} onchange="actualizarEstado('${{c.control_id}}', this.value, this)">
                                <option value="" ${{!c.status ? 'selected' : ''}}>-- Sin evaluar --</option>
                                <option value="Implementado" ${{c.status === 'Implementado' ? 'selected' : ''}}>✅ Implementado</option>
                                <option value="En progreso" ${{c.status === 'En progreso' ? 'selected' : ''}}>⏳ En progreso</option>
                                <option value="No implementado" ${{c.status === 'No implementado' ? 'selected' : ''}}>❌ No implementado</option>
                                <option value="No aplica" ${{c.status === 'No aplica' ? 'selected' : ''}}>⚪ No aplica (Justificado)</option>
                            </select>
                        </div>

                        <div class="field-group">
                            <label class="field-label">Responsable Asignado</label>
                            <input type="text" class="text-input" placeholder="Nombre o cargo del custodio..." value="${{escapeHtml(c.owner || '')}}" ${{modoEdicion ? '' : 'disabled'}} onchange="actualizarOwner('${{c.control_id}}', this.value)">
                        </div>

                        <div class="field-group">
                            <label class="field-label">Evidencias y Notas de Auditoría</label>
                            <textarea class="textarea-input" placeholder="Referencia a políticas, registros, actas o justificación..." ${{modoEdicion ? '' : 'disabled'}} onchange="actualizarEvidencias('${{c.control_id}}', this.value)">${{escapeHtml(c.evidence_notes || '')}}</textarea>
                        </div>
                    </div>

                    <div class="card-footer">
                        <span>Marco Normativo: <strong>${{c.norma}}</strong></span>
                        ${{c.guide_url ? `<a href="${{c.guide_url}}" target="_blank" rel="noopener noreferrer" class="guide-link">Guía Técnica de Implementación ↗</a>` : ''}}
                    </div>
                `;

                fragment.appendChild(card);
            }});

            container.appendChild(fragment);
        }}

        function escapeHtml(str) {{
            return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
        }}

        function obtenerColorTema(theme) {{
            const map = {{
                "Organizacional": "#38bdf8",
                "Personas": "#10b981",
                "Fisico": "#f59e0b",
                "Tecnologico": "#a855f7",
                "Gobernanza IA": "#06b6d4",
                "Privacidad y Datos": "#f43f5e"
            }};
            return map[theme] || "#38bdf8";
        }}

        // Mutaciones de Estado de Controles
        function actualizarEstado(cid, val, sel) {{
            const item = controles.find(c => c.control_id === cid);
            if (item) {{
                item.status = val;
                sel.setAttribute("data-status", val);
                guardarPersistencia();
                actualizarMetricas();
            }}
        }}

        function actualizarOwner(cid, val) {{
            const item = controles.find(c => c.control_id === cid);
            if (item) {{
                item.owner = val.trim();
                guardarPersistencia();
            }}
        }}

        function actualizarEvidencias(cid, val) {{
            const item = controles.find(c => c.control_id === cid);
            if (item) {{
                item.evidence_notes = val.trim();
                guardarPersistencia();
            }}
        }}

        // Renderizado del Módulo SGI
        function renderizarModulosSGI() {{
            const container = document.getElementById("sgiModulesContainer");
            container.innerHTML = "";

            MODULOS_SGI_CANONICOS.forEach(mod => {{
                const card = document.createElement("div");
                card.className = "sgi-module-card";

                let fieldsHtml = "";
                mod.campos.forEach(campo => {{
                    const val = datosSGI[campo.id] || campo.default;
                    if (campo.tipo === "textarea") {{
                        fieldsHtml += `
                            <div class="field-group">
                                <label class="field-label">${{campo.label}}</label>
                                <textarea class="textarea-input sgi-textarea" ${{modoEdicion ? '' : 'disabled'}} onchange="actualizarCampoSGI('${{campo.id}}', this.value)">${{escapeHtml(val)}}</textarea>
                            </div>
                        `;
                    }} else {{
                        fieldsHtml += `
                            <div class="field-group">
                                <label class="field-label">${{campo.label}}</label>
                                <input type="text" class="text-input" value="${{escapeHtml(val)}}" ${{modoEdicion ? '' : 'disabled'}} onchange="actualizarCampoSGI('${{campo.id}}', this.value)">
                            </div>
                        `;
                    }}
                }});

                card.innerHTML = `
                    <div class="sgi-module-header">
                        <div>
                            <span class="sgi-fase-badge">${{mod.fase}}</span>
                            <h3 style="margin-top: 0.35rem;">${{mod.titulo}}</h3>
                            <p style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 0.2rem;">${{mod.descripcion}}</p>
                        </div>
                    </div>
                    <div class="sgi-fields-grid">
                        ${{fieldsHtml}}
                    </div>
                `;

                container.appendChild(card);
            }});
        }}

        function actualizarCampoSGI(campoId, val) {{
            datosSGI[campoId] = val.trim();
            guardarPersistencia();
        }}

        // Cálculo de Métricas y KPIs por Norma
        function actualizarMetricas() {{
            const normaControles = controles.filter(c => c.norma_id === normaActiva);
            const total = normaControles.length;
            const implemented = normaControles.filter(c => c.status === "Implementado").length;
            const inProgress = normaControles.filter(c => c.status === "En progreso").length;
            const notImplemented = normaControles.filter(c => c.status === "No implementado").length;
            const notApplicable = normaControles.filter(c => c.status === "No aplica").length;

            const aplicables = total - notApplicable;
            const percent = aplicables > 0 ? Math.round((implemented / aplicables) * 100) : 0;

            document.getElementById("metricPercent").textContent = `${{percent}}%`;
            document.getElementById("progressBar").style.width = `${{percent}}%`;
            document.getElementById("metricImplemented").textContent = implemented;
            document.getElementById("metricTotalControls").textContent = `de ${{aplicables}} aplicables (${{total}} total)`;
            document.getElementById("metricInProgress").textContent = inProgress;
            document.getElementById("metricNotImplemented").textContent = notImplemented;
            document.getElementById("metricNotApplicable").textContent = notApplicable;

            // Contadores en sub-pestañas de ISO 27001
            if (normaActiva === "ISO_27001") {{
                document.getElementById("countSubAll").textContent = total;
                document.getElementById("countSubOrg").textContent = normaControles.filter(c => c.theme === "Organizacional").length;
                document.getElementById("countSubPeople").textContent = normaControles.filter(c => c.theme === "Personas").length;
                document.getElementById("countSubPhysical").textContent = normaControles.filter(c => c.theme === "Fisico").length;
                document.getElementById("countSubTech").textContent = normaControles.filter(c => c.theme === "Tecnologico").length;
            }}
        }}

        function alternarTema() {{
            const current = document.body.getAttribute("data-theme");
            document.body.setAttribute("data-theme", current === "dark" ? "light" : "dark");
        }}

        // Exportación / Importación
        function exportarAuditoriaJSON() {{
            const exportData = {{
                proyecto: "{title}",
                fecha_exportacion: new Date().toISOString(),
                estadisticas: {{
                    total_controles: controles.length,
                    implementados: controles.filter(c => c.status === "Implementado").length,
                    en_progreso: controles.filter(c => c.status === "En progreso").length,
                    no_implementados: controles.filter(c => c.status === "No implementado").length,
                    no_aplica: controles.filter(c => c.status === "No aplica").length
                }},
                controles: controles,
                sistema_gestion_integrado: datosSGI
            }};

            const blob = new Blob([JSON.stringify(exportData, null, 2)], {{ type: "application/json" }});
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `auditoria_sgi_iso_${{new Date().toISOString().slice(0,10)}}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }}

        function importarAuditoriaJSON(event) {{
            const file = event.target.files[0];
            if (!file) return;

            const reader = new FileReader();
            reader.onload = (e) => {{
                try {{
                    const parsed = JSON.parse(e.target.result);
                    if (parsed.controles && Array.isArray(parsed.controles)) {{
                        controles = CONTROLES_CANONICOS.map(c => {{
                            const match = parsed.controles.find(p => p.control_id === c.control_id);
                            if (match) {{
                                return {{
                                    ...c,
                                    status: match.status || "",
                                    owner: match.owner || "",
                                    evidence_notes: match.evidence_notes || ""
                                }};
                            }}
                            return {{ ...c }};
                        }});

                        if (parsed.sistema_gestion_integrado) {{
                            datosSGI = {{ ...datosSGI, ...parsed.sistema_gestion_integrado }};
                        }}

                        guardarPersistencia();
                        actualizarMetricas();
                        renderizarControles();
                        renderizarModulosSGI();
                        alert("Auditoría y datos del SGI importados exitosamente.");
                    }} else {{
                        alert("El archivo JSON no tiene el formato de auditoría esperado.");
                    }}
                }} catch (err) {{
                    alert("Error parseando el archivo JSON: " + err.message);
                }}
            }};
            reader.readAsText(file);
        }}

        function exportarActaSGI() {{
            const org = datosSGI["sgi_organizacion"] || "Organización";
            let doc = `ACTA FORMAL DE CONSTITUCIÓN Y MANUAL DEL SISTEMA DE GESTIÓN INTEGRADO (SGI)\\n`;
            doc += `================================================================================\\n`;
            doc += `Organización: ${{org}}\\n`;
            doc += `Fecha de Generación: ${{new Date().toLocaleDateString('es-CL')}}\\n`;
            doc += `Marcos Integrados: ISO/IEC 27001:2022 • ISO/IEC 42001:2023 • Ley N° 21.719\\n`;
            doc += `================================================================================\\n\\n`;

            MODULOS_SGI_CANONICOS.forEach(mod => {{
                doc += `[ ${{mod.fase}} - ${{mod.titulo}} ]\\n`;
                doc += `${{mod.descripcion}}\\n`;
                doc += `--------------------------------------------------------------------------------\\n`;
                mod.campos.forEach(c => {{
                    doc += `* ${{c.label}}:\\n${{datosSGI[c.id] || c.default}}\\n\\n`;
                }});
                doc += `\\n`;
            }});

            const blob = new Blob([doc], {{ type: "text/plain;charset=utf-8" }});
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `Manual_Constitutivo_SGI_${{org.replace(/\\s+/g, '_')}}.txt`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }}
    </script>
</body>
</html>
"""
    return html

def main():
    if sys.stdout and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="Compilador SGI & Controles ISO 27001 V2.0")
    parser.add_argument("--json-es", default="ISO_27001_Checklist_App/referencias/controles_iso27001_es.json", help="Ruta al JSON de controles en español")
    parser.add_argument("--output", default="ISO_27001_Checklist_App/output/index.html", help="Ruta de destino del HTML monolítico")
    parser.add_argument("--password", default="iso27001admin", help="Clave maestra de desbloqueo")
    parser.add_argument("--title", default="Sistema de Gestión Integrado • Checklist y Matriz de Controles", help="Título del aplicativo")

    args = parser.parse_args()

    ruta_json = Path(args.json-es if hasattr(args, "json-es") else getattr(args, "json_es")).resolve()
    ruta_output = Path(args.output).resolve()
    ruta_output.parent.mkdir(parents=True, exist_ok=True)

    print(f"[*] Ingestando controles en español desde: {ruta_json}")
    controles = cargar_controles_completos(ruta_json)
    print(f"[+] Total de controles cargados: {len(controles)} (93 ISO 27001 + 6 ISO 42001/27090 + 6 Ley 21.719)")

    password_hash = calcular_hash_sha256(args.password.strip())
    print(f"[*] Hash de clave maestra calculado: {password_hash[:16]}...")

    print("[*] Generando aplicación web monolítica V2.0 en español...")
    html_content = generar_html_v2(controles, MODULOS_SGI_BASE, password_hash, args.title)

    with open(ruta_output, mode="w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"[+] Aplicación compilada exitosamente en: {ruta_output} ({len(html_content)} bytes)")

if __name__ == "__main__":
    main()
