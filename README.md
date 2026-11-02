# ISO/IEC 27001:2022 Compliance Checklist App

Aplicación web interactiva y offline para auditorías de seguridad de la información y seguimiento de cumplimiento de los 93 controles del Anexo A de la norma ISO/IEC 27001:2022.

---

## Arquitectura y Componentes

- **Frontend:** Aplicación monolítica en HTML5, CSS3 y Vanilla JavaScript sin dependencias externas.
- **Persistencia:** Almacenamiento local mediante LocalStorage con exportación/importación en formato JSON.
- **Compilador:** Script en Python para validar y actualizar el catálogo de controles normativos.

---

## Instrucciones de Uso

Abra `index.html` en cualquier navegador web moderno. No requiere conexión a Internet ni servidor web adicional.

---

## Consideraciones de Seguridad

- Este repositorio almacena código fuente, utilitarios de prueba y documentación técnica de ingeniería.
- Todas las credenciales, llaves privadas y variables de entorno deben suministrarse de forma local mediante archivos no versionados.
- Las herramientas de auditoría contenidas deben utilizarse exclusivamente en entornos autorizados y laboratorios de prueba.

---

**Autor:** Security Analyst  
**Licencia:** Uso Privado / Propietario
