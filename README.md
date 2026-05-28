# Azure-Terraform-Security-Agent

## Descripcion del Proyecto
Agente autonomo basado en IA (Google Gemini) disenado para automatizar el ciclo de vida de DevSecOps. Este sistema analiza configuraciones de infraestructura en Azure (Terraform) en busca de vulnerabilidades, aplica remediaciones de seguridad siguiendo las mejores practicas (hardening) y genera informes de auditoria detallados antes del despliegue.

## Funcionalidades Principales
* **Auditoria IA:** Analisis estatico de codigo Terraform para detectar riesgos criticos.
* **Auto-remediacion:** Correccion automatica de configuraciones (ej: forzado de HTTPS, cierre de puertos SSH, sustitucion de contrasenas por claves RSA).
* **Compliance:** Generacion de informes de auditoria (informe_auditoria.md) para trazabilidad total.
* **Seguridad Human-in-the-Loop:** Validacion manual obligatoria mediante terraform plan antes de cualquier despliegue en produccion.

## Tecnologias Utilizadas
* **Lenguaje:** Python 3.x
* **Infraestructura como Codigo:** Terraform (AzureRM Provider)
* **IA:** Google Generative AI API (gemini-3.5-flash)
* **Nube:** Microsoft Azure

## Estructura del Repositorio
```text
├── terraform/          # Archivos .tf vulnerables (fuente)
├── revision/           # Infraestructura corregida y validada
├── agente_devsecops.py # El nucleo del agente de IA
├── informe_auditoria.md# Reporte tecnico de cambios aplicados
└── README.md
