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
├── claves/             # Guardar la API
├── agente_devsecops.py # El nucleo del agente de IA
├── informe_auditoria.md# Reporte tecnico de cambios aplicados
└── README.md
```
# Configuración y Uso
 
## 1. Prerrequisitos
 
- Tener instalado Terraform en el sistema.
- Tener una cuenta de Azure configurada en tu terminal mediante el comando:
```bash
az login
```
 
## 2. Instalación
 
Asegúrate de tener instalada la librería necesaria para la comunicación con la API:
 
```bash
pip install google-generativeai
```
 
## 3. Ejecución del Agente
 
1. Edita el archivo `agente_devsecops.py` e inserta tu `API_KEY` de Google Gemini en la variable correspondiente.
2. Coloca tus archivos de infraestructura `.tf` dentro de la carpeta `/terraform`.
3. Ejecuta el agente desde la raíz del proyecto:
```bash
python agente_devsecops.py
```
 
---
 
## ¿Por qué este proyecto?
 
Este agente soluciona la fricción entre la velocidad de despliegue y la seguridad. Permite a los equipos de desarrollo desplegar infraestructura segura sin necesidad de ser expertos en seguridad, eliminando el error humano y manteniendo un registro auditable de todos los cambios realizados.
 
---
 
*Desarrollado como Proyecto de Fin de Máster — Daniel Rodríguez García*
