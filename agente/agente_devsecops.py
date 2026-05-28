import google.generativeai as genai
import os
import re
import subprocess
import time
from datetime import datetime

# --- CONFIGURACION PRINCIPAL ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIR_VULNERABLE = os.path.join(BASE_DIR, "terraform")
DIR_SEGURA_BASE = os.path.join(BASE_DIR, "revision")
ARCHIVO_REPORTE = os.path.join(BASE_DIR, "informe_auditoria.md")
DIR_CLAVES = os.path.join(BASE_DIR, "claves")
MODELO_IA = "gemini-3.5-flash"


def leer_clave_desde_archivo(nombre_archivo):
    ruta = os.path.join(DIR_CLAVES, nombre_archivo)
    if not os.path.exists(ruta):
        raise FileNotFoundError(f"No se encontro el archivo de clave: {ruta}")

    with open(ruta, 'r', encoding='utf-8') as f:
        return f.read().strip()


API_KEY = os.getenv("GEMINI_API_KEY") or leer_clave_desde_archivo("api_key.txt")
SSH_PUBLIC_KEY_SEGURA = leer_clave_desde_archivo("ssh_public_key.pub")

genai.configure(api_key=API_KEY)


def construir_prompt(codigo_tf):
    return f"""
    Eres un Arquitecto DevSecOps Senior experto en Azure y Terraform.
    Tu objetivo es analizar el siguiente codigo de infraestructura, detectar vulnerabilidades y aplicar auto-remediacion para cumplir con los estandares de seguridad de la industria.

    Directrices estrictas de remediacion:
    1. Zero Trust y Maxima Seguridad: Cierra puertos abiertos a Internet, fuerza conexiones cifradas (HTTPS/SSL), exige las versiones TLS mas recientes soportadas y deshabilita accesos publicos.
    2. Sintaxis Moderna (AzureRM v3/v4): Es OBLIGATORIO utilizar la sintaxis actual del proveedor. No utilices argumentos obsoletos (deprecated) bajo ninguna circunstancia. Si un argumento de seguridad ha cambiado de nombre en las ultimas versiones, utiliza el nuevo.
    3. Preservacion de Arquitectura: NO inventes ni anadas bloques de recursos nuevos (como azurerm_subnet, azurerm_private_endpoint o firewalls adicionales) que no existan en el codigo original. Limitate exclusivamente a securizar los recursos ya definidos.
    4. Estructura Obligatoria: El archivo resultante debe incluir el bloque 'provider "azurerm" {{ features {{}} }}' al principio.
    5. Formato: Anade comentarios formales y tecnicos en espanol explicando las medidas aplicadas.
    6. Devuelve UNICAMENTE el codigo corregido dentro de un bloque HCL (```hcl ... ```).
    7. Si usas admin_ssh_key, utiliza una clave SSH pública valida en formato OpenSSH.
    8. Adicionalmente, incluye un reporte humano en el formato exacto indicado abajo.

    Formato de respuesta requerido (exacto):
    ---INICIO_REPORTE_HUMANO---
    [Resumen tecnico en español de vulnerabilidades y medidas propuestas]
    ---FIN_REPORTE_HUMANO---

    ```hcl
    provider "azurerm" {{
      features {{}}
    }}

    # [codigo corregido aqui]
    ```

    Codigo original a evaluar:
    {codigo_tf}
    """


def extraer_codigo_y_reporte(respuesta_texto):
    if not respuesta_texto or not respuesta_texto.strip():
        raise ValueError("La respuesta del modelo esta vacia.")

    texto = respuesta_texto.strip()

    match_reporte = re.search(
        r'---INICIO_REPORTE_HUMANO---(.*?)---FIN_REPORTE_HUMANO---',
        texto,
        re.DOTALL,
    )
    reporte_humano = match_reporte.group(1).strip() if match_reporte else (
        "Analisis automatizado de seguridad aplicado sobre el archivo y remediado con mejores practicas de Azure y Terraform."
    )

    match_codigo = re.search(r'```(?:hcl)?\s*(.*?)\s*```', texto, re.DOTALL | re.IGNORECASE)
    codigo_seguro = match_codigo.group(1).strip() if match_codigo else texto
    codigo_seguro = re.sub(r'^```(?:hcl)?|```$', '', codigo_seguro, flags=re.IGNORECASE | re.MULTILINE).strip()

    if not codigo_seguro:
        raise ValueError("No se encontro codigo HCL utilizable en la respuesta del modelo.")

    if not re.search(r'^\s*provider\s+"azurerm"', codigo_seguro, re.MULTILINE):
        codigo_seguro = 'provider "azurerm" {\n  features {}\n}\n\n' + codigo_seguro

    if re.search(r'admin_ssh_key\s*\{', codigo_seguro, re.IGNORECASE):
        codigo_seguro = re.sub(
            r'public_key\s*=\s*"[^"]*"',
            f'public_key = "{SSH_PUBLIC_KEY_SEGURA}"',
            codigo_seguro,
        )

    codigo_seguro = re.sub(
        r'\n\s*storage_account_name\s*=\s*azurerm_storage_account\.[A-Za-z0-9_]+\.name',
        '\n  storage_account_id = azurerm_storage_account.almacenamiento.id',
        codigo_seguro,
    )

    codigo_seguro = re.sub(
        r'\n\s*container_access_type\s*=\s*"[^"]+"',
        '\n  container_access_type = "private"',
        codigo_seguro,
    )

    codigo_seguro = re.sub(
        r'\n\s*allow_nested_items_to_be_public\s*=\s*true',
        '\n  allow_nested_items_to_be_public = false',
        codigo_seguro,
    )

    codigo_seguro = re.sub(
        r'\n\s*https_traffic_only_enabled\s*=\s*false',
        '\n  https_traffic_only_enabled = true',
        codigo_seguro,
    )

    return codigo_seguro, reporte_humano


def preparar_entorno():
    if not os.path.exists(DIR_SEGURA_BASE):
        os.makedirs(DIR_SEGURA_BASE)
    if not os.path.exists(ARCHIVO_REPORTE):
        with open(ARCHIVO_REPORTE, 'w', encoding='utf-8') as f:
            f.write("#Reporte Consolidado de Auditoria y Auto-Remediacion DevSecOps\n")
            f.write(f"Generado de forma automatica el: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")


def auditar_y_corregir(nombre_archivo, ruta_destino):
    ruta_origen = os.path.join(DIR_VULNERABLE, nombre_archivo)
    
    with open(ruta_origen, 'r', encoding='utf-8') as f:
        codigo_tf = f.read()
        
    print(f"\n[INFO] Iniciando analisis de IA para el archivo: {nombre_archivo}")

    prompt = construir_prompt(codigo_tf)

    try:
        model = genai.GenerativeModel(MODELO_IA)
        respuesta = model.generate_content(prompt)
        codigo_seguro, reporte_humano = extraer_codigo_y_reporte(respuesta.text)

        with open(ruta_destino, 'w', encoding='utf-8') as f:
            f.write(codigo_seguro)

        with open(ARCHIVO_REPORTE, 'a', encoding='utf-8') as f:
            f.write(f"## Analisis del Archivo Fuente: `{nombre_archivo}`\n\n")
            f.write(f"{reporte_humano}\n\n")
            f.write(f"--- \n\n")

        print(f"[OK] Analisis e informe formal completado para {nombre_archivo}.")
        return True

    except ValueError as e:
        print(f"[WARN] La respuesta del modelo no cumplio con la estructura de etiquetado requerida para {nombre_archivo}: {e}")
        return False
    except Exception as e:
        print(f"[ERROR] Fallo critico en la comunicacion con la API: {e}")
        return False

def validar_y_desplegar(nombre_archivo, directorio_trabajo):
    print(f"[INFO] Ejecutando validacion de arquitectura nativa (Pre-Flight Check)...")
    try:
        subprocess.run(["terraform", "init"], cwd=directorio_trabajo, check=True, capture_output=True)
        subprocess.run(["terraform", "validate"], cwd=directorio_trabajo, check=True, capture_output=True, text=True)
        print("[OK] El codigo autogenerado cumple con la sintaxis de Terraform.")
        
        print("\n--- RESUMEN DEL PLAN DE TERRAFORM ---")
        subprocess.run(["terraform", "plan"], cwd=directorio_trabajo, check=True)
        
        print("\n[REQUISITO DE COMPLIANCE] Control de cambios requiere aprobacion manual.")
        aprobacion = input(f"[INPUT] ¿Autoriza el despliegue de la configuracion remediada de {nombre_archivo} en Azure? (s/n): ")
        
        if aprobacion.lower() == 's':
            print(f"[INFO] Desplegando recursos seguros en la region francecentral...")
            subprocess.run(["terraform", "apply", "-auto-approve"], cwd=directorio_trabajo, check=True)
            print(f"[OK] Aprovisionamiento seguro finalizado correctamente.")
        else:
            print(f"[WARN] Despliegue de {nombre_archivo} cancelado por decision del operador.")
            
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Inconsistencia detectada durante la validacion de Terraform:\n{e.stderr if e.stderr else e}")

if __name__ == "__main__":
    print("=== INICIANDO PIPELINE DEVSECOPS ===")
    preparar_entorno()
    
    if not os.path.exists(DIR_VULNERABLE):
        print(f"[ERROR] No se localiza el directorio fuente: '{DIR_VULNERABLE}'. Proceso detenido.")
        exit(1)
        
    archivos_tf = sorted([f for f in os.listdir(DIR_VULNERABLE) if f.endswith('.tf')])
    
    if not archivos_tf:
        print(f"[INFO] No existen archivos de configuracion en '{DIR_VULNERABLE}'. Finalizando.")
        exit(0)
        
    print(f"[INFO] Archivos en cola de evaluacion: {len(archivos_tf)}")
        
    for archivo in archivos_tf:
        print(f"\n{'='*60}")
        print(f"[PROCESO] Procesando secuencia automatica para: {archivo}")
        print(f"{'='*60}")
        
        dir_temporal = os.path.join(DIR_SEGURA_BASE, f"temp_{archivo.replace('.tf', '')}")
        if not os.path.exists(dir_temporal):
            os.makedirs(dir_temporal)
            
        ruta_archivo_seguro = os.path.join(dir_temporal, archivo)
        
        if auditar_y_corregir(archivo, ruta_archivo_seguro):
            validar_y_desplegar(archivo, dir_temporal)
            
        time.sleep(15) # Retardo incrementado preventivo para estabilizar cuotas por minuto de la API
        
    print("\n=== PIPELINE DEVSECOPS FINALIZADO ===")