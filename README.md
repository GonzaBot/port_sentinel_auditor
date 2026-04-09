# 🛡️ Día 2: Port Sentinel Auditor
> **Reto 100 Días, 100 Apps de Ciberseguridad** > ![Progreso](https://img.shields.io/badge/Progreso-2%2F100-brightgreen) ![Python](https://img.shields.io/badge/Python-3.12-blue) ![Licencia](https://img.shields.io/badge/Licencia-MIT-yellow)

> [!IMPORTANT]
> **⚠️ AVISO LEGAL Y ÉTICO / LEGAL & ETHICAL DISCLAIMER**
> 
> **ES:** No usar contra sistemas de terceros. Este software ha sido creado exclusivamente con fines educativos y para su uso en entornos de auditoría autorizados. El uso de esta herramienta contra objetivos sin consentimiento previo es ilegal.
> 
> **EN:** Do not use against third-party systems. This software is created for educational purposes and authorized auditing environments only. Using this tool against targets without prior consent is illegal.

**Port Sentinel Auditor** es una herramienta de reconocimiento táctico (Footprinting) diseñada para mapear la superficie de exposición de un objetivo. Clasifica la criticidad del hallazgo según el alcance de red (LOOPBACK, LAN, WAN) e implementa un sistema de Dual Logging para reportes profesionales.

---

## 🚀 Funcionalidades
* **Dual Logging System:** Reporte visual en GUI y log técnico detallado en archivo `.txt`.
* **Network Scope Intelligence:** Identificación automática del tipo de red del objetivo.
* **Banner Grabbing:** Captura de firmas de servicios para identificación de versiones.
* **Non-Blocking UI:** Escaneo fluido gracias a una arquitectura basada en threading.

## 🛠️ Instalación y Uso

### Requisitos
* Python 3.12 o superior.
* Sistema operativo con soporte para ejecución de scripts en terminal.

### Cómo ejecutar
1. Descarga o clona el archivo `port_sentinel.py`.
2. Abre una terminal y dirígete al directorio donde se encuentra el archivo.
3. Ejecuta la aplicación:
   ```bash
   python port_sentinel.py