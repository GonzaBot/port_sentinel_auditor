# 🛡️ Día 2: Port Sentinel Auditor
> **Reto 100 Días, 100 Apps de Ciberseguridad** > ![Progreso](https://img.shields.io/badge/Progreso-2%2F100-brightgreen) ![Python](https://img.shields.io/badge/Python-3.12-blue) ![License](https://img.shields.io/badge/License-MIT-yellow)

**Port Sentinel Auditor** es una herramienta de reconocimiento táctico (*Footprinting*) diseñada para mapear la superficie de exposición de un objetivo. A diferencia de un escáner genérico, esta aplicación clasifica la criticidad del hallazgo basándose en el alcance de la red e implementa una estrategia de **Dual Logging** para auditorías profesionales.

---

## 🚀 Funcionalidades Principales

* **Dual Logging System (Modo Híbrido):** * **GUI (Reporte Ejecutivo):** Muestra en pantalla únicamente los puertos **abiertos** con su respectivo alcance para una lectura rápida y limpia.
    * **TXT (Log Forense):** Guarda automáticamente en la carpeta de **Descargas** un registro técnico completo (Verbose) que incluye tanto puertos abiertos como cerrados/timeouts.
* **Inteligencia de Alcance (Network Scope):** Identifica automáticamente si el objetivo es `LOOPBACK` (interno), `LAN` (red local privada) o `WAN` (público en Internet), permitiendo priorizar la respuesta ante incidentes.
* **Banner Grabbing Activo:** Ejecuta peticiones de bajo nivel para capturar las firmas de los servicios y ayudar en la identificación de versiones de software.
* **Arquitectura Non-Blocking:** Implementación de hilos (`threading`) para asegurar que la interfaz de usuario se mantenga fluida durante escaneos de alta latencia.

---

## 🔬 Concepto Clave: El TCP Three-Way Handshake

Para determinar si un puerto está abierto, esta herramienta utiliza el método `socket.connect_ex()`, el cual intenta completar un **saludo de tres vías** de la pila TCP/IP:



1.  **SYN:** El cliente (tu script) envía un paquete de sincronización al puerto objetivo.
2.  **SYN/ACK:** Si el puerto está **abierto**, el servidor responde confirmando la recepción. Si está **cerrado**, responde con un paquete `RST` (Reset).
3.  **ACK:** El cliente confirma la recepción del servidor y la conexión queda establecida.

> **Nota Técnica:** Este método se conoce como **"Full Connect Scan"**. Es extremadamente fiable para confirmar la disponibilidad de un servicio, aunque es más detectable por sistemas de monitoreo (IDS) que un escaneo de tipo "Stealth" (SYN Scan) debido a que completa la sesión TCP.

---

## 🛠️ Cómo Ejecutar

### Requisitos Previos
* Tener instalado **Python 3.10** o superior.
* No requiere la instalación de librerías externas (usa módulos nativos: `socket`, `threading`, `tkinter`, `ipaddress`).

### Pasos para iniciar
1.  **Descargar el código:** Guarda el archivo como `port_sentinel.py`.
2.  **Abrir la Terminal:** Dirígete a la carpeta donde guardaste el archivo.
3.  **Ejecutar la App:**
    ```bash
    python port_sentinel.py
    ```
4.  **Uso:** * Introduce la IP o dominio a auditar (ej: `127.0.0.1` o `google.com`).
    * Haz clic en **"INICIAR AUDITORÍA"**.
    * Al finalizar, el sistema te avisará que el log completo ha sido generado en tu carpeta de **Descargas**.

---

## ⚖️ Descargo de Responsabilidad (Disclaimer)
Esta herramienta fue creada con fines educativos y de auditoría ética. El escaneo de redes sin autorización previa es ilegal. El autor no se hace responsable del uso indebido de este software.