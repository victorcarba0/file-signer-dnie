# Herramienta de Firma Digital con DNIe

Una aplicación de escritorio y conjunto de herramientas de línea de comandos (CLI) para firmar y verificar archivos digitalmente utilizando el DNI electrónico español (DNIe). El proyecto ofrece dos versiones de interfaz gráfica (una con diseño moderno y otra para máxima compatibilidad), así como scripts para automatizar tareas.

---

## ✨ Características

-   **Firma de Archivos**: Firma uno o múltiples archivos de forma segura con la clave privada de tu DNIe.
-   **Verificación de Firmas**: Comprueba la validez de una firma utilizando el archivo original, el fichero de firma y el certificado público.
-   **Exportación de Certificados**: Extrae y guarda el certificado público de firma de tu DNIe en un archivo `.der`.
-   **Interfaz Gráfica Avanzada**: Una aplicación de escritorio fácil de usar con un diseño oscuro, iconos y feedback en tiempo real.
-   **Interfaz Gráfica Sencilla**: Una versión alternativa sin dependencias visuales complejas para asegurar la máxima compatibilidad.
-   **Herramientas de Línea de Comandos (CLI)**: Scripts potentes para usuarios avanzados que deseen integrar la firma en procesos automatizados.
-   **Diagnóstico de Conexión**: Una herramienta para verificar rápidamente que el entorno está configurado correctamente.

---

## 🚀 Installation Steps

Sigue estos pasos para configurar el entorno y ejecutar la aplicación.

### 1. Requisitos del Sistema

-   **Lector de Smart Cards**: Un lector de tarjetas compatible con el DNIe.
-   **Drivers del DNIe**: El software oficial del Cuerpo Nacional de Policía. Puedes descargarlo desde [la web oficial del DNI electrónico](https://www.dnielectronico.es).
-   **OpenSC**: Librerías de código abierto para interactuar con tarjetas inteligentes.
    -   **Windows**: Descarga el instalador `win64.msi` desde las [releases oficiales de OpenSC](https://github.com/OpenSC/OpenSC/releases).

-   **GTK+ (Solo para la interfaz con iconos `intercomp_v1.py` en Windows)**:
    1.  Instala **MSYS2** desde [su web oficial](https://www.msys2.org/).
    2.  Abre una terminal de MSYS2 y ejecuta: `pacman -S mingw-w64-x86_64-gtk3`.
    3.  Añade `C:\msys64\mingw64\bin` a las **variables de entorno (PATH)** de tu sistema y reinicia el equipo.

### 2. Configuración del Proyecto

1.  **Clona o descarga el repositorio** y asegúrate de que la estructura de carpetas sea la siguiente:
    ```
    /projects-seg/
    ├── assets/                 # <== Carpeta de iconos
    │   ├── check-circle.svg
    │   ├── download.svg
    │   ├── edit.svg
    │   ├── log-out.svg
    │   ├── shield.svg
    │   └── trash-2.svg
    └── Seguridad de redes/     # <== Carpeta principal de los scripts
        ├── intercomp_v1.py
        ├── intercomp_v2.py
        ├── dnie_cli.py
        ├── ... (resto de scripts)
        └── requirements.txt
    ```
    **Importante**: La carpeta `assets` debe estar al mismo nivel que la carpeta `Seguridad de redes`.

2.  **Abre una terminal y navega a la carpeta de los scripts**:
    ```bash
    cd ruta/a/projects-seg/Seguridad de redes
    ```

3.  **(Recomendado) Crea y activa un entorno virtual:**
    ```bash
    # En Windows
    python -m venv venv
    .\venv\Scripts\activate
    ```

4.  **Instala las dependencias de Python** usando el archivo `requirements.txt`:
    ```bash
    pip install -r requirements.txt
    ```

---

## ▶️ Usage Examples

Asegúrate de tener tu DNIe insertado en el lector y de ejecutar los comandos desde la carpeta `Seguridad de redes`.

### Interfaz Gráfica (Recomendado)

#### Versión con Estilo (`intercomp_v1.py`)

Esta es la versión completa con tema oscuro e iconos. Requiere tener GTK+ instalado en Windows.
```bash
python intercomp_v1.py
```

#### Versión Sencilla (`intercomp_v2.py`)

Esta versión no requiere iconos ni GTK+, por lo que es ideal si tienes problemas con las dependencias o prefieres un aspecto nativo.
```bash
python intercomp_v2.py
```

### Herramientas de Línea de Comandos (CLI)

#### Script de Diagnóstico (`test_dnie.py`)

Úsalo para verificar que tu lector, DNIe y librerías están correctamente configurados.
```bash
python test_dnie.py
```

#### Firmar y Exportar (`dnie_cli.py`)

```bash
# Exportar el certificado (te pedirá el PIN)
python dnie_cli.py export-cert --output mi_certificado.der

# Firmar uno o más archivos (te pedirá el PIN)
python dnie_cli.py sign documento.pdf informe.docx
```

#### Verificar Firma (`verificar_firma_dnie.py`)

```bash
# Verificar una firma
python verificar_firma_dnie.py documento.pdf documento.pdf.sig mi_certificado.der
```

---

## ⚠️ Limitations/Known Issues

-   **Dependencias de la GUI Avanzada**: La versión con iconos (`intercomp_v1.py`) requiere la instalación manual de GTK+ en Windows a través de MSYS2, lo cual puede ser un proceso complejo para usuarios no técnicos. La versión `intercomp_v2.py` se proporciona como una alternativa robusta que no tiene estas dependencias.
-   **Ruta de OpenSC Hardcodeada**: La ruta a la librería de OpenSC (`LIB_PATH`) está definida dentro de cada script para una instalación estándar en Windows. Si OpenSC está instalado en una ubicación diferente o se usa otro sistema operativo (macOS, Linux), esta variable debe ser modificada manualmente en el código fuente.
-   **Sesión de PIN**: La aplicación no mantiene una sesión abierta. Se solicitará el PIN del DNIe para cada operación principal (firmar, exportar, probar conexión) como medida de seguridad.

---

## 📄 Licencia

Este proyecto está bajo la Licencia MIT.