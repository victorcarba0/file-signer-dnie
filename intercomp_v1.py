import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os
import io

# --- Librerías para la lógica del DNIe y criptografía ---
import pkcs11
from pkcs11 import ObjectClass, Attribute, Mechanism
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

# --- Librerías para manejar iconos SVG ---
from PIL import Image, ImageTk
import cairosvg

# ==============================================================================
# === CONFIGURACIÓN ===
# ==============================================================================
# ⚠️ ¡IMPORTANTE! Asegúrate de que esta ruta sea correcta para tu sistema.
LIB_PATH = 'C:/Archivos de Programa/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll'

# ==============================================================================
# === CLASE PARA EL DIÁLOGO DE PIN PERSONALIZADO ===
# ==============================================================================
class CustomPinDialog(tk.Toplevel):
    """Una ventana de diálogo modal y estilizada para solicitar el PIN."""
    def __init__(self, parent):
        super().__init__(parent)
        self.title("PIN del DNIe")
        self.parent = parent
        self.result = None

        # --- Estilos y Colores ---
        self.COLOR_BG = "#2E2E2E"
        self.FONT_BOLD = ("Segoe UI", 11, "bold")
        self.FONT_NORMAL = ("Segoe UI", 11)

        self.configure(bg=self.COLOR_BG, padx=20, pady=20)
        self.resizable(False, False)

        # --- Estilo para los widgets del diálogo ---
        style = ttk.Style(self)
        style.configure('Dialog.TLabel', background=self.COLOR_BG, foreground="#FFFFFF")
        style.configure('Dialog.TFrame', background=self.COLOR_BG)

        # --- Widgets ---
        label = ttk.Label(self, text="Introduce tu PIN:", style='Dialog.TLabel', font=self.FONT_BOLD)
        label.pack(pady=(0, 10))

        self.pin_entry = ttk.Entry(self, show='*', width=20, font=self.FONT_NORMAL, justify='center')
        self.pin_entry.pack(pady=(0, 20), ipady=4)
        self.pin_entry.focus_set()
        self.pin_entry.bind("<Return>", self.on_ok)

        button_frame = ttk.Frame(self, style='Dialog.TFrame')
        button_frame.pack()
        
        ok_button = ttk.Button(button_frame, text="OK", command=self.on_ok, style='TButton')
        ok_button.pack(side=tk.LEFT, padx=5)
        
        cancel_button = ttk.Button(button_frame, text="Cancelar", command=self.on_cancel, style='TButton')
        cancel_button.pack(side=tk.LEFT, padx=5)

        # --- Hacer la ventana modal ---
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)
        self.wait_window(self)

    def on_ok(self, event=None):
        self.result = self.pin_entry.get()
        self.destroy()

    def on_cancel(self, event=None):
        self.result = None
        self.destroy()

# ==============================================================================
# === CLASE PRINCIPAL DE LA APLICACIÓN ===
# ==============================================================================
class DNIeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Herramienta de Firma con DNIe")
        self.root.state('zoomed')
        self.root.minsize(850, 600)

        # --- Paleta de colores y fuentes ---
        self.COLOR_BG = "#2E2E2E"
        self.COLOR_FG = "#FFFFFF"
        self.COLOR_BUTTON = "#4A4A4A"
        self.COLOR_LOG_BG = "#1E1E1E"
        self.FONT_NORMAL = ("Segoe UI", 10)
        self.FONT_BOLD = ("Segoe UI", 10, "bold")

        self.root.configure(bg=self.COLOR_BG)
        self.setup_styles()
        self.load_icons()

        # --- Estructura de la Interfaz ---
        main_frame = ttk.Frame(self.root, style='Main.TFrame', padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        button_frame = ttk.Frame(main_frame, style='Main.TFrame')
        button_frame.pack(fill=tk.X, pady=(0, 10))
        log_frame = ttk.Frame(main_frame, style='Main.TFrame')
        log_frame.pack(fill=tk.BOTH, expand=True)
        status_frame = ttk.Frame(main_frame, style='Main.TFrame')
        status_frame.pack(fill=tk.X, pady=(5, 0))

        # --- Botones de acción ---
        self.sign_button = ttk.Button(button_frame, text="Firmar Archivo(s)", image=self.icon_sign, compound=tk.LEFT, command=self.start_sign_thread, style='TButton')
        self.sign_button.pack(side=tk.LEFT, padx=(0, 5))
        self.verify_button = ttk.Button(button_frame, text="Verificar Firma", image=self.icon_verify, compound=tk.LEFT, command=self.start_verify_thread, style='TButton')
        self.verify_button.pack(side=tk.LEFT, padx=5)
        self.export_button = ttk.Button(button_frame, text="Exportar Certificado", image=self.icon_export, compound=tk.LEFT, command=self.start_export_thread, style='TButton')
        self.export_button.pack(side=tk.LEFT, padx=5)
        self.diagnostic_button = ttk.Button(button_frame, text="Probar Conexión", image=self.icon_diagnostic, compound=tk.LEFT, command=self.start_diagnostic_thread, style='TButton')
        self.diagnostic_button.pack(side=tk.LEFT, padx=5)

        self.exit_button = ttk.Button(button_frame, text="Salir", image=self.icon_exit, compound=tk.LEFT, command=self.root.destroy, style='TButton')
        self.exit_button.pack(side=tk.RIGHT)
        self.clear_log_button = ttk.Button(button_frame, text="Limpiar Log", image=self.icon_clear, compound=tk.LEFT, command=self.clear_log, style='TButton')
        self.clear_log_button.pack(side=tk.RIGHT, padx=5)

        # --- Área de texto y barra de estado ---
        self.log_area = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, state='disabled', bg=self.COLOR_LOG_BG, fg=self.COLOR_FG, font=self.FONT_NORMAL, relief=tk.FLAT)
        self.log_area.pack(fill=tk.BOTH, expand=True)
        self.status_label = ttk.Label(status_frame, text="Listo", style='Status.TLabel', anchor=tk.W)
        self.status_label.pack(fill=tk.X)
        self.log_message("Bienvenido a la Herramienta de Firma con DNIe.")
        self.log_message(f"Usando librería PKCS#11 en: {LIB_PATH}\n")

    # --- Métodos de Configuración Visual ---
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Main.TFrame', background=self.COLOR_BG)
        style.configure('Status.TLabel', background=self.COLOR_BG, foreground=self.COLOR_FG, font=self.FONT_NORMAL)
        style.configure('TButton', background=self.COLOR_BUTTON, foreground=self.COLOR_FG, font=self.FONT_BOLD, padding=10, borderwidth=0, relief=tk.FLAT)
        style.map('TButton', background=[('active', '#5A5A5A'), ('disabled', '#3A3A3A')], foreground=[('disabled', '#888888')])

    def load_icons(self):
        try:
            self.icon_sign = self.load_svg_icon("assets/edit.svg")
            self.icon_verify = self.load_svg_icon("assets/check-circle.svg")
            self.icon_export = self.load_svg_icon("assets/download.svg")
            self.icon_clear = self.load_svg_icon("assets/trash-2.svg")
            self.icon_exit = self.load_svg_icon("assets/log-out.svg")
            self.icon_diagnostic = self.load_svg_icon("assets/shield.svg")
        except Exception as e:
            messagebox.showwarning("Iconos no encontrados", f"No se pudieron cargar los iconos desde la carpeta 'assets'.\nError: {e}")
            self.icon_sign, self.icon_verify, self.icon_export, self.icon_clear, self.icon_exit, self.icon_diagnostic = (tk.PhotoImage(),)*6

    def load_svg_icon(self, path, size=20):
        png_data = cairosvg.svg2png(url=path, output_width=size, output_height=size)
        image = Image.open(io.BytesIO(png_data))
        return ImageTk.PhotoImage(image)

    # --- Métodos de la Interfaz ---
    def log_message(self, message):
        self.root.after(0, self._log_message, message)

    def _log_message(self, message):
        self.log_area.configure(state='normal')
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.configure(state='disabled')
        self.log_area.see(tk.END)
        
    def clear_log(self):
        self.log_area.configure(state='normal')
        self.log_area.delete(1.0, tk.END)
        self.log_area.configure(state='disabled')

    def update_status(self, message, clear_after_ms=0):
        self.root.after(0, self._update_status, message, clear_after_ms)

    def _update_status(self, message, clear_after_ms):
        self.status_label.config(text=message)
        if clear_after_ms > 0:
            self.root.after(clear_after_ms, lambda: self.status_label.config(text="Listo"))

    def set_buttons_state(self, state):
        self.root.after(0, self._set_buttons_state, state)

    def _set_buttons_state(self, state):
        buttons = [self.sign_button, self.verify_button, self.export_button, self.diagnostic_button, self.clear_log_button, self.exit_button]
        for button in buttons:
            button.config(state=state)

    # --- Lanzadores de Hilos ---
    def start_sign_thread(self):
        files = filedialog.askopenfilenames(title="Seleccione los archivos para firmar")
        if not files: return self.update_status("Operación cancelada.", 3000)
        pin = CustomPinDialog(self.root).result
        if not pin: return self.update_status("Operación cancelada.", 3000)
        threading.Thread(target=self.perform_sign, args=(files, pin), daemon=True).start()

    def start_verify_thread(self):
        documento = filedialog.askopenfilename(title="1. Selecciona el DOCUMENTO ORIGINAL")
        if not documento: return
        firma = filedialog.askopenfilename(title="2. Selecciona el archivo de FIRMA (.sig)")
        if not firma: return
        certificado = filedialog.askopenfilename(title="3. Selecciona el CERTIFICADO PÚBLICO (.der)")
        if not certificado: return
        threading.Thread(target=self.perform_verify, args=(documento, firma, certificado), daemon=True).start()
        
    def start_export_thread(self):
        pin = CustomPinDialog(self.root).result
        if not pin: return self.update_status("Operación cancelada.", 3000)
        output_file = filedialog.asksaveasfilename(title="Guardar certificado como...", defaultextension=".der", filetypes=[("DER certificate", "*.der"), ("All files", "*.*")])
        if not output_file: return self.update_status("Operación cancelada.", 3000)
        threading.Thread(target=self.perform_export, args=(pin, output_file), daemon=True).start()

    def start_diagnostic_thread(self):
        pin = CustomPinDialog(self.root).result
        if not pin: return self.update_status("Operación cancelada.", 3000)
        threading.Thread(target=self.perform_diagnostic, args=(pin,), daemon=True).start()

    # --- Lógica Principal de la Aplicación ---
    def get_session(self, pin):
        lib = pkcs11.lib(LIB_PATH)
        slots = lib.get_slots(token_present=True)
        if not slots:
            raise Exception("No se detecta ningún DNIe en el lector.")
        return slots[0].get_token().open(rw=True, user_pin=pin)
        
    def perform_diagnostic(self, pin):
        self.set_buttons_state('disabled')
        self.update_status("Ejecutando diagnóstico...")
        self.log_message("\n--- INICIANDO PRUEBA DE CONEXIÓN CON DNIE ---")
        try:
            lib = pkcs11.lib(LIB_PATH)
            slots = lib.get_slots(token_present=True)
            if not slots:
                raise Exception("No se detecta ningún DNIe en el lector.")
            
            token = slots[0].get_token()
            self.log_message("✅ DNIe detectado correctamente.")
            self.log_message(f"   - Token: {token}")

            with token.open(rw=False, user_pin=pin) as session:
                self.log_message("\n✅✅✅ DIAGNÓSTICO EXITOSO ✅✅✅")
                self.log_message("   La conexión y el PIN son correctos.")
        except Exception as e:
            self.log_message(f"\n❌❌❌ DIAGNÓSTICO FALLIDO ❌❌❌")
            self.log_message(f"   Error: {e}")
        finally:
            self.set_buttons_state('normal')
            self.update_status("Diagnóstico finalizado.", 5000)

    def perform_export(self, pin, output):
        self.set_buttons_state('disabled')
        self.update_status("Exportando certificado...")
        self.log_message("\n--- INICIANDO EXPORTACIÓN DE CERTIFICADO ---")
        try:
            with self.get_session(pin) as session:
                self.log_message("🔍 Buscando certificados...")
                cert_firma = None
                for cert in session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}):
                    label = cert[Attribute.LABEL] # CORRECCIÓN A [ ]
                    if label and "firmadigital" in label.replace(" ", "").lower():
                        cert_firma = cert
                        break
                if not cert_firma:
                    raise Exception("No se encontró el certificado de firma digital.")
                
                with open(output, 'wb') as f:
                    f.write(cert_firma[Attribute.VALUE])
                self.log_message(f"✅ Certificado exportado en '{os.path.basename(output)}'")
        except Exception as e:
            self.log_message(f"❌ Error al exportar certificado: {e}")
        finally:
            self.set_buttons_state('normal')
            self.update_status("Exportación finalizada.", 5000)

    def perform_sign(self, archivos, pin):
        self.set_buttons_state('disabled')
        self.update_status("Firmando archivos...")
        self.log_message("\n--- INICIANDO PROCESO DE FIRMA ---")
        try:
            with self.get_session(pin) as session:
                self.log_message("🔍 Buscando el certificado y la clave de firma...")
                cert_firma = None
                for cert in session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}):
                    label = cert[Attribute.LABEL] # CORRECCIÓN A [ ]
                    if label and "firmadigital" in label.replace(" ", "").lower():
                        cert_firma = cert
                        break
                if not cert_firma:
                    raise Exception("No se encontró el certificado de firma digital.")
                
                cert_id = cert_firma[Attribute.ID]
                self.log_message("✅ Certificado encontrado. Buscando clave privada...")
                priv_key = next(session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY, Attribute.ID: cert_id}))
                self.log_message("✅ Clave privada encontrada. Procediendo a firmar...")
                for archivo in archivos:
                    filename = os.path.basename(archivo)
                    output_path = f"{archivo}.sig"
                    self.log_message(f"\n📄 Firmando '{filename}'...")
                    try:
                        with open(archivo, 'rb') as f: data = f.read()
                        signature = priv_key.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
                        with open(output_path, 'wb') as f: f.write(signature)
                        self.log_message(f"   ✅ Firma guardada en '{os.path.basename(output_path)}'")
                    except Exception as e:
                        self.log_message(f"   ❌ Error al firmar '{filename}': {e}")
        except Exception as e:
            self.log_message(f"❌ ERROR durante la operación de firma: {e}")
        finally:
            self.set_buttons_state('normal')
            self.update_status("Proceso de firma finalizado.", 5000)

    def perform_verify(self, documento, firma, certificado):
        self.set_buttons_state('disabled')
        self.update_status("Verificando firma...")
        self.log_message("\n--- INICIANDO VERIFICACIÓN DE FIRMA ---")
        try:
            with open(documento, 'rb') as f: data = f.read()
            with open(firma, 'rb') as f: signature = f.read()
            with open(certificado, 'rb') as f: cert_bytes = f.read()
            cert = x509.load_der_x509_certificate(cert_bytes)
            self.log_message("=== INFORMACIÓN DEL CERTIFICADO ===")
            self.log_message(f"📇 Sujeto: {cert.subject}")
            self.log_message(f"🏢 Emisor: {cert.issuer}")
            self.log_message(f"📅 Válido hasta: {cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S')} UTC")
            public_key = cert.public_key()
            public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
            self.log_message("\n✅✅✅ VERIFICACIÓN EXITOSA: La firma es válida. ✅✅✅")
        except InvalidSignature:
            self.log_message("\n❌❌❌ VERIFICACIÓN FALLIDA: ¡La firma NO es válida! ❌❌❌")
        except Exception as e:
            self.log_message(f"\n❌ ERROR durante la verificación: {e}")
        finally:
            self.set_buttons_state('normal')
            self.update_status("Verificación finalizada.", 5000)

# ==============================================================================
# === PUNTO DE ENTRADA DE LA APLICACIÓN ===
# ==============================================================================
if __name__ == '__main__':
    if not os.path.exists(LIB_PATH):
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Error de Configuración", f"No se encontró la librería PKCS#11 en la ruta:\n{LIB_PATH}\n\nPor favor, edita la variable 'LIB_PATH' en el script.")
    else:
        root = tk.Tk()
        app = DNIeApp(root)
        root.mainloop()