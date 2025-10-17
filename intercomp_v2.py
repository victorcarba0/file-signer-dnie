import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog # MODIFICADO: Añadido simpledialog
import threading
import os

# --- Librerías para la lógica del DNIe y criptografía ---
import pkcs11
from pkcs11 import ObjectClass, Attribute, Mechanism
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

# ==============================================================================
# === CONFIGURACIÓN ===
# ==============================================================================
# ⚠️ ¡IMPORTANTE! El usuario final podría necesitar ajustar esta ruta.
LIB_PATH = 'C:/Archivos de Programa/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll'

# ==============================================================================
# === CLASE PRINCIPAL DE LA APLICACIÓN ===
# ==============================================================================
class DNIeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Herramienta de Firma con DNIe (Versión Sencilla)")
        self.root.geometry("750x500")
        self.root.minsize(600, 400)

        # --- Estructura de la Interfaz ---
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 10))
        
        log_frame = ttk.Frame(main_frame)
        log_frame.pack(fill=tk.BOTH, expand=True)

        # --- Botones de acción ---
        self.sign_button = ttk.Button(button_frame, text="Firmar Archivo(s)", command=self.start_sign_thread)
        self.sign_button.pack(side=tk.LEFT, padx=(0, 5))
        self.verify_button = ttk.Button(button_frame, text="Verificar Firma", command=self.start_verify_thread)
        self.verify_button.pack(side=tk.LEFT, padx=5)
        self.export_button = ttk.Button(button_frame, text="Exportar Certificado", command=self.start_export_thread)
        self.export_button.pack(side=tk.LEFT, padx=5)
        self.diagnostic_button = ttk.Button(button_frame, text="Probar Conexión", command=self.start_diagnostic_thread)
        self.diagnostic_button.pack(side=tk.LEFT, padx=5)

        self.exit_button = ttk.Button(button_frame, text="Salir", command=self.root.destroy)
        self.exit_button.pack(side=tk.RIGHT)
        self.clear_log_button = ttk.Button(button_frame, text="Limpiar Log", command=self.clear_log)
        self.clear_log_button.pack(side=tk.RIGHT, padx=5)

        # --- Área de texto (log) ---
        self.log_area = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, state='disabled')
        self.log_area.pack(fill=tk.BOTH, expand=True)
        
        self.log_message("Bienvenido a la Herramienta de Firma con DNIe.")
        self.log_message(f"Usando librería PKCS#11 en: {LIB_PATH}\n")

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

    def set_buttons_state(self, state):
        self.root.after(0, self._set_buttons_state, state)

    def _set_buttons_state(self, state):
        buttons = [self.sign_button, self.verify_button, self.export_button, self.diagnostic_button, self.clear_log_button, self.exit_button]
        for button in buttons:
            button.config(state=state)

    # --- Lanzadores de Hilos ---
    def start_sign_thread(self):
        files = filedialog.askopenfilenames(title="Seleccione los archivos para firmar")
        if not files: return
        # MODIFICADO: Usar simpledialog en lugar de messagebox
        pin = simpledialog.askstring("PIN del DNIe", "Introduce tu PIN:", show='*')
        if not pin: return
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
        # MODIFICADO: Usar simpledialog en lugar de messagebox
        pin = simpledialog.askstring("PIN del DNIe", "Introduce tu PIN:", show='*')
        if not pin: return
        output_file = filedialog.asksaveasfilename(title="Guardar certificado como...", defaultextension=".der", filetypes=[("DER certificate", "*.der"), ("All files", "*.*")])
        if not output_file: return
        threading.Thread(target=self.perform_export, args=(pin, output_file), daemon=True).start()

    def start_diagnostic_thread(self):
        # MODIFICADO: Usar simpledialog en lugar de messagebox
        pin = simpledialog.askstring("PIN del DNIe", "Introduce tu PIN:", show='*')
        if not pin: return
        threading.Thread(target=self.perform_diagnostic, args=(pin,), daemon=True).start()

    # --- Lógica Principal de la Aplicación (Sin cambios) ---
    def get_session(self, pin):
        lib = pkcs11.lib(LIB_PATH)
        slots = lib.get_slots(token_present=True)
        if not slots:
            raise Exception("No se detecta ningún DNIe en el lector.")
        return slots[0].get_token().open(rw=True, user_pin=pin)
        
    def perform_diagnostic(self, pin):
        self.set_buttons_state('disabled')
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

    def perform_export(self, pin, output):
        self.set_buttons_state('disabled')
        self.log_message("\n--- INICIANDO EXPORTACIÓN DE CERTIFICADO ---")
        try:
            with self.get_session(pin) as session:
                self.log_message("🔍 Buscando certificados...")
                cert_firma = None
                for cert in session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}):
                    label = cert[Attribute.LABEL]
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

    def perform_sign(self, archivos, pin):
        self.set_buttons_state('disabled')
        self.log_message("\n--- INICIANDO PROCESO DE FIRMA ---")
        try:
            with self.get_session(pin) as session:
                self.log_message("🔍 Buscando el certificado y la clave de firma...")
                cert_firma = None
                for cert in session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}):
                    label = cert[Attribute.LABEL]
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

    def perform_verify(self, documento, firma, certificado):
        self.set_buttons_state('disabled')
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