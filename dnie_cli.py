import pkcs11
from pkcs11 import ObjectClass, Attribute, KeyType, Mechanism
import click
from cryptography.hazmat.primitives import hashes

# === CONFIGURACIÓN ===
LIB_PATH = 'C:/Archivos de Programa/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll'

# === FUNCIÓN AUXILIAR ===
def get_session(pin):
    """Abre una sesión con el DNIe y la devuelve."""
    lib = pkcs11.lib(LIB_PATH)
    slots = lib.get_slots(token_present=True)
    if not slots:
        raise Exception("No se detecta ningún DNIe en el lector.")
    slot = slots[0]
    token = slot.get_token()
    return token.open(rw=True, user_pin=pin)

# === CLI PRINCIPAL ===
@click.group()
def cli():
    """Herramienta CLI para el DNIe (exportar certificado y firmar archivos)."""
    pass

# === COMANDO: export-cert ===
@cli.command()
@click.option('--pin', prompt=True, hide_input=True, help='PIN del DNIe.')
@click.option('--output', default='certificado_firma.der', help='Archivo de salida DER.')
def export_cert(pin, output):
    """Exporta el certificado de firma digital del DNIe."""
    try:
        with get_session(pin) as session:
            print("🔍 Buscando certificados en el DNIe...")

            certificados = list(session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}))
            if not certificados:
                raise Exception("No se encontraron certificados en el DNIe.")

            cert_firma = None
            for cert in certificados:
                label = cert[Attribute.LABEL]
                print(f"   - {label}")
                if label and "firmadigital" in label.replace(" ", "").lower():
                    cert_firma = cert
                    break

            if not cert_firma:
                raise Exception("No se encontró el certificado de firma digital (CertFirmaDigital).")

            cert_data = cert_firma[Attribute.VALUE]
            with open(output, 'wb') as f:
                f.write(cert_data)

            print(f"✅ Certificado exportado correctamente: {output}")

    except Exception as e:
        print(f"❌ Error al exportar certificado: {e}")

@cli.command()
@click.argument('archivos', nargs=-1, type=click.Path(exists=True, dir_okay=False, resolve_path=True))
@click.option('--pin', prompt=True, hide_input=True, help='PIN del DNIe.')
def sign(archivos, pin):
    """Firma uno o varios archivos con la clave privada del DNIe."""
    if not archivos:
        print("⚠️ No se ha especificado ningún archivo para firmar.")
        print("   Uso: python dnie_cli2.py sign <archivo1> <archivo2> ...")
        return

    try:
        with get_session(pin) as session:
             # --- PASO 1: Encontrar el certificado de firma primero ---
            print("🔍 Buscando el certificado de firma digital...")
            cert_firma = None
            for cert in session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}):
                label = cert[Attribute.LABEL]
                if label and "firmadigital" in label.replace(" ", "").lower():
                    cert_firma = cert
                    break
            
            if not cert_firma:
                raise Exception("No se encontró el certificado de firma digital.")

             # --- PASO 2: Obtener el ID único del certificado ---
            cert_id = cert_firma[Attribute.ID]
            print(f"✅ Certificado encontrado. Buscando clave privada asociada (ID: {bytes(cert_id).hex()})...")
            priv_key = next(session.get_objects({
                Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                Attribute.ID: cert_id  # La clave es buscar por el ID que hemos obtenido
            }))
            
            print("✅ Clave privada encontrada. Procediendo a firmar archivos...")

            # --- PASO 3: Bucle para firmar cada archivo ---
            for archivo in archivos:
                try:
                    output_path = f"{archivo}.sig"
                    
                    print(f"\n📄 Firmando '{archivo}'...")

                    with open(archivo, 'rb') as f:
                        data = f.read()

                    signature = priv_key.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)

                    with open(output_path, 'wb') as f:
                        f.write(signature)
                    
                    print(f"✅ Archivo '{archivo}' firmado correctamente.")
                    print(f"   Firma guardada en '{output_path}'")

                except Exception as e:
                    # Si un archivo falla, informa del error y continúa con el siguiente
                    print(f"   ❌ Error al firmar el archivo '{archivo}': {e}")

    except StopIteration:
        print("❌ No se encontró la clave privada asociada al certificado de firma.")
    except Exception as e:
        print(f"❌ Error durante la operación: {e}")

# === ENTRYPOINT ===
if __name__ == '__main__':
    cli()

