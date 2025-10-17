import click
import subprocess
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization # Importamos 'serialization'
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature # Para capturar el error específico

@click.group()
def cli():
    """Herramienta para verificar firmas digitales con el DNIe."""
    pass

@cli.command()
@click.argument('documento', type=click.Path(exists=True))
@click.argument('firma', type=click.Path(exists=True))
@click.argument('certificado', type=click.Path(exists=True))
def verify(documento, firma, certificado):
    """Verifica la firma de un DOCUMENTO usando la FIRMA y el CERTIFICADO (DER)."""
    try:
        # --- Leer archivos ---
        with open(documento, 'rb') as f:
            data = f.read()
        with open(firma, 'rb') as f:
            signature = f.read()
        with open(certificado, 'rb') as f:
            cert_bytes = f.read()

        # --- Cargar certificado ---
        cert = x509.load_der_x509_certificate(cert_bytes)

        print("\n=== INFORMACIÓN DEL CERTIFICADO ===")
        print(f"📇 Sujeto: {cert.subject}")
        print(f"🏢 Emisor: {cert.issuer}")
        print(f"📅 Válido desde: {cert.not_valid_before_utc.strftime('%Y-%m-%d %H:%M:%S')} UTC")
        print(f"📅 Válido hasta: {cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S')} UTC")

        # --- Calcular hash para mostrarlo ---
        hash_documento = hashlib.sha256(data).hexdigest()
        print(f"\n🔐 Hash del documento (SHA-256): {hash_documento}")

        # --- Intentar verificación con cryptography (MÉTODO SIMPLIFICADO Y ROBUSTO) ---
        print("\n🔍 Intentando verificación con librería 'cryptography'...")
        try:
            public_key = cert.public_key()
            # Dejamos que la librería haga el hash internamente. Es más fiable.
            public_key.verify(
                signature,
                data,  # Pasamos los datos originales, no el hash
                padding.PKCS1v15(),
                hashes.SHA256() # Indicamos el algoritmo de hash que debe usar
            )
            print("\n✅✅✅ VERIFICACIÓN EXITOSA ✅✅✅")
            return
        except InvalidSignature:
            print("⚠️  Verificación con 'cryptography' falló. La firma no es válida.")
        except Exception as e:
            print(f"⚠️  Ocurrió un error inesperado con 'cryptography': {e}")

    except Exception as e:
        print(f"\n❌❌❌ ERROR GENERAL ❌❌❌")
        print(f"No se pudo completar la verificación: {e}")

if __name__ == '__main__':
    cli()

