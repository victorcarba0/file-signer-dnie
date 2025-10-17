# Importamos la librería principal para la comunicación PKCS#11
import pkcs11
import getpass
# Importamos algunos tipos de objetos y atributos que nos ayudarán a buscar cosas
from pkcs11 import ObjectClass, Attribute

# --- CONFIGURACIÓN ---
# Ruta a la librería PKCS#11 (OpenSC en Windows)
LIB_PATH = 'C:/Archivos de Programa/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll'  # ⚠️ AJUSTA SEGÚN TU INSTALACIÓN

# --- CÓDIGO PRINCIPAL ---
try:
    # Cargamos la librería PKCS#11 desde la ruta que hemos definido
    lib = pkcs11.lib(LIB_PATH)

    # Obtenemos la primera "ranura" (slot) donde hay un token (el DNIe) presente
    slots = lib.get_slots(token_present=True)
    if not slots:
        raise Exception("No se detecta ningún token en el lector.")

    slot = slots[0]
    token = slot.get_token()

    print("✅ DNIe detectado correctamente.")
    print(f"   - Slot: {slot}")
    print(f"   - Token (DNIe): {token}")

    # Abrimos una sesión con el token
    pin = getpass.getpass("Introduce el PIN de tu DNIe: ")
    with token.open(user_pin=pin) as session:
        print("\n✅ Sesión iniciada con éxito.")

except Exception as e:
    print(f"❌ Error: {e}")
    print("   Asegúrate de que el DNIe está insertado, la ruta de la librería es correcta y el PIN es válido.")
