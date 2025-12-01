# agente_tierra.py - Corre en la laptop con el CanSat conectado
import serial
import socketio
import time
import os
from dotenv import load_dotenv

# Cargamos variables de entorno (si usas un archivo .env en tu laptop)
load_dotenv()

# =========================================================
# --- CONFIGURACIÓN DE CONEXIÓN (AJUSTAR ESTO) ---
# =========================================================
# URL del servidor en Azure o la IP pública de tu VM de Ubuntu
# ¡Cámbiala a la dirección real de tu despliegue en la nube!
# Ejemplo: AZURE_SERVER_URL = "http://20.10.10.5" o "https://tuhypernova.azurewebsites.net"
AZURE_SERVER_URL = os.getenv("AZURE_SERVER_URL", "http://localhost:5000")

sio = socketio.Client()
# El ID de usuario que se usa para guardar los datos en la DB (Usuario 1 = Sistema/Admin)
# Asegúrate de que este ID exista en tu tabla Usuarios en Azure.
FK_ID_USUARIO_SISTEMA = 1 

# =========================================================
# --- MANEJO DE EVENTOS SOCKET.IO ---
# =========================================================

@sio.event
def connect():
    """Se ejecuta al establecer la conexión con el servidor."""
    print(f"✅ Conectado al servidor en: {AZURE_SERVER_URL}")
    print("Iniciando lectura de puerto serial...")

@sio.event
def disconnect():
    """Se ejecuta al perder la conexión con el servidor."""
    print("❌ Desconectado del servidor de Azure. Transmisión terminada.")

# =========================================================
# --- LÓGICA DE PROCESAMIENTO Y ENVÍO ---
# =========================================================

def parse_data(trama_str):
    """ 
    Procesa la línea CSV del CanSat en un JSON estructurado. 
    ¡Esta lógica debe ser IDÉNTICA a la que el servidor usa para reportes!
    """
    try:
        # Formato esperado: temp,hum,pres,co2,vel,vang,acc,aang,alt,apo,lat,lon,ev1,ev2
        d = trama_str.strip().split(',')
        if len(d) < 14: return None
        
        # Aquí se crea el JSON (payload) que se envía a la nube
        return {
            "temperatura": float(d[0]), "humedad": int(d[1]), "presion": float(d[2]), "co2": int(d[3]),
            "velocidad": float(d[4]), "velocidad_ang": float(d[5]), "aceleracion": float(d[6]), "aceleracion_ang": float(d[7]),
            "altitud": float(d[8]), "apogeo": float(d[9]), "latitud": float(d[10]), "longitud": float(d[11]),
            "evento_1": bool(int(d[12])), "evento_2": bool(int(d[13]))
        }
    except Exception as e:
        # print(f"Error de parseo en la línea: {trama_str} ({e})")
        return None

def start_telemetry_stream(port, mission_id):
    """
    Abre el puerto serial, lee los datos y los envía a la nube.
    """
    str_mid = str(mission_id)
    print(f"📡 Intentando abrir puerto {port}...")
    ser = None
    
    try:
        # 9600 es la velocidad estándar, ajústala si tu CanSat usa otra
        ser = serial.Serial(port, 9600, timeout=1, write_timeout=1)
        ser.reset_input_buffer()
        print(f"✅ Puerto {port} abierto. Iniciando transmisión de Misión #{str_mid}.")
    except serial.SerialException as e:
        print(f"🚫 ERROR: No se pudo abrir el puerto {port}.")
        print("Asegúrate de que el Arduino esté conectado, el puerto sea correcto y no esté en uso.")
        return
    except Exception as e:
        print(f"Error desconocido al abrir el puerto: {e}")
        return

    # Bucle principal de lectura y envío
    while True:
        try:
            # 1. Chequeo de conexión (si se pierde, rompemos el bucle)
            if not sio.connected:
                print("🛑 Conexión con el servidor perdida. Terminando stream local.")
                break

            # 2. Lectura segura del puerto serial
            if ser.in_waiting > 0:
                # La línea cruda que recibes, ejemplo: "25.5,80,1013.2..."
                raw_line = ser.readline().decode('utf-8', errors='ignore').strip()
                
                if raw_line:
                    payload = parse_data(raw_line)
                    
                    if payload:
                        # 3. Envía los datos al servidor en Azure mediante el evento 'ingest_telemetry'
                        sio.emit('ingest_telemetry', {
                            'mission_id': str_mid,
                            'payload': payload,      # Datos parseados (JSON)
                            'raw_line': raw_line,    # La línea cruda (para guardar en BD)
                            'user_id': FK_ID_USUARIO_SISTEMA 
                        })
                        print(f"-> Enviado (Misión #{str_mid}): {raw_line[:60]}...")
            
            time.sleep(0.01) # Espera mínima para no sobrecargar el CPU
        
        except KeyboardInterrupt:
            print("\nDeteniendo la transmisión manualmente...")
            # 4. Avisa al servidor que el stream ha terminado
            sio.emit('ingest_stop', {'mission_id': str_mid})
            break
        except Exception as e:
            print(f"Error durante la transmisión: {e}")
            break
    
    # 5. Limpieza final
    if ser and ser.is_open:
        ser.close()
    if sio.connected:
        sio.disconnect()
    print("Misión de telemetría local finalizada.")


# =========================================================
# --- PUNTO DE ENTRADA PRINCIPAL ---
# =========================================================

if __name__ == '__main__':
    print("\n--- 🛰️ AGENTE DE TIERRA HYPERNOVA ---")
    
    # 1. Solicitar datos de la misión
    try:
        mission_id = int(input(f"1. Ingrese el ID de la Misión (Debe existir en Azure): "))
    except ValueError:
        print("ID de misión no válido. Saliendo.")
        exit()
        
    # 2. Solicitar puerto serial
    serial_port = input("2. Ingrese el Puerto Serial (Ej: COM3 en Windows o /dev/ttyUSB0 en Ubuntu/Mac): ").strip()
    
    # 3. Conectar a Azure
    try:
        sio.connect(AZURE_SERVER_URL)
    except Exception as e:
        print(f"🚫 ERROR: No se pudo conectar al servidor de Azure.")
        print(f"Revise la URL ({AZURE_SERVER_URL}) y asegúrese de que la VM/Azure esté encendida y accesible.")
        print(f"Detalles: {e}")
        exit()

    # 4. Iniciar la transmisión
    start_telemetry_stream(serial_port, mission_id)