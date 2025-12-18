import socketio
import serial
import serial.tools.list_ports
import time
import threading
import platform
import sys

# --- CONFIGURACIÓN ---
SERVER_URL = 'http://3.143.186.4.sslip.io:5000' 
BAUD_RATE = 115200  

sio = socketio.Client()
active_serial = None
is_streaming = False
current_mission = None

def listar_puertos_sistema():
    """Detecta puertos según el Sistema Operativo y filtra para Mac"""
    sistema = platform.system()
    ports = serial.tools.list_ports.comports()
    lista = []
    for p in ports:
        # En Mac, filtramos para evitar puertos 'Incoming' que bloquean el agente
        if sistema == "Darwin":
            if "cu." in p.device and "Incoming" not in p.device:
                lista.append({'device': p.device, 'desc': f"{p.device} - {p.description}"})
        else:
            # En Windows (COM) incluimos todos
            lista.append({'device': p.device, 'desc': f"{p.device} - {p.description}"})
    return lista

@sio.event
def connect():
    print(f"✅ Conectado al Servidor: {SERVER_URL}")
    if current_mission: 
        sio.emit('join', {'mission_id': current_mission, 'type': 'agent'})

@sio.on('server_request_ports')
def on_request(data):
    print("🔍 El servidor pide lista de puertos...")
    puertos = listar_puertos_sistema()
    sio.emit('agent_response_ports', {'mission_id': current_mission, 'puertos': puertos})

@sio.on('server_command_start')
def on_start(data):
    global is_streaming
    puerto = data['puerto']
    if is_streaming: return
    
    print(f"🚀 Intentando abrir {puerto}...")
    is_streaming = True
    
    # Iniciamos el hilo de lectura
    t = threading.Thread(target=leer_puerto_thread, args=(puerto, BAUD_RATE))
    t.daemon = True
    t.start()
    
    sio.emit('agent_confirm_start', {
        'mission_id': current_mission, 
        'port': puerto, 
        'admin_name': data['admin_name'],
        'owner_id': data['owner_id']
    })

@sio.on('server_command_stop')
def on_stop(data):
    global is_streaming, active_serial
    print("🛑 Comando de paro recibido.")
    is_streaming = False
    # En Mac, cambiar el estado del puerto ayuda a romper el bucle sin Error 9
    if active_serial:
        try: active_serial.is_open = False 
        except: pass

def leer_puerto_thread(port, baud):
    global active_serial, is_streaming
    try:
        # Timeout corto para detectar desconexiones rápido
        active_serial = serial.Serial(port, baud, timeout=1) 
        active_serial.reset_input_buffer()
        print(f"🔵 Escuchando datos en {port}...")
        
        while is_streaming:
            # Verificación proactiva: ¿El puerto sigue abierto?
            if not active_serial or not active_serial.is_open:
                raise serial.SerialException("El puerto se cerró inesperadamente.")
            
            try:
                if active_serial.in_waiting:
                    linea = active_serial.readline().decode('utf-8', errors='ignore').strip()
                    if linea:
                        procesar_linea(linea)
                else:
                    # Opcional: Si no hay datos en 5 segundos, podrías lanzar un timeout
                    pass
            except serial.SerialException as e:
                # Si el dispositivo se desconecta físicamente durante la lectura
                raise e 
                
            time.sleep(0.01)
            
    except Exception as e:
        print(f"❌ ERROR CRÍTICO DE HARDWARE: {e}")
        # 1. Informar el error específico a la sala
        sio.emit('agent_message', {
            'mission_id': current_mission, 
            'msg': f'⚠️ SEÑAL PERDIDA: El dispositivo se desconectó ({port})'
        })
        # 2. IMPORTANTE: Pedir al servidor que detenga la misión formalmente
        sio.emit('stop_stream_mission', {'mission_id': current_mission})
        
    finally:
        is_streaming = False
        if active_serial:
            try:
                active_serial.close()
            except:
                pass
            active_serial = None
        print("🔌 Hilo de lectura finalizado y puerto liberado.")

        
def procesar_linea(raw_line):
    datos = raw_line.split(',')
    if len(datos) < 14: return

    try:
        payload = {
            "temperatura": float(datos[0]), 
            "humedad": int(datos[1]), 
            "presion": float(datos[2]), 
            "co2": int(datos[3]),
            "velocidad": float(datos[4]), 
            "velocidad_ang": float(datos[5]), 
            "aceleracion": float(datos[6]), 
            "acc_ang": float(datos[7]),
            "altitud": float(datos[8]), 
            "apogeo": float(datos[9]), 
            "latitud": float(datos[10]), 
            "longitud": float(datos[11]),
            # Convertimos "1"/"0" a True/False
            "evento_1": bool(int(datos[12])), 
            "evento_2": bool(int(datos[13]))
        }
        sio.emit('ingest_telemetry', {'mission_id': current_mission, 'payload': payload, 'raw_line': raw_line})
        print(f"📡 Tx > Alt: {datos[8]}m | Eventos: {datos[12]}-{datos[13]}")
    except: pass

if __name__ == '__main__':
    print("--- AGENTE HYPERNOVA MULTIPLATAFORMA ---")
    current_mission = input("Introduce el ID de la Misión: ")
    try:
        sio.connect(SERVER_URL)
        sio.wait()
    except KeyboardInterrupt:
        print("\n👋 Saliendo...")
        sys.exit(0)