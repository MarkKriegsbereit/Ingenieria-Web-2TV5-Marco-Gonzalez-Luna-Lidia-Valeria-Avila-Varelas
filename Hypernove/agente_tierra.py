import socketio
import serial
import serial.tools.list_ports
import time
import threading
import platform
import sys

# --- CONFIGURACIÓN ---
SERVER_URL = 'http://127.0.0.1:5000' 
BAUD_RATE = 115200  

sio = socketio.Client(reconnection=True, reconnection_attempts=5, reconnection_delay=1)
active_serial = None
is_streaming = False
current_mission = None
serial_lock = threading.Lock() # Previene colisiones al cerrar/abrir el puerto

def listar_puertos_sistema():
    sistema = platform.system()
    ports = serial.tools.list_ports.comports()
    lista = []
    for p in ports:
        if sistema == "Darwin":
            if "cu." in p.device and "Incoming" not in p.device:
                lista.append({'device': p.device, 'desc': f"{p.device}"})
        else:
            lista.append({'device': p.device, 'desc': f"{p.device} - {p.description}"})
    return lista

@sio.event
def connect():
    print(f"✅ Conectado al Servidor: {SERVER_URL}")
    if current_mission: 
        sio.emit('join', {'mission_id': current_mission, 'type': 'agent'})

@sio.on('server_request_ports')
def on_request(data):
    puertos = listar_puertos_sistema()
    sio.emit('agent_response_ports', {'mission_id': current_mission, 'puertos': puertos})

@sio.on('server_command_start')
def on_start(data):
    global is_streaming
    puerto = data['puerto']
    
    # Si ya está transmitiendo, forzamos un stop previo para limpiar
    if is_streaming:
        print("🔄 Reiniciando transmisión previa...")
        detener_transmision()
        time.sleep(1)

    is_streaming = True
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
    print("🛑 Comando de paro recibido del servidor.")
    detener_transmision()

def detener_transmision():
    global is_streaming, active_serial
    is_streaming = False
    with serial_lock:
        if active_serial and active_serial.is_open:
            try:
                active_serial.cancel_read() # Despierta al hilo si está bloqueado en readline
                active_serial.close()
                print("🔌 Puerto serie cerrado manualmente.")
            except Exception as e:
                print(f"⚠️ Error al cerrar puerto: {e}")
            finally:
                active_serial = None

def leer_puerto_thread(port, baud):
    global active_serial, is_streaming
    try:
        # Importante: timeout=0.1 hace que readline() no se bloquee
        active_serial = serial.Serial(port, baud, timeout=0.1) 
        active_serial.reset_input_buffer()
        
        last_data_time = time.time()
        
        while is_streaming:
            # Si el puerto desaparece o se cierra
            if not active_serial or not active_serial.is_open:
                break
                
            try:
                if active_serial.in_waiting > 0:
                    linea = active_serial.readline().decode('utf-8', errors='ignore').strip()
                    if linea:
                        procesar_linea(linea)
                        last_data_time = time.time() # Actualizamos cronómetro interno
                
                # SI NO HAY DATOS DEL ESP32 POR 5 SEGUNDOS (aunque el USB siga puesto)
                if (time.time() - last_data_time) > 5:
                    print("⚠️ No llegan datos del ESP32...")
                    sio.emit('agent_message', {'mission_id': current_mission, 'msg': '⚠️ Sin datos del sensor...'})
                    last_data_time = time.time() # Reset para no spamear

            except (serial.SerialException, OSError):
                print("❌ Puerto desconectado físicamente.")
                break
            
            time.sleep(0.01)
            
    except Exception as e:
        print(f"❌ No se pudo abrir el puerto {port}: {e}")
        sio.emit('agent_message', {'mission_id': current_mission, 'msg': f'Error de hardware: {e}'})
    
    finally:
        # Notificar al servidor que la misión debe morir
        if is_streaming: # Si el bucle se rompió por error, avisamos
            sio.emit('stop_stream_mission', {'mission_id': current_mission})
        detener_transmision()
        print("🏁 Hilo de lectura finalizado.")



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
    except: pass

if __name__ == '__main__':
    print("--- AGENTE HYPERNOVA V2 (RECONEXIÓN ROBUSTA) ---")
    current_mission = input("Introduce el ID de la Misión: ")
    try:
        sio.connect(SERVER_URL)
        sio.wait()
    except KeyboardInterrupt:
        detener_transmision()
        sys.exit(0)