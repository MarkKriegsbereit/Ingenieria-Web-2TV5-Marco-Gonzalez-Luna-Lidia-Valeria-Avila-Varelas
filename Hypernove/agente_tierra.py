import socketio
import serial
import serial.tools.list_ports
import time
import json
import threading
import sys

# --- CONFIGURACIÓN ---
SERVER_URL = 'http://3.143.186.4.sslip.io:5000' 
# 115200 es la velocidad estándar para ESP32 por cable. 
# En Bluetooth el sistema lo ignora y negocia su velocidad, así que es seguro dejarlo así.
BAUD_RATE = 115200  

sio = socketio.Client()
active_serial = None
is_streaming = False
current_mission = None

def listar_puertos_sistema():
    """
    Lista puertos agregando la descripción para identificar el Bluetooth
    """
    ports = serial.tools.list_ports.comports()
    lista = []
    for p in ports:
        # p.device es 'COMx', p.description suele decir 'Bluetooth Link' o 'CP210x USB'
        desc = f"{p.device} - {p.description}"
        lista.append({'device': p.device, 'desc': desc})
    return lista

@sio.event
def connect():
    print(f"✅ Conectado al Servidor: {SERVER_URL}")
    if current_mission: 
        sio.emit('join', {'mission_id': current_mission, 'type': 'agent'})

@sio.on('disconnect')
def on_disconnect():
    print("❌ Desconectado del servidor.")

@sio.on('server_request_ports')
def on_request(data):
    print("🔍 El servidor pide lista de puertos...")
    puertos = listar_puertos_sistema()
    sio.emit('agent_response_ports', {'mission_id': current_mission, 'puertos': puertos})

@sio.on('server_command_start')
def on_start(data):
    global is_streaming, active_serial
    puerto = data['puerto']
    
    if is_streaming: return
    print(f"🚀 Iniciando conexión en {puerto}...")
    
    # 1. Prueba rápida de conexión antes de iniciar el hilo
    try:
        test = serial.Serial(puerto, BAUD_RATE)
        test.close()
    except Exception as e:
        msg = f'❌ No se pudo abrir {puerto}. ¿Está vinculado? Error: {e}'
        print(msg)
        sio.emit('agent_message', {'mission_id': current_mission, 'msg': msg})
        return

    is_streaming = True
    
    # 2. Iniciamos el hilo de lectura
    t = threading.Thread(target=leer_puerto, args=(puerto, BAUD_RATE))
    t.daemon = True
    t.start()
    
    # 3. Confirmamos al servidor
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
    if active_serial: 
        try: active_serial.close()
        except: pass

def leer_puerto(port, baud):
    global active_serial, is_streaming
    try:
        # Timeout de 2 segundos para dar tiempo al Bluetooth
        active_serial = serial.Serial(port, baud, timeout=2)
        # Limpiamos buffers viejos
        active_serial.reset_input_buffer()
        
        print(f"🔵 Escuchando datos en {port}...")
        
        while is_streaming:
            if not active_serial.is_open: break
            
            try:
                if active_serial.in_waiting:
                    # decode('utf-8', errors='ignore') evita que se rompa si llega ruido
                    linea = active_serial.readline().decode('utf-8', errors='ignore').strip()
                    
                    if linea:
                        procesar_linea(linea)
                        
            except serial.SerialException:
                print("⚠️ Error crítico en puerto (posible desconexión).")
                break
            except Exception as e:
                print(f"⚠️ Error de lectura: {e}")
                
            time.sleep(0.01) # Pequeño respiro a la CPU
            
    except Exception as e:
        if is_streaming: 
            sio.emit('agent_message', {'mission_id': current_mission, 'msg': f'Error Serial: {e}'})
    finally:
        is_streaming = False
        if active_serial and active_serial.is_open: active_serial.close()
        print("🔌 Conexión cerrada.")

def procesar_linea(raw_line):
    # Formato esperado: temp,hum,pres,co2,vel,w,acc,acc_w,alt,apo,lat,lon,ev1,ev2
    datos = raw_line.split(',')
    
    # Validamos longitud mínima (tu ESP32 manda 14 datos)
    if len(datos) < 14: 
        return

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
        
        # Enviamos al servidor
        sio.emit('ingest_telemetry', {
            'mission_id': current_mission, 
            'payload': payload, 
            'raw_line': raw_line
        })
        print(f"📡 Tx > Alt: {datos[8]}m | Eventos: {datos[12]}-{datos[13]}")

    except ValueError:
        pass # Ignoramos líneas corruptas incompletas

if __name__ == '__main__':
    print("--- AGENTE HYPERNOVA (Soporte ESP32 / Bluetooth) ---")
    current_mission = input("Introduce el ID de la Misión: ")
    
    try:
        sio.connect(SERVER_URL)
        sio.wait()
    except Exception as e:
        print(f"❌ No se pudo conectar al servidor: {e}")
        time.sleep(3)