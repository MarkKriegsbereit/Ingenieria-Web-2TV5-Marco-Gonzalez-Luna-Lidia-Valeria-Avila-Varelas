import socketio
import serial
import serial.tools.list_ports
import time
import json
import threading

SERVER_URL = 'http://localhost:5000' 
sio = socketio.Client()
active_serial = None
is_streaming = False
current_mission = None

def listar_puertos_sistema():
    ports = serial.tools.list_ports.comports()
    return [{'device': p.device, 'desc': f"{p.device} - {p.description}"} for p in ports]

@sio.event
def connect():
    print(f"✅ Conectado a {SERVER_URL}")
    if current_mission: sio.emit('join', {'mission_id': current_mission, 'type': 'agent'})

@sio.on('server_request_ports')
def on_request(data):
    print("🔍 Solicitud puertos...")
    sio.emit('agent_response_ports', {'mission_id': current_mission, 'puertos': listar_puertos_sistema()})

@sio.on('server_command_start')
def on_start(data):
    global is_streaming, active_serial
    puerto = data['puerto']
    
    if is_streaming: return
    print(f"🚀 Iniciando en {puerto}...")
    
    try:
        test = serial.Serial(puerto); test.close()
    except Exception as e:
        sio.emit('agent_message', {'mission_id': current_mission, 'msg': f'❌ Puerto ocupado: {e}'})
        return

    is_streaming = True
    t = threading.Thread(target=leer_puerto, args=(puerto,))
    t.daemon = True
    t.start()
    
    # CONFIRMAR AL SERVER
    sio.emit('agent_confirm_start', {
        'mission_id': current_mission, 
        'port': puerto, 
        'admin_name': data['admin_name'],
        'owner_id': data['owner_id']
    })

@sio.on('server_command_stop')
def on_stop(data):
    global is_streaming, active_serial
    print("🛑 Deteniendo...")
    is_streaming = False
    if active_serial: 
        try: active_serial.close()
        except: pass

def leer_puerto(port):
    global active_serial, is_streaming
    try:
        active_serial = serial.Serial(port, 9600, timeout=1)
        while is_streaming:
            if not active_serial.is_open: break
            if active_serial.in_waiting:
                try:
                    l = active_serial.readline().decode('utf-8', errors='ignore').strip()
                    if l:
                        d = l.split(',')
                        if len(d) >= 14:
                            jd = {
                               "temperatura": float(d[0]), "humedad": int(d[1]), "presion": float(d[2]), "co2": int(d[3]),
                               "velocidad": float(d[4]), "velocidad_ang": float(d[5]), "aceleracion": float(d[6]), 
                               "altitud": float(d[8]), "apogeo": float(d[9]), "latitud": float(d[10]), "longitud": float(d[11]),
                               "evento_1": bool(int(d[12])), "evento_2": bool(int(d[13]))
                            }
                            sio.emit('ingest_telemetry', {'mission_id': current_mission, 'payload': jd, 'raw_line': l})
                            print(f"Tx > {d[8]}m")
                except: pass
            time.sleep(0.05)
    except Exception as e:
        if is_streaming: sio.emit('agent_message', {'mission_id': current_mission, 'msg': f'Error Agente: {e}'})
    finally:
        is_streaming = False
        if active_serial: active_serial.close()

if __name__ == '__main__':
    current_mission = input("ID Misión: ")
    try:
        sio.connect(SERVER_URL)
        sio.wait()
    except KeyboardInterrupt:
        print("Bye")