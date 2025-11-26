import eventlet
eventlet.monkey_patch()

import requests
import traceback
from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_socketio import SocketIO, emit, join_room, leave_room
from sqlalchemy import or_
import serial
import serial.tools.list_ports
import os
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
from datetime import datetime, timedelta
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev_key")

# GOOGLE
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://127.0.0.1:5000/google/callback")

# DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:root@127.0.0.1/Hypernova'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# SESIONES
app.config["SESSION_TYPE"] = "sqlalchemy"
app.config["SESSION_SQLALCHEMY"] = db
app.config["SESSION_SQLALCHEMY_TABLE"] = 'flask_sessions'
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)
app.config["SESSION_USE_SIGNER"] = True
Session(app)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')
active_streams = {}

# ================== MODELOS ==================
class Usuario(db.Model):
    __tablename__ = 'Usuarios'
    ID_Usuario = db.Column(db.Integer, primary_key=True)
    Nombre = db.Column(db.String(100), nullable=False)
    Password = db.Column(db.String(255), nullable=False)
    Rol = db.Column(db.Enum('admin', 'invitado', 'mantenimiento'), default='invitado')
    oauth_provider = db.Column(db.String(50), nullable=True)
    oauth_sub = db.Column(db.String(255), unique=True, nullable=True)
    email = db.Column(db.String(200), unique=True, nullable=True)

class Vehiculo(db.Model):
    __tablename__ = 'Vehiculo_CanSat'
    ID_Vehiculo = db.Column(db.Integer, primary_key=True)
    Nombre_Vehiculo = db.Column(db.String(100), nullable=False)
    Categoria = db.Column(db.String(100))
    Estado = db.Column(db.Enum('operativo', 'requiere revision'), default='operativo')

class Mision(db.Model):
    __tablename__ = 'Mision'
    ID_Mision = db.Column(db.Integer, primary_key=True)
    Nombre_Mision = db.Column(db.String(100), nullable=False)
    Fecha = db.Column(db.Date)
    Lugar = db.Column(db.String(100))
    FK_ID_Vehiculo = db.Column(db.Integer, db.ForeignKey('Vehiculo_CanSat.ID_Vehiculo'), nullable=True)
    FK_ID_Usuario = db.Column(db.Integer, db.ForeignKey('Usuarios.ID_Usuario'), nullable=True)
    vehiculo = db.relationship('Vehiculo', backref=db.backref('misiones', lazy=True))
    usuario = db.relationship('Usuario', backref=db.backref('misiones', lazy=True))

class Trama_CanSat(db.Model):
    __tablename__ = 'Trama_CanSat'
    ID_Trama = db.Column(db.Integer, primary_key=True)
    Trama = db.Column(db.String(500))
    Fecha_Hora = db.Column(db.DateTime, default=datetime.now)
    FK_ID_Mision = db.Column(db.Integer, db.ForeignKey('Mision.ID_Mision'))
    FK_ID_Usuario = db.Column(db.Integer, db.ForeignKey('Usuarios.ID_Usuario'))

class SesionModel(db.Model):
    __tablename__ = 'Sesion'
    ID_Sesion = db.Column(db.Integer, primary_key=True)
    Fecha_Hora_Inicio = db.Column(db.DateTime, nullable=False)
    Fecha_Hora_Fin = db.Column(db.DateTime, nullable=True)
    FK_ID_Usuario = db.Column(db.Integer, db.ForeignKey('Usuarios.ID_Usuario'))

# ================== LÓGICA STREAM BLINDADA ==================
def leer_puerto_mision(puerto_com, mission_id):
    str_mid = str(mission_id)
    print(f"🚀 Iniciando Misión {mission_id} en {puerto_com}")
    ser = None
    
    try:
        # write_timeout evita bloqueos si el dispositivo deja de responder
        ser = serial.Serial(puerto_com, 9600, timeout=1, write_timeout=1)
        ser.reset_input_buffer()
        socketio.emit('status_msg', {'msg': f'🔴 EN VIVO: Conectado a {puerto_com}'}, to=str_mid)
        
        while True:
            # Chequeo de bandera de parada
            if str_mid not in active_streams or active_streams[str_mid]['stop']:
                break
            
            # Lectura segura
            try:
                if ser.in_waiting > 0:
                    linea = ser.readline().decode('utf-8', errors='ignore').strip()
                    if linea:
                        # Parseo y envío...
                        d = linea.split(',')
                        if len(d) >= 14:
                            json_data = {
                                "temperatura": float(d[0]), "humedad": int(d[1]), "presion": float(d[2]), "co2": int(d[3]),
                                "velocidad": float(d[4]), "velocidad_ang": float(d[5]), "aceleracion": float(d[6]), "aceleracion_ang": float(d[7]),
                                "altitud": float(d[8]), "apogeo": float(d[9]), "latitud": float(d[10]), "longitud": float(d[11]),
                                "evento_1": bool(int(d[12])), "evento_2": bool(int(d[13]))
                            }
                            socketio.emit('telemetria', json_data, to=str_mid)
                            with app.app_context():
                                db.session.add(Trama_CanSat(Trama=linea, FK_ID_Mision=mission_id, FK_ID_Usuario=1))
                                db.session.commit()
            except (OSError, serial.SerialException):
                # ESTO CAPTURA LA DESCONEXIÓN FÍSICA DEL CABLE
                print(f"⚠️ Dispositivo desconectado en {puerto_com}")
                socketio.emit('status_msg', {'msg': '⚠️ ERROR: Dispositivo desconectado abruptamente.'}, to=str_mid)
                break # Romper el bucle para ir al finally
            except Exception:
                pass # Errores de parseo ignorados
            
            socketio.sleep(0.01)

    except Exception as e:
        socketio.emit('status_msg', {'msg': f'Error Conexión: {str(e)}'}, to=str_mid)
    
    finally:
        # LIMPIEZA CRÍTICA
        if ser and ser.is_open:
            try: ser.close()
            except: pass
            
        if str_mid in active_streams: 
            del active_streams[str_mid]
            
        # AVISAR AL FRONTEND QUE SE ACABÓ
        # Esto resetea los botones del admin
        print(f"🛑 Stream Misión {mission_id} finalizado.")
        socketio.emit('status_msg', {'msg': 'Transmisión finalizada.'}, to=str_mid)
        socketio.emit('stream_ended', {'force_reset': True}, to=str_mid)

# ================== AUTH ==================
oauth = OAuth(app)
oauth.register(name='google', client_id=GOOGLE_CLIENT_ID, client_secret=GOOGLE_CLIENT_SECRET, server_metadata_url='https://accounts.google.com/.well-known/openid-configuration', client_kwargs={'scope': 'openid email profile'})

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session: return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapped

def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if session.get('role') != 'admin': return redirect(url_for('home'))
        return f(*args, **kwargs)
    return wrapped

# ================== RUTAS ==================
@app.route('/')
def home(): return render_template("index.html")

@app.route('/login', methods=['GET','POST'])
def login():
    if 'user_id' in session: return redirect(url_for('catalogo_misiones'))
    if request.method == 'POST':
        email = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        user = Usuario.query.filter_by(email=email).first()
        if user and check_password_hash(user.Password, password):
            session.clear()
            session['user_id'] = user.ID_Usuario
            session['role'] = user.Rol
            session['email'] = user.email
            session['name'] = user.Nombre
            session.permanent = True
            ns = SesionModel(Fecha_Hora_Inicio=datetime.now(), FK_ID_Usuario=user.ID_Usuario)
            db.session.add(ns)
            db.session.commit()
            session['id_bitacora'] = ns.ID_Sesion
            return redirect(url_for('catalogo_misiones'))
        else:
            return render_template('login.html', mensaje="Datos incorrectos")
    return render_template('login.html')

@app.route('/login_local')
def login_local():
    c = "invitado@local.lan"
    u = Usuario.query.filter_by(email=c).first()
    if not u:
        u = Usuario(Nombre="Espectador LAN", email=c, Password=generate_password_hash("lan"), Rol="invitado", oauth_provider="local")
        db.session.add(u)
        db.session.commit()
    session.clear()
    session['user_id'] = u.ID_Usuario
    session['role'] = u.Rol
    session['email'] = u.email
    session['name'] = u.Nombre
    session.permanent = True
    return redirect(url_for('catalogo_misiones'))

@app.route('/logout')
def logout():
    bid = session.get('id_bitacora')
    if bid:
        s = SesionModel.query.get(bid)
        if s:
            s.Fecha_Hora_Fin = datetime.now()
            db.session.commit()
    session.clear()
    return redirect(url_for('login'))

# GOOGLE
@app.route("/google_login")
def google_login():
    return redirect(f"https://accounts.google.com/o/oauth2/v2/auth?client_id={GOOGLE_CLIENT_ID}&redirect_uri={GOOGLE_REDIRECT_URI}&response_type=code&scope=openid%20email%20profile")

@app.route("/google/callback")
def google_callback():
    code = request.args.get("code")
    if not code: return redirect(url_for("login"))
    token_url = "https://oauth2.googleapis.com/token"
    token_data = {"code": code, "client_id": GOOGLE_CLIENT_ID, "client_secret": GOOGLE_CLIENT_SECRET, "redirect_uri": GOOGLE_REDIRECT_URI, "grant_type": "authorization_code"}
    try:
        tr = requests.post(token_url, data=token_data, verify=False).json()
        at = tr.get("access_token")
        ui = requests.get("https://www.googleapis.com/oauth2/v2/userinfo", headers={"Authorization": f"Bearer {at}"}, verify=False).json()
        email, sub, name = ui.get("email"), ui.get("id"), ui.get("name")
        u = Usuario.query.filter(or_(Usuario.oauth_sub == sub, Usuario.email == email)).first()
        if not u:
            u = Usuario(Nombre=name, email=email, Password="", Rol="invitado", oauth_provider="google", oauth_sub=sub)
            db.session.add(u)
            db.session.commit()
        session['user_id'] = u.ID_Usuario
        session['email'] = u.email
        session['role'] = u.Rol
        session['name'] = u.Nombre
        session.permanent = True
        return redirect(url_for('catalogo_misiones'))
    except:
        flash("Error Google. Usa Local.", "error")
        return redirect(url_for('login'))

# RUTAS SISTEMA
@app.route('/catalogo')
@login_required
def catalogo_misiones():
    misiones = Mision.query.all()
    lista = []
    rol_actual = session.get('role')
    for m in misiones:
        en_vivo = str(m.ID_Mision) in active_streams
        if rol_actual != 'admin' and not en_vivo: continue
        puerto = active_streams[str(m.ID_Mision)]['port'] if en_vivo else None
        broadcaster = active_streams[str(m.ID_Mision)].get('admin_name', 'Admin') if en_vivo else None
        lista.append({'id': m.ID_Mision, 'nombre': m.Nombre_Mision, 'fecha': m.Fecha, 'lugar': m.Lugar, 'en_vivo': en_vivo, 'puerto': puerto, 'broadcaster': broadcaster})
    return render_template('catalogo.html', misiones=lista)

@app.route('/sala/<int:id_mision>')
@login_required
def sala_mision(id_mision):
    mision = Mision.query.get_or_404(id_mision)
    es_admin = (session.get('role') == 'admin')
    return render_template('dashboard_sala.html', mision=mision, es_admin=es_admin)

# PANELES
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard(): return render_template('admin.html')

@app.route('/invitado', methods=['GET', 'POST'])
@login_required
def invitado_dashboard():
    u = Usuario.query.get(session.get('user_id'))
    if request.method == 'POST':
        u.Nombre = request.form['nombre']
        u.email = request.form['email']
        if request.form.get('password'): u.Password = generate_password_hash(request.form['password'])
        db.session.commit()
        session['name'] = u.Nombre
        return redirect(url_for('invitado_dashboard'))
    return render_template("invitado.html", usuario=u)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        n, e, p = request.form.get('username'), request.form.get('email'), request.form.get('password')
        if not Usuario.query.filter_by(email=e).first():
            nu = Usuario(Nombre=n, email=e, Password=generate_password_hash(p), Rol='invitado', oauth_provider='local')
            db.session.add(nu)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template("register.html")

# CRUD
@app.route('/admin/usuarios')
@login_required
@admin_required
def usuarios_list(): return render_template('usuarios_list.html', usuarios=Usuario.query.all())
@app.route('/admin/usuarios/crear', methods=['GET', 'POST'])
@login_required
@admin_required
def usuarios_crear():
    if request.method == 'POST':
        db.session.add(Usuario(Nombre=request.form['nombre'], email=request.form['email'], Password=generate_password_hash(request.form['password']), Rol=request.form['rol']))
        db.session.commit()
        return redirect(url_for('usuarios_list'))
    return render_template('usuario_form.html', accion='crear')
@app.route('/admin/usuarios/editar/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def usuarios_editar(id):
    u = Usuario.query.get_or_404(id)
    if request.method == 'POST':
        u.Nombre, u.email, u.Rol = request.form['nombre'], request.form['email'], request.form['rol']
        if request.form.get('password'): u.Password = generate_password_hash(request.form.get('password'))
        db.session.commit()
        return redirect(url_for('usuarios_list'))
    return render_template('usuario_form.html', accion='editar', usuario=u)
@app.route('/admin/usuarios/eliminar/<int:id>', methods=['POST'])
@login_required
@admin_required
def usuarios_eliminar(id):
    db.session.delete(Usuario.query.get_or_404(id))
    db.session.commit()
    return redirect(url_for('usuarios_list'))
@app.route('/admin/vehiculos')
@login_required
@admin_required
def vehiculos_list(): return render_template('vehiculos_list.html', vehiculos=Vehiculo.query.all())
@app.route('/admin/vehiculos/crear', methods=['GET', 'POST'])
@login_required
@admin_required
def vehiculos_crear():
    if request.method == 'POST':
        db.session.add(Vehiculo(Nombre_Vehiculo=request.form['nombre'], Categoria=request.form['categoria'], Estado=request.form['estado']))
        db.session.commit()
        return redirect(url_for('vehiculos_list'))
    return render_template('vehiculo_form.html', accion='crear')
@app.route('/admin/vehiculos/editar/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def vehiculos_editar(id):
    v = Vehiculo.query.get_or_404(id)
    if request.method == 'POST':
        v.Nombre_Vehiculo, v.Categoria, v.Estado = request.form['nombre'], request.form['categoria'], request.form['estado']
        db.session.commit()
        return redirect(url_for('vehiculos_list'))
    return render_template('vehiculo_form.html', accion='editar', vehiculo=v)
@app.route('/admin/vehiculos/eliminar/<int:id>', methods=['POST'])
@login_required
@admin_required
def vehiculos_eliminar(id):
    db.session.delete(Vehiculo.query.get_or_404(id))
    db.session.commit()
    return redirect(url_for('vehiculos_list'))
@app.route('/admin/misiones')
@login_required
def misiones_list(): return render_template('misiones_list.html', misiones=Mision.query.all())
@app.route('/admin/misiones/crear', methods=['GET', 'POST'])
@login_required
@admin_required
def misiones_crear():
    if request.method == 'POST':
        m = Mision(Nombre_Mision=request.form['nombre'], Fecha=request.form['fecha'] or None, Lugar=request.form['lugar'])
        if request.form.get('vehiculo'): m.FK_ID_Vehiculo = request.form.get('vehiculo')
        if request.form.get('usuario'): m.FK_ID_Usuario = request.form.get('usuario')
        db.session.add(m)
        db.session.commit()
        return redirect(url_for('misiones_list'))
    return render_template('mision_form.html', accion='crear', vehiculos=Vehiculo.query.all(), usuarios=Usuario.query.all())
@app.route('/admin/misiones/editar/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def misiones_editar(id):
    m = Mision.query.get_or_404(id)
    if request.method == 'POST':
        m.Nombre_Mision, m.Fecha, m.Lugar = request.form['nombre'], request.form['fecha'] or None, request.form['lugar']
        m.FK_ID_Vehiculo, m.FK_ID_Usuario = request.form.get('vehiculo'), request.form.get('usuario')
        db.session.commit()
        return redirect(url_for('misiones_list'))
    return render_template('mision_form.html', accion='editar', mision=m, vehiculos=Vehiculo.query.all(), usuarios=Usuario.query.all())
@app.route('/admin/misiones/eliminar/<int:id>', methods=['POST'])
@login_required
@admin_required
def misiones_eliminar(id):
    db.session.delete(Mision.query.get_or_404(id))
    db.session.commit()
    return redirect(url_for('misiones_list'))

# SOCKETS
@socketio.on('join')
def on_join(data):
    room = str(data['mission_id'])
    join_room(room)
    if room in active_streams:
        emit('status_msg', {'msg': f'✅ Conectado ({active_streams[room]["port"]})'})
        if active_streams[room]['owner_id'] == session.get('user_id'):
            emit('you_are_broadcaster', {'val': True})
    else:
        emit('status_msg', {'msg': 'Esperando transmisión...'})

@socketio.on('start_stream_mission')
def handle_start(data):
    if session.get('role') != 'admin': return
    mid, puerto = str(data['mission_id']), data['puerto']
    if mid in active_streams: return
    u = Usuario.query.get(session.get('user_id'))
    active_streams[mid] = {'stop': False, 'port': puerto, 'owner_id': session.get('user_id'), 'admin_name': u.Nombre}
    socketio.start_background_task(leer_puerto_mision, puerto, mid)
    emit('status_msg', {'msg': 'Iniciando...'})
    emit('you_are_broadcaster', {'val': True})

@socketio.on('stop_stream_mission')
def handle_stop(data):
    mid = str(data['mission_id'])
    
    # REGLA DE SEGURIDAD:
    # Si el ID está en streams activos, intentamos detenerlo.
    if mid in active_streams:
        # OPCIONAL: Validar owner_id si quieres que SOLO el dueño original pueda parar
        # if active_streams[mid]['owner_id'] == session.get('user_id'): ...
        
        active_streams[mid]['stop'] = True
        emit('status_msg', {'msg': 'Deteniendo...'})
        
    else:
        # FIX CLAVE: Si la transmisión ya murió (por error de cable), forzamos el reseteo visual
        # Le decimos al cliente "Ya no hay stream, actualiza tus botones"
        emit('stream_ended', {'force_reset': True})
        emit('status_msg', {'msg': 'Stream inactivo. Interfaz reseteada.'})

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    for mid, data in list(active_streams.items()):
        if data.get('admin_sid') == sid:
            data['stop'] = True
            socketio.emit('status_msg', {'msg': '⚠️ Host desconectado'}, to=mid)

@socketio.on('buscar_puertos')
def handle_scan():
    try:
        emit('lista_puertos', [{'device': p.device, 'desc': f"{p.device} ({p.description})"} for p in serial.tools.list_ports.comports()])
    except: emit('lista_puertos', [])

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    print("🚀 Hypernova Server: Online en 0.0.0.0:5000")
    socketio.run(app, host='0.0.0.0', debug=True, port=5000, allow_unsafe_werkzeug=True)