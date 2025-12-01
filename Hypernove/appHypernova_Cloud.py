import eventlet
eventlet.monkey_patch()

import requests
from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_socketio import SocketIO, emit, join_room, leave_room
from sqlalchemy import or_
# --- ELIMINADAS: serial, serial.tools.list_ports (ya no son necesarias en la nube)
import os
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
from datetime import datetime, timedelta
import urllib3
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev_key")

# =========================================================
# === CONFIGURACIÓN DE NUBE (Variables de Entorno) ========
# =========================================================

# GOOGLE
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
# IMPORTANTE: Esta URL debe ser la URL pública de Azure/VM
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI") 

# DB - Se lee de la variable de entorno DATABASE_URL
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
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

# Registro de transmisiones activas (Metadata)
# Ahora solo guarda si la misión está activa y cuándo inició
active_streams = {} 

# ================== MODELOS (IDÉNTICOS) ==================
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

class ReporteMantenimiento(db.Model):
    __tablename__ = 'Reporte_Mantenimiento'
    ID_Reporte = db.Column(db.Integer, primary_key=True)
    Comentarios = db.Column(db.Text, nullable=False)
    Fecha_Hora_Reporte = db.Column(db.DateTime, default=datetime.now)
    FK_ID_Vehiculo = db.Column(db.Integer, db.ForeignKey('Vehiculo_CanSat.ID_Vehiculo'))
    FK_ID_Usuario = db.Column(db.Integer, db.ForeignKey('Usuarios.ID_Usuario'))
    vehiculo = db.relationship('Vehiculo', backref='reportes')
    usuario = db.relationship('Usuario', backref='reportes')

class BitacoraDB(db.Model):
    __tablename__ = 'Bitacora_DB'
    ID_Log = db.Column(db.Integer, primary_key=True)
    Tabla_Afectada = db.Column(db.String(50))
    Accion = db.Column(db.String(20))
    Detalle = db.Column(db.Text)
    Fecha = db.Column(db.DateTime, default=datetime.now)
    Usuario_Responsable = db.Column(db.String(100))

# ================== LÓGICA DE STREAMING (ELIMINADA) ==================
# La función leer_puerto_mision y la lógica de serialización se movieron a agente_tierra.py.

def parse_data(trama_str):
    """ Convierte el string CSV guardado en BD a un diccionario útil """
    try:
        # Formato esperado: temp,hum,pres,co2,vel,vang,acc,aang,alt,apo,lat,lon,ev1,ev2
        d = trama_str.split(',')
        if len(d) < 14: return None
        
        return {
            "temperatura": float(d[0]),
            "humedad": int(d[1]),
            "presion": float(d[2]),
            "co2": int(d[3]),
            "velocidad": float(d[4]),
            "aceleracion": float(d[6]),
            "altitud": float(d[8]),
            "apogeo": float(d[9]),
            "latitud": float(d[10]),
            "longitud": float(d[11])
        }
    except:
        return None


# ================== DECORADORES (IDÉNTICOS) ==================
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

def staff_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if session.get('role') not in ['admin', 'mantenimiento']:
            flash("Acceso denegado.", "error")
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return wrapped


# ================== AUTH (IDÉNTICO) ==================
oauth = OAuth(app)
oauth.register(name='google', client_id=GOOGLE_CLIENT_ID, client_secret=GOOGLE_CLIENT_SECRET, server_metadata_url='https://accounts.google.com/.well-known/openid-configuration', client_kwargs={'scope': 'openid email profile'})


# RUTAS DE AUTENTICACIÓN (IDÉNTICAS)
@app.route('/')
def home(): return render_template("index.html")

@app.route('/login', methods=['GET','POST'])
def login():
    if 'user_id' in session:
        role = session.get('role')
        if role == 'admin': return redirect(url_for('admin_dashboard'))
        if role == 'mantenimiento': return redirect(url_for('mantenimiento_dashboard'))
        return redirect(url_for('catalogo_misiones'))

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
            
            if user.Rol == 'admin': return redirect(url_for('admin_dashboard'))
            if user.Rol == 'mantenimiento': return redirect(url_for('mantenimiento_dashboard'))
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
        # Agregamos 'verify=False' para asegurar que funcione con peticiones HTTP si es necesario
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


# =========================================================
# === RUTAS DE VISTAS (MODIFICADAS PARA NUBE) =============
# =========================================================

@app.route('/catalogo')
@login_required
def catalogo_misiones():
    misiones = Mision.query.all()
    lista = []
    rol_actual = session.get('role')
    
    for m in misiones:
        en_vivo = str(m.ID_Mision) in active_streams
        
        if rol_actual != 'admin' and not en_vivo: 
            continue
        
        # Eliminamos la referencia a 'port' y 'broadcaster' que eran locales
        lista.append({'id': m.ID_Mision, 'nombre': m.Nombre_Mision, 'fecha': m.Fecha, 'lugar': m.Lugar, 'en_vivo': en_vivo})
        
    return render_template('catalogo.html', misiones=lista)

@app.route('/sala/<int:id_mision>')
@login_required
def sala_mision(id_mision):
    mision = Mision.query.get_or_404(id_mision)
    es_admin = (session.get('role') == 'admin')
    # Usamos una plantilla diferente (dashboard_sala_cloud.html) si es necesario,
    # o simplemente la misma, pero el JS sabe que no debe mostrar botones de puerto USB
    return render_template('dashboard_sala.html', mision=mision, es_admin=es_admin) 

# PANELES (IDÉNTICOS)
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

# =========================================================
# === RUTAS CRUD (IDÉNTICAS) ==============================
# =========================================================
@app.route('/admin/usuarios')
@login_required
@staff_required 
def usuarios_list(): return render_template('usuarios_list.html', usuarios=Usuario.query.all())

@app.route('/admin/usuarios/crear', methods=['GET', 'POST'])
@login_required
@staff_required
def usuarios_crear():
    if request.method == 'POST':
        db.session.add(Usuario(Nombre=request.form['nombre'], email=request.form['email'], Password=generate_password_hash(request.form['password']), Rol=request.form['rol']))
        db.session.commit()
        return redirect(url_for('usuarios_list'))
    return render_template('usuario_form.html', accion='crear')

@app.route('/admin/usuarios/editar/<int:id>', methods=['GET', 'POST'])
@login_required
@staff_required
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
@staff_required
def usuarios_eliminar(id):
    db.session.delete(Usuario.query.get_or_404(id))
    db.session.commit()
    return redirect(url_for('usuarios_list'))

@app.route('/admin/vehiculos')
@login_required
@staff_required
def vehiculos_list(): return render_template('vehiculos_list.html', vehiculos=Vehiculo.query.all())

@app.route('/admin/vehiculos/crear', methods=['GET', 'POST'])
@login_required
@staff_required
def vehiculos_crear():
    if request.method == 'POST':
        db.session.add(Vehiculo(Nombre_Vehiculo=request.form['nombre'], Categoria=request.form['categoria'], Estado=request.form['estado']))
        db.session.commit()
        return redirect(url_for('vehiculos_list'))
    return render_template('vehiculo_form.html', accion='crear')

@app.route('/admin/vehiculos/editar/<int:id>', methods=['GET', 'POST'])
@login_required
@staff_required
def vehiculos_editar(id):
    v = Vehiculo.query.get_or_404(id)
    if request.method == 'POST':
        v.Nombre_Vehiculo, v.Categoria, v.Estado = request.form['nombre'], request.form['categoria'], request.form['estado']
        db.session.commit()
        return redirect(url_for('vehiculos_list'))
    return render_template('vehiculo_form.html', accion='editar', vehiculo=v)

@app.route('/admin/vehiculos/eliminar/<int:id>', methods=['POST'])
@login_required
@staff_required
def vehiculos_eliminar(id):
    db.session.delete(Vehiculo.query.get_or_404(id))
    db.session.commit()
    return redirect(url_for('vehiculos_list'))

@app.route('/admin/misiones')
@login_required
@staff_required
def misiones_list(): return render_template('misiones_list.html', misiones=Mision.query.all())

@app.route('/admin/misiones/crear', methods=['GET', 'POST'])
@login_required
@staff_required
def misiones_crear():
    if request.method == 'POST':
        m = Mision(Nombre_Mision=request.form['nombre'], Fecha=request.form['fecha'] or None, Lugar=request.form['lugar'])
        if request.form.get('vehiculo'): m.FK_ID_Vehiculo = request.form.get('vehiculo')
        if request.form.get('usuario'): m.FK_ID_Usuario = request.form.get('usuario')
        db.session.add(m)
        db.session.commit()
        return redirect(url_for('misiones_list'))
    vehiculos = Vehiculo.query.all()
    usuarios = Usuario.query.filter_by(Rol='admin').all()
    return render_template('mision_form.html', accion='crear', vehiculos=vehiculos, usuarios=usuarios)

@app.route('/admin/misiones/editar/<int:id>', methods=['GET', 'POST'])
@login_required
@staff_required
def misiones_editar(id):
    m = Mision.query.get_or_404(id)
    if request.method == 'POST':
        m.Nombre_Mision, m.Fecha, m.Lugar = request.form['nombre'], request.form['fecha'] or None, request.form['lugar']
        m.FK_ID_Vehiculo, m.FK_ID_Usuario = request.form.get('vehiculo'), request.form.get('usuario')
        db.session.commit()
        return redirect(url_for('misiones_list'))
    vehiculos = Vehiculo.query.all()
    usuarios = Usuario.query.filter_by(Rol='admin').all()
    return render_template('mision_form.html', accion='editar', mision=m, vehiculos=vehiculos, usuarios=usuarios)

@app.route('/admin/misiones/eliminar/<int:id>', methods=['POST'])
@login_required
@staff_required
def misiones_eliminar(id):
    db.session.delete(Mision.query.get_or_404(id))
    db.session.commit()
    return redirect(url_for('misiones_list'))

@app.route('/reportes', methods=['GET', 'POST'])
@login_required
def ver_reporte():
    misiones = Mision.query.order_by(Mision.Fecha.desc()).all()
    datos_grafica = []
    stats = {'max_alt': 0, 'max_vel': 0, 'max_acc': 0, 'flight_time': 0, 'apogeo_real': 0}
    mision_seleccionada = None
    mision_id = request.args.get('mision_id') or (request.form.get('mision_id') if request.method == 'POST' else None)
    
    if mision_id:
        mision_seleccionada = Mision.query.get(mision_id)
        registros = Trama_CanSat.query.filter_by(FK_ID_Mision=mision_id).order_by(Trama_CanSat.Fecha_Hora).all()
        parsed_data, start_time, end_time = [], None, None

        for r in registros:
            val = parse_data(r.Trama)
            if val:
                val['time'] = r.Fecha_Hora.strftime('%H:%M:%S')
                parsed_data.append(val)
                
                if val['altitud'] > stats['max_alt']: stats['max_alt'] = val['altitud']
                if val['velocidad'] > stats['max_vel']: stats['max_vel'] = val['velocidad']
                if val['aceleracion'] > stats['max_acc']: stats['max_acc'] = val['aceleracion']
                if val['apogeo'] > stats['apogeo_real']: stats['apogeo_real'] = val['apogeo']
                
                if not start_time: start_time = r.Fecha_Hora
                end_time = r.Fecha_Hora

        if start_time and end_time:
            duration = end_time - start_time
            stats['flight_time'] =str(duration).split('.')[0]

        datos_grafica = parsed_data

    return render_template('reportes.html', 
                           misiones=misiones, 
                           datos=json.dumps(datos_grafica),
                           stats=stats,
                           mision_actual=mision_seleccionada)


# =========================================================
# === MÓDULO DE MANTENIMIENTO (IDÉNTICO) ==================
# =========================================================

@app.route('/mantenimiento')
@login_required
@staff_required
def mantenimiento_dashboard():
    reportes = ReporteMantenimiento.query.order_by(ReporteMantenimiento.Fecha_Hora_Reporte.desc()).limit(5).all()
    logs = BitacoraDB.query.order_by(BitacoraDB.Fecha.desc()).limit(10).all()
    return render_template("mantenimiento.html", reportes=reportes, logs=logs)

@app.route('/mantenimiento/logs')
@login_required
@staff_required
def logs_db():
    logs = BitacoraDB.query.order_by(BitacoraDB.Fecha.desc()).limit(100).all()
    return render_template("logs_db.html", logs=logs)

@app.route('/mantenimiento/reportes/crear', methods=['GET', 'POST'])
@login_required
@staff_required
def reportes_crear():
    if request.method == 'POST':
        vehiculo_id = request.form.get('vehiculo')
        comentario = request.form.get('comentarios')
        
        nuevo_reporte = ReporteMantenimiento(
            Comentarios=comentario,
            FK_ID_Vehiculo=vehiculo_id,
            FK_ID_Usuario=session.get('user_id')
        )
        
        estado_nuevo = request.form.get('estado_vehiculo')
        if estado_nuevo:
            v = Vehiculo.query.get(vehiculo_id)
            v.Estado = estado_nuevo
        
        db.session.add(nuevo_reporte)
        db.session.commit()
        flash("Reporte registrado", "success")
        return redirect(url_for('mantenimiento_dashboard'))
        
    vehiculos = Vehiculo.query.all()
    return render_template("reportes_crear.html", vehiculos=vehiculos)

@app.route('/mantenimiento/reportes')
@login_required
@staff_required
def reportes_lista():
    reportes = ReporteMantenimiento.query.order_by(ReporteMantenimiento.Fecha_Hora_Reporte.desc()).all()
    return render_template("reportes_lista.html", reportes=reportes)


# =========================================================
# === SOCKETS (MODIFICADOS PARA RECEPCIÓN EN LA NUBE) =====
# =========================================================

@socketio.on('join')
def on_join(data):
    room = str(data['mission_id'])
    join_room(room)
    if room in active_streams:
        # Mensaje modificado para reflejar que la señal viene de Tierra
        emit('status_msg', {'msg': '🔴 SEÑAL RECIBIDA DESDE TIERRA'})
    else:
        emit('status_msg', {'msg': 'Esperando conexión del Agente de Tierra...'})

# EVENTO ELIMINADO: 'start_stream_mission' (ya no lo inicia la nube)
# EVENTO ELIMINADO: 'stop_stream_mission' (ya lo gestiona el agente o el timeout)
# EVENTO ELIMINADO: 'disconnect' (la desconexión del host ya no detiene todo, lo hace el agente)
# EVENTO ELIMINADO: 'buscar_puertos' (la nube no busca puertos)

# EVENTO NUEVO: Recibe datos desde tu Laptop (Agente de Tierra)
@socketio.on('ingest_telemetry')
def handle_ingest(data):
    """
    Este evento es llamado por 'agente_tierra.py' desde tu laptop.
    Recibe el JSON ya procesado, guarda el raw_line y lo retransmite.
    """
    mission_id = str(data.get('mission_id'))
    payload = data.get('payload') # JSON con los datos parseados
    raw_line = data.get('raw_line') # La línea CSV original
    
    if not mission_id or not payload: return
    
    # 1. Registrar que esta misión está activa
    if mission_id not in active_streams:
        active_streams[mission_id] = {'start': datetime.now()}
        # Avisar a todos en el catálogo que se prendió el foco rojo
        socketio.emit('mission_started', {'mission_id': mission_id}, broadcast=True)

    # 2. Retransmitir a la sala (Browsers)
    socketio.emit('telemetria', payload, to=mission_id)
    
    # 3. Guardar en Base de Datos Nube
    with app.app_context():
        try:
            # Usamos el usuario 1 (System) o el que venga en el payload
            t = Trama_CanSat(Trama=raw_line, FK_ID_Mision=mission_id, FK_ID_Usuario=1) 
            db.session.add(t)
            db.session.commit()
        except:
            # En producción, esto debería logearse, pero por ahora evitamos el crash
            pass 

@socketio.on('ingest_stop')
def handle_ingest_stop(data):
    """
    Recibe la señal de que el Agente de Tierra ha terminado la transmisión.
    """
    mission_id = str(data.get('mission_id'))
    if mission_id in active_streams:
        del active_streams[mission_id]
        socketio.emit('status_msg', {'msg': 'Transmisión finalizada desde Tierra.'}, to=mission_id)
        socketio.emit('stream_ended', {}, to=mission_id)


if __name__ == '__main__':
    # En producción (Azure), gunicorn se encarga de ejecutar esto.
    # Aquí lo dejamos para que cree las tablas si no existen.
    with app.app_context(): db.create_all() 
    print("🚀 Hypernova Server (Cloud Ready): Online en 0.0.0.0:5000")
    # Nota: removemos debug=True y allow_unsafe_werkzeug=True para producción
    socketio.run(app, host='0.0.0.0', port=5000)