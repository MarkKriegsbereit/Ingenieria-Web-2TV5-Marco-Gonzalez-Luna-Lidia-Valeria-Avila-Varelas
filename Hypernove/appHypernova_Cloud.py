import eventlet
# 1. PARCHE OBLIGATORIO
eventlet.monkey_patch()

import requests
import traceback
from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_socketio import SocketIO, emit, join_room, leave_room
from sqlalchemy.exc import IntegrityError

import re

from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

from sqlalchemy import or_
import os
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
from datetime import datetime, timedelta
import urllib3
import json
##nuevo
from werkzeug.utils import secure_filename
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev_key")

# CONFIGURACIÓN
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI="http://3.143.186.4.sslip.io:5000/google/callback"

UPLOAD_FOLDER = 'static/vehiculo_fotos'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- Configuración de CORREO ELECTRÓNICO (SMTP) ---
# Necesitas configurar estas variables en tu archivo .env
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', True)
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # Tu correo de envío
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # Tu contraseña de aplicación/App Password

# === NUEVA LÍNEA CLAVE ===
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_CHARSET'] = 'utf-8'
# ========================

mail = Mail(app)

# Serializador de Tokens Seguros
# Usamos app.secret_key para firmar el token y prevenir manipulaciones.
s = URLSafeTimedSerializer(app.secret_key, salt='recuperacion-salt')

def allowed_file(filename):
    """Verifica si la extensión del archivo es permitida."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# DB
db_url = os.getenv("DATABASE_URL")
if db_url:
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+mysqlconnector://hypernova_user:Hyper123!@localhost/Hypernova"

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

# DICCIONARIO DE STREAMS ACTIVOS
active_streams = {}

@app.after_request
def add_security_headers(response):
    # Esto previene que el navegador guarde la página en el historial de caché
    # Asegura que el navegador DEBE revalidar la página con el servidor
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    # Para compatibilidad con HTTP/1.0
    response.headers['Pragma'] = 'no-cache'
    # Para compatibilidad con HTTP/1.0 y proxies
    response.headers['Expires'] = '0'
    
    return response

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
    # NUEVO CAMPO: Guardará la ruta/nombre del archivo de la foto
    Foto_Path = db.Column(db.String(255), nullable=True)

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

# ================== TAREA DE FONDO ==================
def check_heartbeats():
    while True:
        eventlet.sleep(5)
        now = datetime.now()
        for mid in list(active_streams.keys()):
            stream = active_streams[mid]
            last_beat = stream.get('last_heartbeat')
            
            if last_beat and (now - last_beat).total_seconds() > 20:
                print(f"⚠️ Misión {mid}: Timeout de Agente. Cerrando.")
                socketio.emit('status_msg', {'msg': '⚠️ SEÑAL PERDIDA (Timeout)'}, to=mid)
                socketio.emit('stream_ended', {'force_reset': True}, to=mid)
                if mid in active_streams:
                    del active_streams[mid]
                # Corrección: usar server.emit para broadcast global sin error
                socketio.server.emit('mission_stopped', {'mission_id': mid}) 

socketio.start_background_task(check_heartbeats)

def parse_data(trama_str):
    try:
        d = trama_str.split(',')
        # Aseguramos que tenga al menos 14 datos (tu trama actual)
        if len(d) < 14: return None
        
        return {
            "temperatura": float(d[0]),
            "humedad": int(d[1]),
            "presion": float(d[2]),
            "co2": int(d[3]),            # <--- ESTA LÍNEA ES CRÍTICA (Índice 3)
            "velocidad": float(d[4]),
            "velocidad_ang": float(d[5]), # Agregamos esto para completitud
            "aceleracion": float(d[6]),
            "acc_ang": float(d[7]),       # Agregamos esto para completitud
            "altitud": float(d[8]),
            "apogeo": float(d[9])
        }
    except: return None

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

def staff_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if session.get('role') not in ['admin', 'mantenimiento']: return redirect(url_for('home'))
        return f(*args, **kwargs)
    return wrapped

# ================== RUTAS WEB ==================
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
            db.session.add(ns); db.session.commit()
            session['id_bitacora'] = ns.ID_Sesion
            if user.Rol == 'admin': return redirect(url_for('admin_dashboard'))
            if user.Rol == 'mantenimiento': return redirect(url_for('mantenimiento_dashboard'))
            return redirect(url_for('catalogo_misiones'))
        return render_template('login.html', mensaje="Datos incorrectos")
    return render_template('login.html')

@app.route('/login_local')
def login_local():
    u = Usuario.query.filter_by(email="invitado@local.lan").first()
    if not u:
        u = Usuario(Nombre="Espectador LAN", email="invitado@local.lan", Password=generate_password_hash("lan"), Rol="invitado", oauth_provider="local")
        db.session.add(u); db.session.commit()
    session.clear()
    session['user_id'] = u.ID_Usuario
    session['role'] = u.Rol
    session['email'] = u.email
    session['name'] = u.Nombre
    session.permanent = True
    return redirect(url_for('catalogo_misiones'))

@app.route('/logout')
def logout():
    # 1. Finalizar la sesión de bitácora si existe
    id_bitacora = session.pop('id_bitacora', None)
    if id_bitacora:
        # Usamos app.app_context() porque estamos fuera de una vista normal
        with app.app_context():
            try:
                ns = SesionModel.query.get(id_bitacora)
                if ns:
                    ns.Fecha_Hora_Fin = datetime.now()
                    db.session.commit()
            except Exception as e:
                # Opcional: registrar el error de cierre de sesión
                print(f"Error al cerrar sesión de bitácora: {e}")

    # 2. Borrar todos los datos de sesión (incluyendo user_id, role, etc.)
    session.clear()
    
    # 3. Redirigir inmediatamente a una página pública (como login)
    # Esto es crucial para que el navegador no tenga una página autenticada para volver.
    return redirect(url_for('login'))

# @app.route("/google_login")
# def google_login(): return redirect(f"https://accounts.google.com/o/oauth2/v2/auth?client_id={GOOGLE_CLIENT_ID}&redirect_uri={GOOGLE_REDIRECT_URI}&response_type=code&scope=openid%20email%20profile")

@app.route("/google_login")
def google_login(): 
    # Se añade '&prompt=select_account' al final de la URL.
    # Esto obliga a Google a mostrar la pantalla de selección de cuentas
    # o de re-autenticación, en lugar de acceder silenciosamente si ya hay una sesión.
    return redirect(f"https://accounts.google.com/o/oauth2/v2/auth?client_id={GOOGLE_CLIENT_ID}&redirect_uri={GOOGLE_REDIRECT_URI}&response_type=code&scope=openid%20email%20profile&prompt=select_account")

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
            db.session.add(u); db.session.commit()
        session['user_id'] = u.ID_Usuario
        session['email'] = u.email
        session['role'] = u.Rol
        session['name'] = u.Nombre
        session.permanent = True
        return redirect(url_for('catalogo_misiones'))
    except: return redirect(url_for('login'))


@app.route('/catalogo')
@login_required
def catalogo_misiones():
    misiones = Mision.query.all()
    lista = []
    rol = session.get('role')
    for m in misiones:
        en_vivo = str(m.ID_Mision) in active_streams
        if rol not in ['admin', 'mantenimiento'] and not en_vivo: continue
        broadcaster = active_streams[str(m.ID_Mision)].get('admin_name', 'Remoto') if en_vivo else None
        lista.append({'id': m.ID_Mision, 'nombre': m.Nombre_Mision, 'fecha': m.Fecha, 'lugar': m.Lugar, 'en_vivo': en_vivo, 'broadcaster': broadcaster})
    return render_template('catalogo.html', misiones=lista)

@app.route('/sala/<int:id_mision>')
@login_required
def sala_mision(id_mision):
    mision = Mision.query.get_or_404(id_mision)
    es_admin = (session.get('role') == 'admin')
    return render_template('dashboard_sala.html', mision=mision, es_admin=es_admin)

# PANELES Y CRUD (Mismos de siempre)
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard(): return render_template('admin.html')

@app.route('/invitado', methods=['GET', 'POST'])
@login_required
def invitado_dashboard():
    u = Usuario.query.get(session.get('user_id'))
    
    if request.method == 'POST':
        nuevo_nombre = request.form['nombre']
        nuevo_email = request.form['email'].strip()
        
        # --- 1. VALIDACIÓN DE FORMATO (Formato de correo real) ---
        if '@' not in nuevo_email or '.' not in nuevo_email:
            flash('El formato del correo electrónico no es válido. Debe contener @ y un dominio.', 'danger')
            return redirect(url_for('invitado_dashboard'))

        # --- Lógica de actualización ---
        u.Nombre = nuevo_nombre
        
        # Solo intenta cambiar el correo si es diferente
        if u.email != nuevo_email:
            u.email = nuevo_email
            try:
                # 2. INTENTA HACER COMMIT (Puede fallar si el correo ya existe)
                db.session.commit()
                
                # Si el correo se cambió con éxito, actualiza la sesión
                session['email'] = nuevo_email
                flash('Perfil actualizado con éxito.', 'success')
                return redirect(url_for('invitado_dashboard'))
                
            except IntegrityError:
                # 3. CAPTURA EL ERROR DE UNICIDAD
                db.session.rollback() # Revierte la transacción fallida
                flash('Ese correo electrónico ya está registrado por otro usuario.', 'danger')
                return redirect(url_for('invitado_dashboard'))
        else:
            # Si solo se cambió el nombre (o nada), guardamos y notificamos
            try:
                db.session.commit()
                flash('Perfil actualizado con éxito.', 'success')
            except:
                db.session.rollback()
                flash('Ocurrió un error al guardar el nombre.', 'danger')
            return redirect(url_for('invitado_dashboard'))

    return render_template("invitado.html", usuario=u)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        n, e, p = request.form.get('username'), request.form.get('email'), request.form.get('password')
        if not Usuario.query.filter_by(email=e).first():
            nu = Usuario(Nombre=n, email=e, Password=generate_password_hash(p), Rol='invitado', oauth_provider='local')
            db.session.add(nu); db.session.commit()
            return redirect(url_for('login'))
    return render_template("register.html")

# ================== RECUPERACIÓN DE CONTRASEÑA ==================

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = Usuario.query.filter_by(email=email).first()

        # Solo permite la recuperación si es un usuario local (no Google/OAuth)
        # if user and user.oauth_provider in [None, 'local']:
        # Permite a cualquier usuario registrado pedir un reset
        if user:
            try:
                # 1. Generar token único con caducidad (1 hora)
                token = s.dumps(email, salt='recuperacion-salt')
                
                # 2. Construir URL de reseteo (external=True para que el enlace funcione fuera de AWS)
                reset_url = url_for('reset_password', token=token, _external=True)
                
                # 3. Enviar correo
                msg = Message(
                    subject="Restablecer Contraseña - Hypernova",
                    recipients=[email],
                    charset="utf-8"
                )
                
                msg.body = (
                    f"Hola {user.Nombre},\n\n"
                    "Recibimos una solicitud para restablecer tu contraseña.\n\n"
                    "Haz clic en el siguiente enlace (expira en 1 hora):\n"
                    f"{reset_url}\n\n"
                    "Si no solicitaste esto, ignora este correo."
                )

                mail.send(msg)
                
                flash('Se ha enviado un correo electrónico con instrucciones para restablecer tu contraseña.', 'success')
                return redirect(url_for('login'))
                
            except Exception as e:
                flash(f'Error al enviar correo: {e}', 'danger')
                return redirect(url_for('forgot_password'))
        else:
            flash('Correo no encontrado o asociado a una cuenta de Google/OAuth.', 'danger')
            return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='recuperacion-salt', max_age=3600)
    except (SignatureExpired, BadSignature):
        flash('El enlace ha expirado o no es válido.', 'danger')
        return redirect(url_for('forgot_password'))

    user = Usuario.query.filter_by(email=email).first()
    if not user:
        flash('Usuario no encontrado.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form.get('confirm_password')

        # 1. Validar coincidencia
        if new_password != confirm_password:
            flash('Las contraseñas no coinciden.', 'danger')
            return render_template('reset_password.html', token=token)
        
        # 2. Validación Regex (8 caracteres, 1 número, 1 símbolo)
        # Explicación: (?=.*\d) busca un número, (?=.*[!@#$%^&*]) busca el símbolo
        regex_seguridad = r"^(?=.*\d)(?=.*[!@#$%^&*(),.?\":{}|<>]).{8,}$"
        
        if not re.match(regex_seguridad, new_password):
            flash('La contraseña debe tener al menos 8 caracteres, un número y un símbolo especial.', 'danger')
            return render_template('reset_password.html', token=token)
        
        # Si pasa las pruebas
        user.Password = generate_password_hash(new_password)
        db.session.commit()
        
        flash('Tu contraseña ha sido restablecida con éxito.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)
@app.route('/admin/usuarios')
@login_required
@staff_required
def usuarios_list(): return render_template('usuarios_list.html', usuarios=Usuario.query.all())
@app.route('/admin/usuarios/crear', methods=['GET', 'POST'])
@login_required
@staff_required
def usuarios_crear():

    if request.method == 'POST':
        email = request.form.get('email', '').lower().strip()
        
        # Expresión regular para validar formato real y extensiones comunes
        # Valida que termine en .com, .net, .org, .edu, .mx, etc.
        email_regex = r'^[a-z0-9._%+-]+@[a-z0-9.-]+\.(com|net|org|edu|gov|mx|io|app)$'
        
        if not re.match(email_regex, email):
            flash('Error: El formato del correo no es válido o la extensión no es permitida.', 'danger')
            return render_template('usuario_form.html', accion='crear')

        # Verificar si el correo ya existe para evitar duplicados
        if Usuario.query.filter_by(email=email).first():
            flash('Ese correo electrónico ya está registrado.', 'danger')
            return render_template('usuario_form.html', accion='crear')

    if request.method == 'POST':
        db.session.add(Usuario(Nombre=request.form['nombre'], email=request.form['email'], Password=generate_password_hash(request.form['password']), Rol=request.form['rol']))
        db.session.commit()
        return redirect(url_for('usuarios_list'))
    return render_template('usuario_form.html', accion='crear')

# @app.route('/admin/usuarios/editar/<int:id>', methods=['GET', 'POST'])
# @login_required
# @staff_required
# def usuarios_editar(id):
#     u = Usuario.query.get_or_404(id)
#     if request.method == 'POST':
#         u.Nombre, u.email, u.Rol = request.form['nombre'], request.form['email'], request.form['rol']
#         if request.form.get('password'): u.Password = generate_password_hash(request.form.get('password'))
#         db.session.commit()
#         return redirect(url_for('usuarios_list'))
#     return render_template('usuario_form.html', accion='editar', usuario=u)

# @app.route('/admin/usuarios/editar/<int:id>', methods=['GET', 'POST'])
# @login_required
# @staff_required
# def usuarios_editar(id):
#     u = Usuario.query.get_or_404(id)
#     if request.method == 'POST':
#         u.Nombre = request.form['nombre']
#         u.email = request.form['email']
#         u.Rol = request.form['rol']
        
#         # Solo actualiza la contraseña si el campo existe en el formulario (caso 'crear')
#         # En edición, como quitamos el input, este if se saltará automáticamente
#         if 'password' in request.form and request.form.get('password'):
#             u.Password = generate_password_hash(request.form.get('password'))
            
#         db.session.commit()
#         flash('Usuario actualizado correctamente', 'success')
#         return redirect(url_for('usuarios_list'))
        
#     return render_template('usuario_form.html', accion='editar', usuario=u)

@app.route('/admin/usuarios/editar/<int:id>', methods=['GET', 'POST'])
@login_required
@staff_required
def usuarios_editar(id):
    u = Usuario.query.get_or_404(id)
    if request.method == 'POST':
        # 1. Obtener y limpiar datos (Igual que en crear)
        nuevo_nombre = request.form.get('nombre', '').strip()
        nuevo_email = request.form.get('email', '').lower().strip()
        nuevo_rol = request.form.get('rol')

        # 2. VALIDACIÓN DE CORREO (Regex)
        # Importante: Mantener la misma seguridad que en la creación
        email_regex = r'^[a-z0-9._%+-]+@[a-z0-9.-]+\.(com|net|org|edu|gov|mx|io|app)$'
        if not re.match(email_regex, nuevo_email):
            flash('Error: El formato del correo no es válido o la extensión no es permitida.', 'danger')
            return render_template('usuario_form.html', accion='editar', usuario=u)

        # 3. VERIFICAR DUPLICADOS (Solo si el correo cambió)
        if nuevo_email != u.email:
            if Usuario.query.filter_by(email=nuevo_email).first():
                flash('Error: El nuevo correo ya está registrado por otro usuario.', 'danger')
                return render_template('usuario_form.html', accion='editar', usuario=u)

        # 4. ACTUALIZAR LOS DATOS
        u.Nombre = nuevo_nombre
        u.email = nuevo_email
        u.Rol = nuevo_rol
        
        # Como en el HTML de edición quitamos el campo 'password',
        # este bloque se saltará solo, manteniendo la clave actual.
        if 'password' in request.form and request.form.get('password'):
            u.Password = generate_password_hash(request.form.get('password'))
            
        try:
            db.session.commit()
            flash('Usuario actualizado correctamente', 'success')
            return redirect(url_for('usuarios_list'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al actualizar: {str(e)}', 'danger')
            return render_template('usuario_form.html', accion='editar', usuario=u)
        
    return render_template('usuario_form.html', accion='editar', usuario=u)

@app.route('/admin/usuarios/eliminar/<int:id>', methods=['POST'])
@login_required
@staff_required
def usuarios_eliminar(id):
    db.session.delete(Usuario.query.get_or_404(id)); db.session.commit()
    return redirect(url_for('usuarios_list'))
@app.route('/admin/vehiculos')
@login_required
@staff_required
def vehiculos_list(): return render_template('vehiculos_list.html', vehiculos=Vehiculo.query.all())

# @app.route('/admin/vehiculos/crear', methods=['GET', 'POST'])
# @login_required
# @staff_required
# def vehiculos_crear():
#     if request.method == 'POST':
#         db.session.add(Vehiculo(Nombre_Vehiculo=request.form['nombre'], Categoria=request.form['categoria'], Estado=request.form['estado']))
#         db.session.commit()
#         return redirect(url_for('vehiculos_list'))
#     return render_template('vehiculo_form.html', accion='crear')

@app.route('/admin/vehiculos/crear', methods=['GET', 'POST'])
@login_required
@staff_required
def vehiculos_crear():
    if request.method == 'POST':
        # 1. Extraer y limpiar los datos (strip elimina espacios vacíos accidentales)
        nombre = request.form.get('nombre', '').strip()
        categoria = request.form.get('categoria', '').strip()
        estado = request.form.get('estado')

        # 2. VALIDACIÓN: Si falta el nombre o la categoría, recarga con error
        if not nombre or not categoria:
            flash('Error: El nombre y la categoría son campos obligatorios.', 'danger')
            return render_template('vehiculo_form.html', accion='crear')

        # 3. Crear el objeto solo si pasó la validación
        v = Vehiculo(
            Nombre_Vehiculo=nombre, 
            Categoria=categoria, 
            Estado=estado
        )

        # --- Lógica de Subida de Archivo (Se mantiene opcional) ---
        if 'foto' in request.files:
            file = request.files['foto']
            # Verifica que realmente se haya seleccionado un archivo
            if file and file.filename != '' and allowed_file(file.filename):
                filename = str(int(time.time())) + '_' + secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                v.Foto_Path = filename
        
        try:
            db.session.add(v)
            db.session.commit()
            flash('Vehículo registrado correctamente.', 'success')
            return redirect(url_for('vehiculos_list'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error en la base de datos: {e}', 'danger')
            return render_template('vehiculo_form.html', accion='crear')

    return render_template('vehiculo_form.html', accion='crear')

#antes de agregar el de abajo este codigo servia
# @app.route('/admin/vehiculos/editar/<int:id>', methods=['GET', 'POST'])
# @login_required
# @staff_required
# def vehiculos_editar(id):
#     v = Vehiculo.query.get_or_404(id)
#     if request.method == 'POST':
#         v.Nombre_Vehiculo, v.Categoria, v.Estado = request.form['nombre'], request.form['categoria'], request.form['estado']
#         db.session.commit()
#         return redirect(url_for('vehiculos_list'))
#     return render_template('vehiculo_form.html', accion='editar', vehiculo=v)

@app.route('/admin/vehiculos/editar/<int:id>', methods=['GET', 'POST'])
@login_required
@staff_required
def vehiculos_editar(id):
    v = Vehiculo.query.get_or_404(id)
    if request.method == 'POST':
        v.Nombre_Vehiculo, v.Categoria, v.Estado = request.form['nombre'], request.form['categoria'], request.form['estado']
        
        # --- Lógica de Subida de Archivo ---
        if 'foto' in request.files:
            file = request.files['foto']
            if file and allowed_file(file.filename):
                # Opcional: Eliminar la foto vieja para no llenar el servidor
                if v.Foto_Path:
                     old_path = os.path.join(app.config['UPLOAD_FOLDER'], v.Foto_Path)
                     if os.path.exists(old_path): os.remove(old_path)
                     
                filename = str(int(time.time())) + '_' + secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                v.Foto_Path = filename # Actualiza el nombre del archivo
                
        db.session.commit()
        return redirect(url_for('vehiculos_list'))
    return render_template('vehiculo_form.html', accion='editar', vehiculo=v)

@app.route('/admin/vehiculos/eliminar/<int:id>', methods=['POST'])
@login_required
@staff_required
def vehiculos_eliminar(id):
    db.session.delete(Vehiculo.query.get_or_404(id)); db.session.commit()
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
        db.session.add(m); db.session.commit()
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
    db.session.delete(Mision.query.get_or_404(id)); db.session.commit()
    return redirect(url_for('misiones_list'))

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
@app.route('/mantenimiento/reportes')
@login_required
@staff_required
def reportes_lista():
    reportes = ReporteMantenimiento.query.order_by(ReporteMantenimiento.Fecha_Hora_Reporte.desc()).all()
    return render_template("reportes_lista.html", reportes=reportes)
@app.route('/mantenimiento/reportes/crear', methods=['GET', 'POST'])
@login_required
@staff_required
def reportes_crear():
    if request.method == 'POST':
        vid = request.form.get('vehiculo')
        nuevo = ReporteMantenimiento(Comentarios=request.form.get('comentarios'), FK_ID_Vehiculo=vid, FK_ID_Usuario=session.get('user_id'))
        est = request.form.get('estado_vehiculo')
        if est:
            v = Vehiculo.query.get(vid); v.Estado = est
        db.session.add(nuevo); db.session.commit()
        return redirect(url_for('mantenimiento_dashboard'))
    vehiculos = Vehiculo.query.all()
    return render_template("reportes_crear.html", vehiculos=vehiculos)
@app.route('/reportes', methods=['GET', 'POST'])
@login_required
@staff_required
def ver_reporte():
    misiones = Mision.query.order_by(Mision.Fecha.desc()).all()
    datos_grafica = []
    # Inicializamos stats
    stats = {
        'max_alt': 0, 
        'max_vel': 0, 
        'max_acc': 0, 
        'flight_time': "00:00:00", 
        'apogeo_real': 0  # Inicializar en 0
    }
    mision_actual = None
    
    mision_id = request.args.get('mision_id') or (request.form.get('mision_id') if request.method == 'POST' else None)
    
    if mision_id:
        mision_actual = Mision.query.get(mision_id)
        registros = Trama_CanSat.query.filter_by(FK_ID_Mision=mision_id).order_by(Trama_CanSat.Fecha_Hora).all()
        
        parsed_list = []
        start_time = None
        end_time = None

        for r in registros:
            val = parse_data(r.Trama)
            if val:
                val['time'] = r.Fecha_Hora.strftime('%H:%M:%S')
                parsed_list.append(val)
                
                # --- CÁLCULOS ESTADÍSTICOS ---
                if val['altitud'] > stats['max_alt']: 
                    stats['max_alt'] = val['altitud']
                
                if val['velocidad'] > stats['max_vel']: 
                    stats['max_vel'] = val['velocidad']
                
                if val['aceleracion'] > stats['max_acc']: 
                    stats['max_acc'] = val['aceleracion']
                
                # Control de tiempo
                if not start_time: start_time = r.Fecha_Hora
                end_time = r.Fecha_Hora
        
        # ASIGNAR APOGEO REAL
        # El apogeo real es simplemente la altitud máxima alcanzada
        stats['apogeo_real'] = stats['max_alt']

        if start_time and end_time:
            delta = end_time - start_time
            stats['flight_time'] = str(delta).split('.')[0] # Formato HH:MM:SS
            
        datos_grafica = parsed_list

    return render_template('reportes.html', misiones=misiones, datos=json.dumps(datos_grafica), stats=stats, mision_actual=mision_actual)
# ================== SOCKETS (CORREGIDO PARA EVITAR CRASHES) ==================

@socketio.on('join')
def on_join(data):
    room = str(data['mission_id'])
    client_type = data.get('type', 'viewer')
    join_room(room)
    
    if client_type == 'agent':
        if room in active_streams: active_streams[room]['agent_sid'] = request.sid
        emit('status_msg', {'msg': '✅ AGENTE EN LÍNEA'}, to=room)
    elif room in active_streams:
        stream = active_streams[room]
        emit('status_msg', {'msg': f'🔴 EN VIVO ({stream["port"]})'})
        # Validar dueño de forma segura con .get() para evitar KeyError
        if str(stream.get('owner_id')) == str(session.get('user_id')):
             emit('you_are_broadcaster', {'val': True})
    else:
        emit('status_msg', {'msg': 'Esperando transmisión...'})

@socketio.on('start_stream_mission')
def handle_start_command(data):
    if session.get('role') != 'admin': return
    mid = str(data['mission_id'])
    if mid in active_streams:
        emit('status_msg', {'msg': 'Stream activo.'})
        return
    u = Usuario.query.get(session.get('user_id'))
    # Enviamos orden al agente
    emit('server_command_start', {'puerto': data['puerto'], 'admin_name': u.Nombre, 'owner_id': session.get('user_id')}, to=mid)

@socketio.on('agent_confirm_start')
def handle_agent_confirm(data):
    mid = str(data.get('mission_id'))
    port = data.get('port')
    owner_id = data.get('owner_id') 
    
    active_streams[mid] = {
        'start': datetime.now(),
        'port': port,
        'owner_id': str(owner_id), 
        'broadcaster_name': data.get('admin_name'),
        'last_heartbeat': datetime.now()
    }
    # FIX: Usar server.emit para broadcast global seguro
    socketio.server.emit('mission_started', {'mission_id': mid, 'owner_id': str(owner_id)})
    emit('status_msg', {'msg': f'🔴 INICIADO'}, to=mid)
    emit('you_are_broadcaster', {'val': True}, to=mid)

@socketio.on('stop_stream_mission')
def handle_stop_command(data):
    mid = str(data['mission_id'])
    if mid in active_streams:
        if str(active_streams[mid].get('owner_id')) == str(session.get('user_id')):
            emit('server_command_stop', {}, to=mid)
            del active_streams[mid]
            emit('status_msg', {'msg': 'Detenido.'}, to=mid)
            emit('stream_ended', {'force_reset': True}, to=mid)
            socketio.server.emit('mission_stopped', {'mission_id': mid})
        else:
            emit('status_msg', {'msg': '⛔ Acceso denegado.'})

@socketio.on('ingest_telemetry')
def handle_ingest(data):
    mid = str(data.get('mission_id'))
    if mid not in active_streams:
        emit('server_command_stop', {}, to=request.sid)
        return
    active_streams[mid]['last_heartbeat'] = datetime.now()
    socketio.emit('telemetria', data.get('payload'), to=mid)
    with app.app_context():
        try:
            db.session.add(Trama_CanSat(Trama=data.get('raw_line'), FK_ID_Mision=mid, FK_ID_Usuario=1))
            db.session.commit()
        except: pass

@socketio.on('buscar_puertos')
def handle_request_ports(data):
    mid = str(data.get('mission_id'))
    emit('server_request_ports', {}, to=mid)

@socketio.on('agent_response_ports')
def handle_agent_ports(data):
    mid = str(data.get('mission_id'))
    emit('lista_puertos', data.get('puertos', []), to=mid)

@socketio.on('agent_message')
def handle_agent_msg(data):
    mid = str(data.get('mission_id'))
    emit('status_msg', {'msg': data.get('msg')}, to=mid)

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    socketio.run(app, host='0.0.0.0', debug=True, port=5000)