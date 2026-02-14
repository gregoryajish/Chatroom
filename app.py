import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template, request, redirect, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from database import get_connection
from flask_socketio import SocketIO, emit, join_room
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
import os
import filetype
import logging

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    filename='chatroom.log',
    level=logging.ERROR,
    format='%(asctime)s %(levelname)s: %(message)s'
)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(24)

# CSRF Protection
csrf = CSRFProtect(app)

# Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Upload configuration
UPLOAD_FOLDER = 'static/uploads/profiles'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
app.config['WTF_CSRF_TIME_LIMIT'] = None

# SocketIO (important for Railway)
socketio = SocketIO(app, async_mode="eventlet")

# ============ VALIDATION FUNCTIONS ============

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_image(stream):
    """Validate uploaded image using filetype (Python 3.13 safe)"""
    try:
        header = stream.read(261)
        stream.seek(0)
        kind = filetype.guess(header)
        if kind is None:
            return False
        return kind.extension in ALLOWED_EXTENSIONS
    except:
        return False


def validate_username(username):
    if not username or len(username) < 3 or len(username) > 20:
        return False
    if not username.replace('_', '').isalnum():
        return False
    return True


def validate_message(message):
    if not message or len(message.strip()) == 0:
        return False
    if len(message) > 2000:
        return False
    return True


def validate_bio(bio):
    if bio and len(bio) > 500:
        return False
    return True


# ---------------- HOME ----------------
@app.route('/')
def home():
    return redirect('/login')


# ---------------- REGISTER ----------------
@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email_or_phone = request.form['email']
        ip_address = request.remote_addr

        if not validate_username(username):
            return "Invalid username", 400

        if len(password) < 6:
            return "Password must be at least 6 characters long.", 400

        hashed_password = generate_password_hash(password)

        conn = get_connection()
        if conn is None:
            return "Database connection failed"

        cur = conn.cursor()

        try:
            cur.execute("""
                INSERT INTO users (username, password_hash, email_or_phone, ip_address)
                VALUES (%s, %s, %s, %s)
            """, (username, hashed_password, email_or_phone, ip_address))
            conn.commit()
            return redirect('/login')

        except Exception as e:
            logging.error(str(e))
            return "Username or email already exists!"

        finally:
            cur.close()
            conn.close()

    return render_template('register.html')


# ---------------- LOGIN ----------------
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_connection()
        if conn is None:
            return "Database connection failed"

        cur = conn.cursor()
        cur.execute("SELECT id, password_hash FROM users WHERE username=%s", (username,))
        user = cur.fetchone()

        cur.close()
        conn.close()

        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['username'] = username
            return redirect('/chat')
        else:
            return "Invalid username or password"

    return render_template('login.html')


# ---------------- CHAT ----------------
@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect('/login')

    room_id = 1

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT users.username, messages.message_text, users.profile_picture
        FROM messages
        JOIN users ON messages.sender_id = users.id
        WHERE room_id = %s
        ORDER BY messages.id ASC
    """, (room_id,))
    messages = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        'chat.html',
        username=session['username'],
        messages=messages,
        current_room=room_id
    )


# ---------------- SOCKET MESSAGE ----------------
@socketio.on('send_message')
def handle_send_message(data):
    if 'user_id' not in session:
        emit('error', {'message': 'Unauthorized'})
        return

    message = data['message']
    room_id = data.get('room_id', 1)

    if not validate_message(message):
        emit('error', {'message': 'Invalid message'})
        return

    user_id = session['user_id']
    username = session['username']

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO messages (sender_id, room_id, message_text)
        VALUES (%s, %s, %s)
    """, (user_id, room_id, message))

    conn.commit()
    cur.close()
    conn.close()

    emit('receive_message', {
        'username': username,
        'message': message
    }, room=str(room_id))


# ---------------- JOIN ROOM ----------------
@socketio.on('join')
def on_join(data):
    room = str(data['room'])
    join_room(room)


# ---------------- RUN ----------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port)
