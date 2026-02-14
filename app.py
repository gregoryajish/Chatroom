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
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max file size
app.config['WTF_CSRF_TIME_LIMIT'] = None  # CSRF tokens don't expire

socketio = SocketIO(app)

# ============ SECURITY & VALIDATION FUNCTIONS ============

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_image(stream):
    """Validate that uploaded file is actually an image"""
    try:
        header = stream.read(512)
        stream.seek(0)
        format = imghdr.what(None, header)
        if not format:
            return False
        return format in ['png', 'jpeg', 'gif']
    except:
        return False

def validate_username(username):
    """Validate username: 3-20 alphanumeric characters"""
    if not username or len(username) < 3 or len(username) > 20:
        return False
    if not username.replace('_', '').isalnum():  # Allow underscores
        return False
    return True

def validate_message(message):
    """Validate message: not empty, max 2000 characters"""
    if not message or len(message.strip()) == 0:
        return False
    if len(message) > 2000:
        return False
    return True

def validate_bio(bio):
    """Validate bio: max 500 characters"""
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

        # Validate inputs
        if not validate_username(username):
            return "Invalid username. Must be 3-20 characters, alphanumeric (underscores allowed).", 400
        
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
            print(e)
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


# ---------------- PROFILE ----------------
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect('/login')
    
    conn = get_connection()
    if conn is None:
        return "Database connection failed"
    
    cur = conn.cursor()
    
    if request.method == 'POST':
        # Handle profile picture upload
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and file.filename != '' and allowed_file(file.filename):
                # Validate MIME type
                if not validate_image(file.stream):
                    return "Invalid image file. Please upload a valid PNG, JPG, or GIF image.", 400
                
                # Ensure upload directory exists
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                
                filename = secure_filename(file.filename)
                # Create unique filename
                unique_filename = f"user_{session['user_id']}_{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(filepath)
                
                # Update database
                cur.execute("""
                    UPDATE users SET profile_picture = %s WHERE id = %s
                """, (unique_filename, session['user_id']))
        
        # Update bio with validation
        if 'bio' in request.form:
            bio = request.form['bio']
            if not validate_bio(bio):
                return "Bio is too long. Maximum 500 characters.", 400
            cur.execute("""
                UPDATE users SET bio = %s WHERE id = %s
            """, (bio, session['user_id']))
        
        # Update email
        if 'email' in request.form:
            email = request.form['email']
            cur.execute("""
                UPDATE users SET email_or_phone = %s WHERE id = %s
            """, (email, session['user_id']))
        
        conn.commit()
        cur.close()
        conn.close()
        return redirect('/profile')
    
    # GET request - fetch user data
    cur.execute("""
        SELECT username, email_or_phone, profile_picture, bio
        FROM users WHERE id = %s
    """, (session['user_id'],))
    user_data = cur.fetchone()
    
    cur.close()
    conn.close()
    
    return render_template('profile.html',
        username=user_data[0],
        email=user_data[1],
        profile_picture=user_data[2],
        bio=user_data[3]
    )


# ---------------- MAIN CHAT (PUBLIC ROOM DEFAULT) ----------------
@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect('/login')

    room_id = 1  # Public room

    conn = get_connection()
    cur = conn.cursor()

    # Load messages with profile pictures
    cur.execute("""
        SELECT users.username, messages.message_text, users.profile_picture
        FROM messages
        JOIN users ON messages.sender_id = users.id
        WHERE room_id = %s
        ORDER BY messages.id ASC
    """, (room_id,))
    messages = cur.fetchall()

    # Load user's private rooms with friend names and profile pictures
    cur.execute("""
        SELECT DISTINCT rooms.id, users.username, users.profile_picture
        FROM rooms
        JOIN room_members ON rooms.id = room_members.room_id
        JOIN room_members AS other_member ON rooms.id = other_member.room_id
        JOIN users ON other_member.user_id = users.id
        WHERE room_members.user_id = %s
          AND other_member.user_id != %s
          AND rooms.is_private = TRUE
    """, (session['user_id'], session['user_id']))
    private_rooms = cur.fetchall()

    # Count pending friend requests
    cur.execute("""
        SELECT COUNT(*) FROM friend_requests
        WHERE receiver_id = %s AND status = 'pending'
    """, (session['user_id'],))
    request_count = cur.fetchone()[0]

    # Get user's profile picture
    cur.execute("""
        SELECT profile_picture FROM users WHERE id = %s
    """, (session['user_id'],))
    user_profile_pic = cur.fetchone()[0]

    cur.close()
    conn.close()

    return render_template(
        'chat.html',
        username=session['username'],
        messages=messages,
        private_rooms=private_rooms,
        current_room=room_id,
        request_count=request_count,
        user_profile_picture=user_profile_pic
    )


# ---------------- OPEN SPECIFIC ROOM ----------------
@app.route('/room/<int:room_id>')
def open_room(room_id):
    if 'user_id' not in session:
        return redirect('/login')

    conn = get_connection()
    cur = conn.cursor()

    # Verify user is a member of this room (security check)
    cur.execute("""
        SELECT 1 FROM room_members 
        WHERE room_id = %s AND user_id = %s
    """, (room_id, session['user_id']))
    
    if not cur.fetchone():
        cur.close()
        conn.close()
        return "Access denied - you are not a member of this room"

    # Load room messages
    cur.execute("""
        SELECT users.username, messages.message_text, users.profile_picture
        FROM messages
        JOIN users ON messages.sender_id = users.id
        WHERE room_id = %s
        ORDER BY messages.id ASC
    """, (room_id,))
    messages = cur.fetchall()

    # Load user's private rooms with friend names and profile pictures
    cur.execute("""
        SELECT DISTINCT rooms.id, users.username, users.profile_picture
        FROM rooms
        JOIN room_members ON rooms.id = room_members.room_id
        JOIN room_members AS other_member ON rooms.id = other_member.room_id
        JOIN users ON other_member.user_id = users.id
        WHERE room_members.user_id = %s
          AND other_member.user_id != %s
          AND rooms.is_private = TRUE
    """, (session['user_id'], session['user_id']))
    private_rooms = cur.fetchall()

    # Count pending friend requests
    cur.execute("""
        SELECT COUNT(*) FROM friend_requests
        WHERE receiver_id = %s AND status = 'pending'
    """, (session['user_id'],))
    request_count = cur.fetchone()[0]

    # Get user's profile picture
    cur.execute("""
        SELECT profile_picture FROM users WHERE id = %s
    """, (session['user_id'],))
    user_profile_pic = cur.fetchone()[0]

    cur.close()
    conn.close()

    return render_template(
        'chat.html',
        username=session['username'],
        messages=messages,
        private_rooms=private_rooms,
        current_room=room_id,
        request_count=request_count,
        user_profile_picture=user_profile_pic
    )


# ---------------- SEND FRIEND REQUEST ----------------
@app.route('/send_request', methods=['POST'])
def send_request():
    if 'user_id' not in session:
        return redirect('/login')

    receiver_username = request.form['username']
    sender_id = session['user_id']

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT id FROM users WHERE username=%s", (receiver_username,))
    receiver = cur.fetchone()

    if not receiver:
        return "User not found"

    receiver_id = receiver[0]

    if receiver_id == sender_id:
        return "Cannot send request to yourself"

    cur.execute("""
        INSERT INTO friend_requests (sender_id, receiver_id, status)
        VALUES (%s, %s, 'pending')
    """, (sender_id, receiver_id))

    conn.commit()
    cur.close()
    conn.close()

    return redirect('/chat')


# ---------------- SEND FRIEND REQUEST (AJAX) ----------------
@app.route('/api/send_request', methods=['POST'])
def api_send_request():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    data = request.get_json()
    receiver_username = data.get('username')
    sender_id = session['user_id']

    conn = get_connection()
    if conn is None:
        return jsonify({'success': False, 'message': 'Database error'}), 500
    
    cur = conn.cursor()

    # Check if user exists
    cur.execute("SELECT id FROM users WHERE username=%s", (receiver_username,))
    receiver = cur.fetchone()

    if not receiver:
        cur.close()
        conn.close()
        return jsonify({'success': False, 'message': 'User not found'}), 404

    receiver_id = receiver[0]

    if receiver_id == sender_id:
        cur.close()
        conn.close()
        return jsonify({'success': False, 'message': 'Cannot send request to yourself'}), 400

    # Check if request already exists
    cur.execute("""
        SELECT id FROM friend_requests 
        WHERE sender_id = %s AND receiver_id = %s
    """, (sender_id, receiver_id))
    
    if cur.fetchone():
        cur.close()
        conn.close()
        return jsonify({'success': False, 'message': 'Friend request already sent'}), 400

    # Insert friend request
    try:
        cur.execute("""
            INSERT INTO friend_requests (sender_id, receiver_id, status)
            VALUES (%s, %s, 'pending')
        """, (sender_id, receiver_id))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'success': True, 'message': 'Friend request sent!'}), 200
    except Exception as e:
        cur.close()
        conn.close()
        return jsonify({'success': False, 'message': 'Error sending request'}), 500


# ---------------- VIEW REQUESTS ----------------
@app.route('/view_requests')
def view_requests():
    if 'user_id' not in session:
        return redirect('/login')

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT friend_requests.id, users.username
        FROM friend_requests
        JOIN users ON friend_requests.sender_id = users.id
        WHERE receiver_id = %s AND status = 'pending'
    """, (session['user_id'],))

    requests = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('requests.html', requests=requests)


# ---------------- ACCEPT REQUEST ----------------
@app.route('/accept_request/<int:request_id>')
def accept_request(request_id):
    if 'user_id' not in session:
        return redirect('/login')

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT sender_id, receiver_id
        FROM friend_requests
        WHERE id = %s
    """, (request_id,))

    request_data = cur.fetchone()

    if not request_data:
        return "Request not found"

    sender_id, receiver_id = request_data

    # Get usernames for creating a unique room name
    cur.execute("SELECT username FROM users WHERE id = %s", (sender_id,))
    sender_username = cur.fetchone()[0]
    
    cur.execute("SELECT username FROM users WHERE id = %s", (receiver_id,))
    receiver_username = cur.fetchone()[0]
    
    # Create unique room name
    room_name = f"{sender_username} & {receiver_username}"

    # Create private room with unique name
    cur.execute("""
        INSERT INTO rooms (is_private, room_name)
        VALUES (TRUE, %s)
        RETURNING id
    """, (room_name,))
    room_id = cur.fetchone()[0]

    # Add members
    cur.execute("""
        INSERT INTO room_members (room_id, user_id)
        VALUES (%s, %s), (%s, %s)
    """, (room_id, sender_id, room_id, receiver_id))

    # Mark request accepted
    cur.execute("""
        UPDATE friend_requests
        SET status='accepted'
        WHERE id=%s
    """, (request_id,))

    conn.commit()
    cur.close()
    conn.close()

    return redirect('/chat')


# ---------------- SOCKET MESSAGE ----------------
@socketio.on('send_message')
def handle_send_message(data):
    if 'user_id' not in session:
        emit('error', {'message': 'Unauthorized'})
        return

    message = data['message']
    room_id = data.get('room_id', 1)

    # Validate message
    if not validate_message(message):
        emit('error', {'message': 'Invalid message. Must be 1-2000 characters.'})
        return

    user_id = session['user_id']
    username = session['username']

    conn = get_connection()
    cur = conn.cursor()

    # Get user's profile picture
    cur.execute("SELECT profile_picture FROM users WHERE id = %s", (user_id,))
    profile_pic = cur.fetchone()[0] if cur.rowcount > 0 else None

    cur.execute("""
        INSERT INTO messages (sender_id, room_id, message_text)
        VALUES (%s, %s, %s)
    """, (user_id, room_id, message))

    conn.commit()
    cur.close()
    conn.close()

    # 🔥 Emit ONLY to that room with profile picture
    emit('receive_message', {
        'username': username,
        'message': message,
        'profile_picture': profile_pic
    }, room=str(room_id))


# ---------------- JOIN ROOM ----------------
@socketio.on('join')
def on_join(data):
    room = str(data['room'])
    join_room(room)


# ---------------- RUN ----------------
import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port)

