from flask import Flask, render_template, request, jsonify, url_for, make_response, session
from flask_socketio import SocketIO, join_room, leave_room, emit
from werkzeug.exceptions import RequestEntityTooLarge
import qrcode
import os
import random
import string
import sqlite3
import logging
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from flask import send_from_directory, abort
import requests
from dotenv import load_dotenv
from flask import redirect
import hashlib
import secrets
import uuid

# Configure logging
logging.basicConfig(level=logging.DEBUG)
active_users = {}
# Flask setup
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)  # Generate a secure random key
socketio = SocketIO(app)


# Configuration for uploads
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'pdf', 'txt', 'doc', 'docx','ppt',"pptx"}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB limit

# Error handling for large files
@app.errorhandler(RequestEntityTooLarge)
def handle_file_size_error(error):
    return jsonify({"error": "File is too large. Maximum allowed size is 100MB."}), 413

# Error handling for 404 errors
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error="Page not found", code=404), 404

# Error handling for 500 errors
@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', error="Internal server error", code=500), 500

# Ensure necessary directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs("static/qr_codes", exist_ok=True)

# Initialize the database
# Generate a secure CSRF token
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

# Add CSRF token to all templates
app.jinja_env.globals['csrf_token'] = generate_csrf_token

# Securely hash passwords
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    # Create a hash with salt
    hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    hash_hex = hash_obj.hex()
    return f"{salt}${hash_hex}"

# Verify a password against a hash
def verify_password(stored_hash, provided_password):
    if not stored_hash or '$' not in stored_hash:
        return False
    salt, hash_value = stored_hash.split('$', 1)
    new_hash = hash_password(provided_password, salt)
    return new_hash == stored_hash

def init_db():
    with sqlite3.connect("data.db") as conn:
        cursor = conn.cursor()
        # Table for file uploads
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS uploads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                file_url TEXT NOT NULL,
                username TEXT NOT NULL,
                room_code TEXT NOT NULL
            )
        """)
        
        # Check if rooms table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='rooms'")
        table_exists = cursor.fetchone()
        
        if table_exists:
            # Check if view_password and host_password columns exist
            cursor.execute("PRAGMA table_info(rooms)")
            columns = cursor.fetchall()
            column_names = [column[1] for column in columns]
            
            # If columns don't exist, add them
            if 'view_password' not in column_names:
                cursor.execute("ALTER TABLE rooms ADD COLUMN view_password TEXT DEFAULT ''")
            if 'host_password' not in column_names:
                cursor.execute("ALTER TABLE rooms ADD COLUMN host_password TEXT DEFAULT ''")
            if 'csrf_token' not in column_names:
                cursor.execute("ALTER TABLE rooms ADD COLUMN csrf_token TEXT DEFAULT ''")
                
            # Update existing rooms to have secure passwords
            cursor.execute("SELECT room_code, view_password, host_password FROM rooms")
            rooms = cursor.fetchall()
            for room in rooms:
                room_code, view_password, host_password = room
                
                # Only update if passwords aren't already hashed (no $ in the string)
                if view_password and '$' not in view_password:
                    hashed_view_password = hash_password(view_password)
                    cursor.execute("UPDATE rooms SET view_password = ? WHERE room_code = ?", 
                                (hashed_view_password, room_code))
                    
                if host_password and '$' not in host_password:
                    hashed_host_password = hash_password(host_password)
                    cursor.execute("UPDATE rooms SET host_password = ? WHERE room_code = ?", 
                                (hashed_host_password, room_code))
                
                # Generate a CSRF token for each room
                csrf_token = secrets.token_hex(16)
                cursor.execute("UPDATE rooms SET csrf_token = ? WHERE room_code = ?", 
                            (csrf_token, room_code))
        else:
            # Create rooms table with password columns and CSRF token
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS rooms (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    room_code TEXT NOT NULL UNIQUE,
                    genre TEXT NOT NULL,
                    view_password TEXT NOT NULL,
                    host_password TEXT NOT NULL,
                    csrf_token TEXT NOT NULL
                )
            """)
            
        # Table for messages with timestamp
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room_code TEXT NOT NULL,
                username TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()

init_db()

# Sample data
genres = ["Drama", "Thriller", "Comedy", "Fantasy", "Sci-Fi", "Romance"]
projects = [
    {"id": 1, "title": "The Storm Within", "genre": "Drama", "description": "An emotional journey through..."},
    {"id": 2, "title": "The Selfie Disaster", "genre": "Comedy", "description": "A humorous take on modern life..."},
]

# Generate response from Groq API
def generate_bot_response(query):
    try:
        # Check for predefined responses
        predefined_responses = {
            "who are you": "I'm Genius AI, specially trained for Scene Weaver. I improvise text and assist with scriptwriting.",
            "what is scene weaver": "Scene Weaver is a tool that automates the analysis and synthesis of multiple drafts into a cohesive, polished script. It helps with collaboration and script editing.",
            # Add more predefined responses as needed
        }

        # Convert query to lowercase for easier matching
        query_lower = query.lower()

        # Check if the query matches a predefined response
        if query_lower in predefined_responses:
            return predefined_responses[query_lower]

        # If not a predefined query, proceed to Groq API for AI response
        api_key = os.getenv('GROQ_API_KEY')
        api_url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        data = {
            "model": "llama3-8b-8192",
            "messages": [{"role": "user", "content": query}],
            "max_tokens": 150,
            "temperature": 0.7,
        }

        # Call the API
        response = requests.post(api_url, json=data, headers=headers)

        # Log the full API response for debugging
        logging.debug(f"Groq API response: {response.json()}")

        if response.status_code == 200:
            response_json = response.json()
            # Extract the assistant's content from the API response
            answer = response_json["choices"][0]["message"]["content"].strip()
            return answer
        else:
            logging.error(f"Groq API error: {response.status_code} - {response.text}")
            return "Sorry, I couldn't process your request at the moment."

    except Exception as e:
        logging.error(f"Error generating response from Groq: {e}")
        return "Sorry, I couldn't process your request at the moment."
# Helper function to check allowed file types
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Home route
@app.route("/")
def home():
    return render_template("index.html", genres=genres, projects=projects)

@app.route("/project/<int:project_id>")
def project_details(project_id):
    # Find the project by ID
    project = next((p for p in projects if p["id"] == project_id), None)
    
    if project:
        # Redirect to a dynamic URL based on the project ID using url_for
        return redirect(url_for('join_room_page', room_code=project_id, _external=True))
    else:
        return "Project not found", 404

# Search API
@app.route("/search", methods=["POST"])
def search():
    query = request.json.get("query", "").lower()
    filtered_projects = [proj for proj in projects if query in proj["title"].lower() or query in proj["description"].lower()]
    return jsonify(filtered_projects)

# Room creation
@app.route("/create-room", methods=["POST"])
def create_room():
    # Validate form data
    genre = request.form.get("genre")
    username = request.form.get("username", "Host")  # Get username if provided
    
    if not genre:
        return render_template('error.html', error="Genre is required", code=400), 400
    
    # Generate a secure room code
    room_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    
    # Generate secure random passwords for viewing and hosting
    view_password_plain = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    host_password_plain = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    
    # Hash the passwords for storage
    view_password_hash = hash_password(view_password_plain)
    host_password_hash = hash_password(host_password_plain)
    
    # Generate CSRF token for this room
    csrf_token = secrets.token_hex(16)
    
    with sqlite3.connect("data.db") as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO rooms (room_code, genre, view_password, host_password, csrf_token) VALUES (?, ?, ?, ?, ?)", 
                      (room_code, genre, view_password_hash, host_password_hash, csrf_token))
        conn.commit()

    # Generate room URL with username parameter for persistence
    room_url = url_for("join_room_page", room_code=room_code, username=username, _external=True)
    qr = qrcode.make(room_url)
    qr_filename = f"static/qr_codes/{room_code}.png"
    qr.save(qr_filename)

    # Set a secure cookie with the room's CSRF token
    response = make_response(render_template(
        "room.html", 
        genre=genre, 
        room_code=room_code, 
        room_url=room_url, 
        qr_code=qr_filename,
        username=username,
        view_password=view_password_plain,  # Pass plain view password to template
        host_password=host_password_plain,   # Pass plain host password to template
        csrf_token=csrf_token  # Pass CSRF token to template
    ))
    
    # Set secure cookie for the room creator (host)
    response.set_cookie(
        f'host_auth_{room_code}', 
        host_password_plain, 
        max_age=86400,  # 24 hour expiry
        httponly=True,   # Not accessible via JavaScript
        samesite='Strict'  # Prevents CSRF attacks
    )
    
    return response


# Join room and fetch chat history
@app.route("/room/<room_code>", methods=["GET", "POST"])
def join_room_page(room_code):
    # Check if the room exists
    with sqlite3.connect("data.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT room_code, genre, view_password, csrf_token FROM rooms WHERE room_code = ?", (room_code,))
        room = cursor.fetchone()
        
        if not room:
            return render_template('error.html', error="Room not found", code=404), 404
        
        room_code, genre, stored_view_password, csrf_token = room
        
        # Check for authenticated session or direct password submission
        is_authenticated = False
        
        # Check if user has a valid authentication cookie for this room
        auth_cookie = request.cookies.get(f'room_auth_{room_code}')
        if auth_cookie:
            # Verify the cookie value against the stored password hash
            is_authenticated = verify_password(stored_view_password, auth_cookie)
        
        # Handle POST request for password submission
        if request.method == "POST":
            submitted_password = request.form.get('password', '')
            # Get username from URL parameter or use a default
            username = request.args.get('username', 'Guest')
            
            # Verify the submitted password against the stored hash
            if verify_password(stored_view_password, submitted_password):
                # Get chat history for authenticated users
                cursor.execute("SELECT username, message, timestamp FROM messages WHERE room_code = ? ORDER BY timestamp", (room_code,))
                chat_history = cursor.fetchall()
                
                # Create response with authentication cookie
                response = make_response(render_template(
                    "collaboration.html", 
                    room_code=room_code, 
                    chat_history=chat_history,
                    username=username,
                    csrf_token=csrf_token
                ))
                
                # Set secure authentication cookie with the plain password
                # We store the plain password in the cookie because we'll verify it against the hash in the database
                response.set_cookie(
                    f'room_auth_{room_code}', 
                    submitted_password, 
                    max_age=86400,  # 24 hour expiry
                    httponly=True,  # Not accessible via JavaScript
                    samesite='Strict'  # Prevents CSRF attacks
                )
                return response
            else:
                # Wrong password
                return render_template('room_auth.html', room_code=room_code, error="Incorrect password", genre=genre)
        
        # If already authenticated, proceed to room
        if is_authenticated:
            # Get chat history
            cursor.execute("SELECT username, message, timestamp FROM messages WHERE room_code = ? ORDER BY timestamp", (room_code,))
            chat_history = cursor.fetchall()
            
            # Get username from query parameter if provided (for rejoining)
            username = request.args.get('username', '')
            
            if not username:
                # If no username in URL, check if we can get it from active_users
                for user_id, user_data in active_users.items():
                    if user_data.get('room') == room_code:
                        username = user_data.get('username', '')
                        break
            
            # If still no username, use a default
            if not username:
                username = 'Guest'
            
            return render_template(
                "collaboration.html", 
                room_code=room_code, 
                chat_history=chat_history,
                username=username,
                csrf_token=csrf_token
            )
        
        # Not authenticated, show password form
        return render_template('room_auth.html', room_code=room_code, genre=genre)





# Verify CSRF token for socket events
def verify_socket_csrf(data):
    # Get the CSRF token from the data
    csrf_token = data.get('csrf_token', '')
    room_code = data.get('room', '')
    
    # If no CSRF token or room code, return False
    if not csrf_token or not room_code:
        return False
    
    # Verify the CSRF token against the one stored in the database
    with sqlite3.connect("data.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT csrf_token FROM rooms WHERE room_code = ?", (room_code,))
        result = cursor.fetchone()
        
        if not result:
            return False
        
        stored_csrf_token = result[0]
        
        # Return True if the tokens match
        return csrf_token == stored_csrf_token

# WebSocket events
@socketio.on("join")
def handle_join(data):
    try:
        # Verify CSRF token for security
        if not verify_socket_csrf(data):
            # If verification fails, emit an error and return
            emit("error", {"message": "Authentication failed. Please refresh the page and try again."}, room=request.sid)
            return
            
        username = data["username"]
        room_code = data["room"]

        # Check if the room exists in the database
        with sqlite3.connect("data.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM rooms WHERE room_code = ?", (room_code,))
            room = cursor.fetchone()
            
            if not room:
                emit("error", {"message": "Room not found."}, room=request.sid)
                return

        # Ensure the room exists in active_users
        if room_code not in active_users:
            active_users[room_code] = []

        # Check if this is a rejoin (user already in the room)
        is_rejoin = username in active_users[room_code]

        # Add the username to the room's active user list if not already there
        if not is_rejoin:
            active_users[room_code].append(username)
        
        # Join the Socket.IO room
        join_room(room_code)

        # Check if this is the host (first user to join)
        is_host = len(active_users[room_code]) == 1
        
        # If this is the host, send them the host password (room code reversed)
        if is_host:
            host_password = room_code[::-1]  # Simple reversing for demo purposes
            emit("host_credentials", {
                "password": host_password,
                "room_code": room_code
            }, room=request.sid)  # Send only to the host

        # Inform the room that the user has joined (only if not rejoining)
        if not is_rejoin:
            emit("joined", {"username": username}, room=room_code)
        
        # Get chat history from the database
        with sqlite3.connect("data.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username, message, timestamp FROM messages WHERE room_code = ? ORDER BY timestamp", (room_code,))
            history = cursor.fetchall()
        
        # Send chat history to the user who just joined, marking them as initial load
        for msg in history:
            emit("message", {
                "username": msg[0],
                "message": msg[1],
                "timestamp": msg[2],
                "isInitialLoad": True
            }, room=request.sid)
        
        # Signal that history loading is complete
        emit("chat_history", {"complete": True}, room=request.sid)
        
        logging.debug(f"User {username} joined room {room_code}")
    except Exception as e:
        logging.error(f"Error in handle_join: {str(e)}")
        emit("error", {"message": "An error occurred while joining the room."}, room=request.sid)


@socketio.on("message")
def handle_message(data):
    try:
        # Verify CSRF token for security
        if not verify_socket_csrf(data):
            # If verification fails, emit an error and return
            emit("error", {"message": "Authentication failed. Please refresh the page and try again."}, room=request.sid)
            return
            
        room_code = data["room"]
        username = data["username"]
        message = data["message"]

        # Get the current timestamp in the desired format
        timestamp = datetime.now().strftime('%b %d, %Y %I:%M %p')

        # Save the user message to the database
        with sqlite3.connect("data.db") as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO messages (room_code, username, message, timestamp) VALUES (?, ?, ?, ?)", 
                        (room_code, username, message, timestamp))
            conn.commit()  # Commit inside the 'with' block

        # Emit the user message to the room
        emit("message", {
            "username": username,
            "message": message,
            "timestamp": timestamp,
            "room": room_code
        }, room=room_code)

        # Initialize 'query' to avoid UnboundLocalError
        query = None

        # If it's a Genius query, generate a response and send it
        if message.lower().startswith('@genius'):
            query = message[len('@genius'):].strip()

        if query:  # Only generate response if 'query' is not None or empty
            response = generate_bot_response(query)
            
            # Save the bot response to the database
            with sqlite3.connect("data.db") as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO messages (room_code, username, message, timestamp) VALUES (?, ?, ?, ?)", 
                            (room_code, 'Genius', response, timestamp))
                conn.commit()
            
            # Emit the Genius response after the user's message
            emit('message', {
                'username': 'Genius',
                'message': response,
                'timestamp': timestamp,
                'room': room_code,
                'isGenius': True
                }, room=room_code)
    except Exception as e:
        logging.error(f"Error handling message: {str(e)}")
        emit("error", {"message": "An error occurred while processing your message."}, room=request.sid)



@socketio.on("leave")
def handle_leave(data):
    # Verify CSRF token for security
    if not verify_socket_csrf(data):
        # If verification fails, emit an error and return
        emit("error", {"message": "Authentication failed. Please refresh the page and try again."}, room=request.sid)
        return
        
    username = data["username"]
    room_code = data["room"]

    # Remove the user from the room's active users list
    if room_code in active_users and username in active_users[room_code]:
        active_users[room_code].remove(username)

    # Leave the room
    leave_room(room_code)
    logging.debug(f"User {username} left room {room_code}")

    # Emit a similar structure to the "join" message
    emit("left", {"username": username, "message": f"{username} has left the room."}, room=room_code)

    
@socketio.on("file_upload")
def handle_file_upload(data):
    try:
        room_code = data["room"]
        username = data["username"]
        file_url = data["file_url"]
        filename = file_url.split('/')[-1]  # Extract the file name from the URL
        timestamp = datetime.now().strftime('%b %d, %Y %I:%M %p')

        # Save file details in the database
        with sqlite3.connect("data.db") as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO uploads (filename, file_url, username, room_code) VALUES (?, ?, ?, ?)", 
                (filename, file_url, username, room_code)
            )
            conn.commit()

        # Emit a system message indicating the file upload, with the actual file name
        emit("message", {
            "username": "System", 
            "message": f"{username} uploaded a file: {filename}",
            "room": room_code,
            "filename": filename,  # Pass filename to frontend
            "file_url": file_url,   # Pass file URL to frontend
            "timestamp": timestamp
        }, room=room_code)
    except Exception as e:
        logging.error(f"Error handling file upload: {str(e)}")
        emit("error", {"message": "An error occurred while processing your file upload."}, room=request.sid)


# File upload route
@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file part"}), 400
            
        file = request.files['file']
        username = request.form.get('username', 'Unknown')
        room_code = request.form.get('room_code', '')
        
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
            
        if not allowed_file(file.filename):
            return jsonify({"error": "File type not allowed"}), 400
        
        # Add timestamp to filename to prevent overwriting
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        original_filename = secure_filename(file.filename)
        filename_parts = os.path.splitext(original_filename)
        filename = f"{filename_parts[0]}_{timestamp}{filename_parts[1]}"
        
        # Save the file to the server
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Use the correct URL for accessing the file
        file_url = f"/uploads/{filename}"

        # Emit the file message to the room using Socket.IO
        socketio.emit('file_message', {
            'username': username,
            'file_url': file_url,
            'room': room_code
        }, room=room_code)

        return jsonify({'file_url': file_url}), 200
    except Exception as e:
        logging.error(f"Error uploading file: {str(e)}")
        return jsonify({'error': f'Error uploading file: {str(e)}'}), 500



@app.route("/room-history/<room_code>")
def room_history(room_code):
    with sqlite3.connect("data.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username, message, timestamp FROM messages WHERE room_code = ? ORDER BY timestamp", (room_code,))
        history = cursor.fetchall()
    
    # Return the chat history as JSON with formatted timestamps and mark as initial load
    messages = [{
        "username": username, 
        "message": message, 
        "timestamp": datetime.strptime(timestamp, '%b %d, %Y %I:%M %p').strftime('%b %d, %Y %I:%M %p'),
        "isInitialLoad": True
    } for username, message, timestamp in history]
    
    return jsonify({
        "messages": messages,
        "complete": True
    })

    
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
# View all booked rooms
@app.route("/view-rooms")
def view_rooms():
    # Show all rooms without admin authentication
    with sqlite3.connect("data.db") as conn:
        cursor = conn.cursor()
        # Fetch all rooms
        cursor.execute("SELECT room_code, genre FROM rooms")
        rooms = cursor.fetchall()

    # Render the template to display rooms
    return render_template("view_rooms.html", rooms=rooms)

@app.route("/release-room/<room_code>", methods=["GET", "POST"])
def release_room(room_code):
    # For GET requests, just check if the room exists and return room info
    if request.method == "GET":
        with sqlite3.connect("data.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT room_code, genre, csrf_token FROM rooms WHERE room_code = ?", (room_code,))
            room = cursor.fetchone()
            
            if not room:
                return jsonify({"error": "Room not found."}), 404
                
            # Return room info with CSRF token for security
            return jsonify({
                "room_code": room_code, 
                "genre": room[1],
                "csrf_token": room[2]
            }), 200
    
    # For POST requests, verify the password and CSRF token, then release the room
    elif request.method == "POST":
        data = request.get_json()
        password = data.get('password')
        csrf_token = data.get('csrf_token')
        
        if not password:
            return jsonify({"error": "Password is required."}), 400
            
        if not csrf_token:
            return jsonify({"error": "CSRF token is required."}), 400
        
        # Get the host password and CSRF token from the database
        with sqlite3.connect("data.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT host_password, csrf_token FROM rooms WHERE room_code = ?", (room_code,))
            result = cursor.fetchone()
            
            if not result:
                return jsonify({"error": "Room not found."}), 404
                
            stored_host_password, stored_csrf_token = result
            
            # Verify the CSRF token
            if csrf_token != stored_csrf_token:
                return jsonify({"error": "Invalid request. Please try again."}), 403
            
            # Check for host authentication cookie first
            host_cookie = request.cookies.get(f'host_auth_{room_code}')
            is_host_authenticated = False
            
            if host_cookie:
                # Verify the cookie value against the stored host password hash
                is_host_authenticated = verify_password(stored_host_password, host_cookie)
            
            # If not authenticated by cookie, check the provided password
            if not is_host_authenticated:
                # Verify the submitted password against the stored hash
                if not verify_password(stored_host_password, password):
                    return jsonify({"error": "Incorrect password. Only the host can release this room."}), 403
            
            # Authentication successful, proceed with room release
            cursor.execute("SELECT * FROM rooms WHERE room_code = ?", (room_code,))
            room = cursor.fetchone()

            if room:
                # Delete the room from the rooms table
                cursor.execute("DELETE FROM rooms WHERE room_code = ?", (room_code,))
                conn.commit()

                # Delete related messages and uploads
                cursor.execute("DELETE FROM messages WHERE room_code = ?", (room_code,))
                cursor.execute("DELETE FROM uploads WHERE room_code = ?", (room_code,))
                conn.commit()
                
                # Notify all users in the room that it has been ended by the host
                socketio.emit("room_ended", {
                    "message": "The host has ended this room session.",
                    "room_code": room_code
                }, room=room_code)

                # Create response with success message
                response = make_response(jsonify({"message": f"Room {room_code} has been successfully released."}), 200)
                
                # Clear the authentication cookies
                response.set_cookie(f'room_auth_{room_code}', '', expires=0)
                response.set_cookie(f'host_auth_{room_code}', '', expires=0)
                
                return response
            else:
                return jsonify({"error": "Room not found."}), 404



# Create error.html template if it doesn't exist
os.makedirs("templates", exist_ok=True)
if not os.path.exists("templates/error.html"):
    with open("templates/error.html", "w") as f:
        f.write('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error - Scene Weaver</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='styles2.css') }}">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    <style>
        .error-container {
            text-align: center;
            padding: 50px 20px;
            max-width: 600px;
            margin: 0 auto;
        }
        .error-code {
            font-size: 72px;
            color: #dc3545;
            margin-bottom: 20px;
        }
        .error-message {
            font-size: 24px;
            margin-bottom: 30px;
        }
        .home-button {
            display: inline-block;
            padding: 10px 20px;
            background-color: #007bff;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            font-weight: bold;
            transition: background-color 0.3s;
        }
        .home-button:hover {
            background-color: #0056b3;
        }
    </style>
</head>
<body>
    <header>
        <h1>Scene Weaver</h1>
    </header>
    
    <div class="error-container">
        <div class="error-code">{{ code }}</div>
        <div class="error-message">{{ error }}</div>
        <a href="/" class="home-button">Return to Home</a>
    </div>
    
    <footer>
        <p>&copy; 2025 Scene Weaver. All rights reserved.</p>
    </footer>
</body>
</html>
''')

app = Flask(__name__)
socketio = SocketIO(app, async_mode="gevent")

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=10000)