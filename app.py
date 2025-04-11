from flask import Flask, render_template, request, jsonify, url_for
from flask_socketio import SocketIO, join_room, leave_room, emit
from werkzeug.exceptions import RequestEntityTooLarge
import qrcode
import os
import random
import string
import sqlite3
import logging
from werkzeug.utils import secure_filename
from datetime import datetime
from flask import send_from_directory
import requests
from dotenv import load_dotenv
from flask import redirect



# Configure logging
logging.basicConfig(level=logging.DEBUG)
active_users = {}
# Flask setup
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
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

# Ensure necessary directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs("static/qr_codes", exist_ok=True)

# Initialize the database
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
        # Table for rooms
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rooms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room_code TEXT NOT NULL UNIQUE,
                genre TEXT NOT NULL
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
        # Redirect to a dynamic URL based on the project ID
        return redirect(f"http://127.0.0.1:5000/room/{project_id}")
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
    genre = request.form.get("genre")
    room_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    
    with sqlite3.connect("data.db") as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO rooms (room_code, genre) VALUES (?, ?)", (room_code, genre))
        conn.commit()

    room_url = url_for("join_room_page", room_code=room_code, _external=True)
    qr = qrcode.make(room_url)
    qr_filename = f"static/qr_codes/{room_code}.png"
    qr.save(qr_filename)

    return render_template("room.html", genre=genre, room_code=room_code, room_url=room_url, qr_code=qr_filename)


# Join room and fetch chat history
@app.route("/room/<room_code>")
def join_room_page(room_code):
    with sqlite3.connect("data.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username, message, timestamp FROM messages WHERE room_code = ? ORDER BY timestamp", (room_code,))
        chat_history = cursor.fetchall()
    return render_template("collaboration.html", room_code=room_code, chat_history=chat_history)





# WebSocket events
@socketio.on("join")
def handle_join(data):
    username = data["username"]
    room_code = data["room"]

    # Ensure the room exists in active_users
    if room_code not in active_users:
        active_users[room_code] = []

    # Check if the username already exists in the room
    if username in active_users[room_code]:
        emit("error", {"message": "Username already exists in the room."}, to=request.sid)
        return

    # Add the username to the room's active user list
    active_users[room_code].append(username)
    join_room(room_code)

    # Inform the room that the user has joined
    emit("joined", {"username": username}, room=room_code)
   

    logging.debug(f"User {username} joined room {room_code}")


@socketio.on("message")
def handle_message(data):
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
    if message.startswith('@genius') or message.startswith('@Genius') or message.startswith('@GENIUS'):
     query = message[len('@genius'):].strip()  # Adjust this to handle all cases

    if query:  # Only generate response if 'query' is not None or empty
        response = generate_bot_response(query)
        
        # Emit the Genius response after the user's message
        emit('message', {
            'username': 'Genius',
            'message': response,
            'timestamp': timestamp,
            'room': room_code,
            'isGenius': True
            }, room=room_code)



@socketio.on("leave")
def handle_leave(data):
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
    room_code = data["room"]
    username = data["username"]
    file_url = data["file_url"]
    filename = file_url.split('/')[-1]  # Extract the file name from the URL

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
        "file_url": file_url    # Pass file URL to frontend
    }, room=room_code)


# File upload route
@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    username = request.form['username']
    room_code = request.form['room_code']
    
    if file:
        # Save the file to the server
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        # Use the correct URL for accessing the file
        file_url = f"/uploads/{file.filename}"

        # Emit the file message to the room using Socket.IO
        socketio.emit('file_message', {
            'username': username,
            'file_url': file_url,
            'room': room_code
        }, room=room_code)

        return jsonify({'file_url': file_url}), 200

    return jsonify({'error': 'No file uploaded'}), 400



@app.route("/room-history/<room_code>")
def room_history(room_code):
    with sqlite3.connect("data.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username, message, timestamp FROM messages WHERE room_code = ? ORDER BY timestamp", (room_code,))
        history = cursor.fetchall()
    
    # Return the chat history as JSON with formatted timestamps
    return jsonify([{
        "username": username, 
        "message": message, 
        "timestamp": datetime.strptime(timestamp, '%b %d, %Y %I:%M %p').strftime('%b %d, %Y %I:%M %p')
    } for username, message, timestamp in history])

    
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
# View all booked rooms
@app.route("/view-rooms")
def view_rooms():
    with sqlite3.connect("data.db") as conn:
        cursor = conn.cursor()
        # Fetch all rooms
        cursor.execute("SELECT room_code, genre FROM rooms")
        rooms = cursor.fetchall()

    # Render the template to display rooms
    return render_template("view_rooms.html", rooms=rooms)

@app.route("/release-room/<room_code>", methods=["GET"])
def release_room(room_code):
    with sqlite3.connect("data.db") as conn:
        cursor = conn.cursor()

        # Check if the room exists
        cursor.execute("SELECT * FROM rooms WHERE room_code = ?", (room_code,))
        room = cursor.fetchone()

        if room:
            # Delete the room from the rooms table
            cursor.execute("DELETE FROM rooms WHERE room_code = ?", (room_code,))
            conn.commit()

            # Optionally, delete related messages and uploads
            cursor.execute("DELETE FROM messages WHERE room_code = ?", (room_code,))
            cursor.execute("DELETE FROM uploads WHERE room_code = ?", (room_code,))
            conn.commit()

            return jsonify({"message": f"Room {room_code} has been successfully released."}), 200
        else:
            return jsonify({"error": "Room not found."}), 404



if __name__ == "__main__":
    # Use socketio.run() to handle both Flask app and SocketIO
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
