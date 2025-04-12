# 🎬 Scene Weaver

**Scene Weaver** is an intelligent AI-powered collaboration platform designed to revolutionize the scriptwriting process. It not only automates the analysis and synthesis of multiple drafts into a cohesive and polished scene, but also provides real-time collaboration tools for writers, editors, and producers. 
Scene Weaver ensures a smooth, unified writing experience, enhancing both productivity and creative quality.

---

**SCENE WEAVER WEB URL**: https://sceneweaver.onrender.com/
## 📌 Features

- 🛠️ **Room Management**: Create, join, or delete secure collaboration rooms
- 🔐 **Two-Level Authentication**: View and host passwords with PBKDF2 hashing
- 💬 **Real-Time Chat**: Live conversations powered by Flask-SocketIO
- 📁 **File Sharing**: Upload and share files up to 100MB (images, docs, etc.)
- 👥 **User Tracking**: Display active users with join/leave notifications
- 📷 **QR Code Sharing**: Easy access via generated QR codes
- 🛡️ **Security-First Design**: CSRF protection, secure cookies, input sanitization
- 💬 **Genius-AI**:Get on-demand help through the @Genius Bot, a built-in chatbot that offers:
Answers to writing-related queries
Scriptwriting recommendations
- 🔐 **Genius AI Tool**:Leverage an advanced AI assistant for 1. Real-time script analysis.2. Intelligent enhancements. 3. Script editing.4. Draft comparison.


---

## 🧱 Tech Stack

### Backend

- **Framework**: Flask
- **Real-Time**: Flask-SocketIO
- **Database**: SQLite (direct SQL with `sqlite3`)
- **Authentication**: Custom with PBKDF2 + SHA-256
- **Security**: CSRF protection, session cookies, input validation

### Frontend

- **Templating**: Jinja2
- **JavaScript**: Vanilla JS + Socket.IO client
- **CSS**: Custom styles (`styles2.css`, `styles3.css`, `styles4.css`)
- **Icons**: Font Awesome

### Dependencies

- `Flask`, `Flask-SocketIO`
- `Werkzeug` – secure file handling
- `qrcode` – QR code generation
- `python-dotenv` – environment variable management
- `requests` – optional API integration
- `eventlet` – Socket.IO async support

---

### Data Processing
-`Difflib` : A Python library for comparing sequences, often used for text comparison or finding similarities.
-`GroqAPI`: Likely referring to an API service for interacting with Groq, a company providing AI hardware solutions.
### Machine Learning & AI
-`Claude AI (Sonnet 3.5)`: Advanced AI model by Anthropic, known for context-aware, safe, and intelligent conversations and content generation.
-`Llama 3`: Likely referring to a model or version of Llama, an open-source large language model developed by Meta (formerly Facebook).

### Web Application
-`Streamlit`: An open-source app framework for building and sharing data apps, often used for creating interactive dashboards and visualizations.


## 🧩 Architecture Overview

### Database Schema

| Table     | Purpose                                   |
|-----------|-------------------------------------------|
| `rooms`   | Room metadata (code, name, password, etc.)|
| `messages`| Chat logs per room                        |
| `uploads` | Tracks uploaded files per room            |

### Authentication

- **Two-tier**: `view password` for participants, `host password` for admins
- **Hashing**: PBKDF2 with salt (SHA-256)
- **Sessions**: Cookie-based auth
- **CSRF**: Token-based validation

### Real-Time Communication

- WebSockets via Socket.IO for:
  - Messaging
  - Room entry/exit
  - File share notifications
  - Room status updates

---

## 🚀 Getting Started

### 1. Clone the repository

### SCENE WEAVER 

```bash
git clone https://github.com/KarthikRommula/sceneweaver_application.git
cd scene-weaver

### SCENE WEAVER - GENIUS AI TOOL
```bash
git clone https://github.com/KarthikRommula/scene_weaver_AI.git