#!/usr/bin/env python3
"""
VULNERABLE AGENTIC AGENT - FOR EDUCATIONAL PURPOSES ONLY
This application is intentionally insecure to demonstrate OWASP vulnerabilities.
DO NOT USE IN PRODUCTION OR WITH REAL DATA.
"""

import os
import sqlite3
import hashlib
import subprocess
import urllib.request
import json
import base64
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from werkzeug.utils import secure_filename
import jwt
import requests

app = Flask(__name__)

# A05:2021 - Security Misconfiguration
# Weak secret key and debug mode enabled
app.config['SECRET_KEY'] = 'weak_secret_key_123'
app.config['DEBUG'] = True

# A02:2021 - Cryptographic Failures
# Weak encryption key
ENCRYPTION_KEY = b'weak_key_32_bytes_long_12345'

# A07:2021 - Authentication Failures
# Hardcoded admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"  # Weak password

# A06:2021 - Vulnerable Components
# Using outdated JWT library with weak algorithms
JWT_SECRET = "weak_jwt_secret"

# Initialize database with weak security practices
def init_db():
    conn = sqlite3.connect('vulnerable_agent.db')
    cursor = conn.cursor()
    
    # A01:2021 - Broken Access Control
    # No proper user roles or permissions
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user'
        )
    ''')
    
    # A03:2021 - Injection
    # Table for storing user data without proper validation
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_data (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert default admin user with weak password
    cursor.execute('''
        INSERT OR IGNORE INTO users (username, password, role) 
        VALUES (?, ?, ?)
    ''', (ADMIN_USERNAME, hashlib.md5(ADMIN_PASSWORD.encode()).hexdigest(), 'admin'))
    
    conn.commit()
    conn.close()

# A03:2021 - Injection
# Vulnerable SQL query function
def execute_sql_query(query):
    conn = sqlite3.connect('vulnerable_agent.db')
    cursor = conn.cursor()
    # VULNERABLE: Direct string concatenation - SQL Injection
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    return result

# A02:2021 - Cryptographic Failures
# Weak encryption function
def weak_encrypt(data):
    # VULNERABLE: Using weak encryption
    return base64.b64encode(data.encode()).decode()

def weak_decrypt(encrypted_data):
    # VULNERABLE: Weak decryption
    return base64.b64decode(encrypted_data.encode()).decode()

# A07:2021 - Authentication Failures
# Weak session management
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # VULNERABLE: Weak password comparison
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['user_id'] = 1
            session['username'] = username
            session['role'] = 'admin'
            # VULNERABLE: No session timeout
            return redirect(url_for('dashboard'))
        else:
            return "Invalid credentials", 401
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    # VULNERABLE: No authentication check
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # A01:2021 - Broken Access Control
    # VULNERABLE: No proper authorization checks
    return render_template('dashboard.html', user=session)

# A03:2021 - Injection
# SQL Injection vulnerable endpoint
@app.route('/api/user_data', methods=['GET'])
def get_user_data():
    user_id = request.args.get('user_id')
    
    # VULNERABLE: SQL Injection
    query = f"SELECT * FROM user_data WHERE user_id = {user_id}"
    result = execute_sql_query(query)
    
    return jsonify(result)

# A03:2021 - Injection
# Command Injection vulnerable endpoint
@app.route('/api/execute', methods=['POST'])
def execute_command():
    command = request.json.get('command')
    
    # VULNERABLE: Command Injection
    # No input validation or sanitization
    try:
        result = subprocess.check_output(command, shell=True, text=True)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# A10:2021 - Server-Side Request Forgery (SSRF)
@app.route('/api/fetch_url', methods=['POST'])
def fetch_url():
    url = request.json.get('url')
    
    # VULNERABLE: SSRF - No URL validation
    try:
        response = requests.get(url, timeout=5)
        return jsonify({
            'status_code': response.status_code,
            'content': response.text[:1000]  # Limit response size
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# A08:2021 - Software and Data Integrity Failures
# Unsafe file upload
@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    # VULNERABLE: No file type validation
    # VULNERABLE: No file size limits
    # VULNERABLE: Unsafe file path
    filename = file.filename
    file_path = os.path.join('uploads', filename)
    
    # Create uploads directory if it doesn't exist
    os.makedirs('uploads', exist_ok=True)
    
    file.save(file_path)
    
    return jsonify({'message': f'File uploaded successfully: {filename}'})

# A01:2021 - Broken Access Control
# Insecure file download
@app.route('/api/download/<filename>')
def download_file(filename):
    # VULNERABLE: Path traversal possible
    # VULNERABLE: No authentication required
    file_path = os.path.join('uploads', filename)
    
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            content = f.read()
        return jsonify({'content': content})
    else:
        return jsonify({'error': 'File not found'}), 404

# A02:2021 - Cryptographic Failures
# Weak JWT token generation
@app.route('/api/generate_token', methods=['POST'])
def generate_token():
    user_data = request.json
    
    # VULNERABLE: Using weak algorithm and secret
    payload = {
        'user_id': user_data.get('user_id'),
        'username': user_data.get('username'),
        'role': user_data.get('role', 'user'),
        'exp': datetime.utcnow() + timedelta(days=30)  # Long expiration
    }
    
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    return jsonify({'token': token})

# A05:2021 - Security Misconfiguration
# Exposed debug information
@app.route('/api/debug')
def debug_info():
    # VULNERABLE: Exposing sensitive information
    return jsonify({
        'database_path': 'vulnerable_agent.db',
        'upload_directory': 'uploads',
        'secret_key': app.config['SECRET_KEY'],
        'jwt_secret': JWT_SECRET,
        'admin_credentials': f'{ADMIN_USERNAME}:{ADMIN_PASSWORD}',
        'server_info': {
            'python_version': os.sys.version,
            'working_directory': os.getcwd(),
            'environment_variables': dict(os.environ)
        }
    })

# Agent functionality with vulnerabilities
@app.route('/api/agent/execute', methods=['POST'])
def agent_execute():
    task = request.json.get('task')
    user_id = request.json.get('user_id')
    
    # VULNERABLE: No input validation
    # VULNERABLE: No authentication required
    # VULNERABLE: Command injection possible
    
    if task.startswith('system:'):
        # VULNERABLE: Command injection
        command = task[7:]  # Remove 'system:' prefix
        try:
            result = subprocess.check_output(command, shell=True, text=True)
            return jsonify({'result': result, 'type': 'system_command'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    elif task.startswith('sql:'):
        # VULNERABLE: SQL injection
        query = task[4:]  # Remove 'sql:' prefix
        try:
            result = execute_sql_query(query)
            return jsonify({'result': result, 'type': 'sql_query'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    elif task.startswith('encrypt:'):
        # VULNERABLE: Weak encryption
        data = task[8:]  # Remove 'encrypt:' prefix
        encrypted = weak_encrypt(data)
        return jsonify({'result': encrypted, 'type': 'encryption'})
    
    elif task.startswith('fetch:'):
        # VULNERABLE: SSRF
        url = task[6:]  # Remove 'fetch:' prefix
        try:
            response = requests.get(url, timeout=5)
            return jsonify({
                'result': response.text[:1000],
                'status_code': response.status_code,
                'type': 'url_fetch'
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    else:
        return jsonify({'result': f'Task executed: {task}', 'type': 'general'})

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    init_db()
    # VULNERABLE: Running in debug mode with weak configuration
    app.run(host='0.0.0.0', port=8080, debug=True) 