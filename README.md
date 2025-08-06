# 🔓 Vulnerable Agentic Agent - Educational Platform

**⚠️ WARNING: This application is intentionally insecure for educational purposes. DO NOT use with real data or in production environments.**

## 📋 Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [Vulnerability Walkthrough](#vulnerability-walkthrough)
- [Security Learning](#security-learning)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [Safety Guidelines](#safety-guidelines)

## 🎯 Overview

This is an intentionally vulnerable agentic agent designed to demonstrate OWASP Top 10 security vulnerabilities. It serves as an educational platform for learning about web application security, penetration testing, and secure coding practices.

### 🎓 Learning Objectives

- **Understand Common Vulnerabilities**: Learn how vulnerabilities are introduced
- **Practice Exploitation**: Test various attack vectors in a safe environment
- **Learn Secure Coding**: See examples of secure alternatives
- **Develop Security Mindset**: Think like a security researcher

## 🚀 Quick Start

### Prerequisites

- Python 3.7+
- pip (Python package manager)
- Web browser
- Terminal/Command Prompt

### Installation

1. **Clone or Download the Project**
   ```bash
   # If you have git
   git clone https://github.com/not2cleverdotme/Agent_OWASP.git
   cd vulnerable-agentic-agent
   
   # Or download and extract the files
   ```

2. **Create Virtual Environment**
   ```bash
   python3 -m venv venv
   ```

3. **Activate Virtual Environment**
   ```bash
   # On macOS/Linux
   source venv/bin/activate
   
   # On Windows
   venv\Scripts\activate
   
   # On PowerShell
   venv\Scripts\Activate.ps1
   ```

4. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

5. **Run the Application**
   ```bash
   python app.py
   ```

6. **Access the Application**
   - Open your browser
   - Go to `http://localhost:8080`
   - You should see the vulnerable agent interface

## 🧪 Usage

### Web Interface

1. **Main Interface** (`http://localhost:8080`)
   - Navigate between tabs to test different vulnerabilities
   - Use the interactive forms to input payloads
   - View real-time results of your attacks

2. **Available Tabs**
   - **Agent Interface**: Test the main agent functionality
   - **Login**: Test weak authentication
   - **Vulnerability Tests**: Test specific attack vectors
   - **Debug Info**: View exposed sensitive information

### Command Line Testing

1. **Basic Functionality Test**
   ```bash
   python test_app.py
   ```

2. **Exploitation Demonstration**
   ```bash
   python exploit_demo.py
   ```

### Manual Testing Examples

1. **SQL Injection**
   ```bash
   curl "http://localhost:8080/api/user_data?user_id=1%20OR%201=1"
   ```

2. **Command Injection**
   ```bash
   curl -X POST http://localhost:8080/api/execute \
     -H "Content-Type: application/json" \
     -d '{"command": "whoami"}'
   ```

3. **SSRF**
   ```bash
   curl -X POST http://localhost:8080/api/fetch_url \
     -H "Content-Type: application/json" \
     -d '{"url": "http://localhost:8080/api/debug"}'
   ```

## 🔍 Vulnerability Walkthrough

### 1. SQL Injection (A03:2021)

**Objective**: Extract sensitive data from the database

**Steps**:
1. Go to the "Vulnerability Tests" tab
2. In the SQL Injection section, try these payloads:
   - `1 OR 1=1` - Get all data
   - `1 UNION SELECT * FROM users --` - Get user table
   - `1; DROP TABLE users; --` - Drop table (destructive)

**What to Learn**:
- How SQL injection works
- Why parameterized queries are important
- Impact of unauthorized data access

### 2. Command Injection (A03:2021)

**Objective**: Execute system commands

**Steps**:
1. Go to the "Vulnerability Tests" tab
2. In the Command Injection section, try these commands:
   - `whoami` - Check current user
   - `ls -la` - List files
   - `ls -la; cat /etc/passwd` - Multiple commands

**What to Learn**:
- How command injection works
- Importance of input validation
- Dangers of shell=True

### 3. SSRF (A10:2021)

**Objective**: Access internal services

**Steps**:
1. Go to the "Vulnerability Tests" tab
2. In the SSRF section, try these URLs:
   - `http://localhost:8080/api/debug` - Internal debug info
   - `http://127.0.0.1:22` - Port scanning
   - `file:///etc/passwd` - File reading

**What to Learn**:
- How SSRF works
- Importance of URL validation
- Internal service exposure risks

### 4. Weak Authentication (A07:2021)

**Objective**: Bypass authentication

**Steps**:
1. Go to the "Login" tab
2. Try these credentials:
   - Username: `admin`, Password: `admin123` (should work)
   - Username: `admin`, Password: `wrong` (should fail)

**What to Learn**:
- Weak password policies
- Importance of strong authentication
- Session management issues

### 5. Debug Information Exposure (A05:2021)

**Objective**: Access sensitive configuration

**Steps**:
1. Go to the "Debug Info" tab
2. Click "Get Debug Info"
3. Review the exposed information

**What to Learn**:
- Information disclosure risks
- Importance of secure configuration
- Debug mode dangers

### 6. Agent Task Execution

**Objective**: Exploit agent functionality

**Steps**:
1. Go to the "Agent Interface" tab
2. Try these tasks:
   - `system:whoami` - System command
   - `sql:SELECT * FROM users` - SQL query
   - `encrypt:secret_data` - Weak encryption
   - `fetch:http://localhost:8080/api/debug` - SSRF

**What to Learn**:
- Multiple attack vectors
- Input validation importance
- Secure task execution

## 🔧 Security Learning

### Understanding the Vulnerabilities

1. **SQL Injection**
   - **Problem**: Direct string concatenation in SQL queries
   - **Solution**: Use parameterized queries
   - **Impact**: Data theft, database manipulation

2. **Command Injection**
   - **Problem**: Unsafe command execution with shell=True
   - **Solution**: Use subprocess with shell=False
   - **Impact**: System compromise, data theft

3. **SSRF**
   - **Problem**: Unvalidated URL fetching
   - **Solution**: URL validation and allowlisting
   - **Impact**: Internal service access, data theft

4. **Weak Authentication**
   - **Problem**: Weak passwords, no rate limiting
   - **Solution**: Strong passwords, MFA, rate limiting
   - **Impact**: Unauthorized access

5. **Information Disclosure**
   - **Problem**: Exposed debug information
   - **Solution**: Secure configuration, disable debug mode
   - **Impact**: Information gathering for attacks

### Secure Coding Practices

1. **Input Validation**
   ```python
   # VULNERABLE
   user_input = request.args.get('user_id')
   query = f"SELECT * FROM users WHERE id = {user_input}"
   
   # SECURE
   user_input = request.args.get('user_id')
   if not user_input.isdigit():
       return "Invalid input", 400
   query = "SELECT * FROM users WHERE id = ?"
   cursor.execute(query, (user_input,))
   ```

2. **Authentication**
   ```python
   # VULNERABLE
   if password == "admin123":
   
   # SECURE
   if bcrypt.verify(password, hashed_password):
   ```

3. **Encryption**
   ```python
   # VULNERABLE
   def weak_encrypt(data):
       return base64.b64encode(data.encode()).decode()
   
   # SECURE
   from cryptography.fernet import Fernet
   def secure_encrypt(data):
       key = Fernet.generate_key()
       f = Fernet(key)
       return f.encrypt(data.encode())
   ```

## 📁 Project Structure

```
vulnerable-agentic-agent/
├── app.py                    # Main Flask application
├── requirements.txt          # Python dependencies
├── test_app.py              # Basic functionality tests
├── exploit_demo.py          # Exploitation demonstrations
├── README.md                # This file
├── VULNERABILITY_SUMMARY.md # Detailed vulnerability analysis
├── templates/               # HTML templates
│   ├── index.html          # Main interface
│   ├── login.html          # Login page
│   └── dashboard.html      # Dashboard
├── uploads/                # File upload directory (created automatically)
├── vulnerable_agent.db     # SQLite database (created automatically)
└── venv/                   # Virtual environment
```

## 🛠️ Troubleshooting

### Common Issues

1. **Port Already in Use**
   ```bash
   # Change port in app.py
   app.run(host='0.0.0.0', port=8081, debug=True)
   ```

2. **Module Not Found**
   ```bash
   # Make sure virtual environment is activated
   source venv/bin/activate  # or appropriate command for your OS
   pip install -r requirements.txt
   ```

3. **Permission Denied**
   ```bash
   # On macOS/Linux, you might need
   chmod +x app.py
   ```

4. **Database Errors**
   ```bash
   # Delete and recreate database
   rm vulnerable_agent.db
   python app.py
   ```

### Getting Help

1. **Check the logs** when running the application
2. **Verify all dependencies** are installed
3. **Ensure virtual environment** is activated
4. **Check port availability** (8080 by default)

## ⚠️ Safety Guidelines

### Important Reminders

1. **Educational Purpose Only**
   - This application is intentionally vulnerable
   - Use only for learning and testing
   - Never use with real data

2. **Isolated Environment**
   - Run in controlled, isolated environments
   - Don't connect to real services
   - Use only test data

3. **Responsible Usage**
   - Don't use for malicious purposes
   - Respect ethical boundaries
   - Learn to build secure applications

4. **Regular Updates**
   - Keep dependencies updated in real applications
   - Follow security best practices
   - Stay informed about new vulnerabilities

## 🤝 Contributing

This is an educational project. Contributions are welcome:

- **Add new vulnerability examples**
- **Improve educational content**
- **Enhance the user interface**
- **Add more secure alternatives**
- **Fix bugs or issues**

## 📚 Additional Resources

### OWASP Resources
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)

### Similar Projects
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
- [DVWA](http://www.dvwa.co.uk/)
- [WebGoat](https://owasp.org/www-project-webgoat/)

### Learning Resources
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackerOne](https://hackerone.com/)
- [Bugcrowd](https://www.bugcrowd.com/)

## 📄 License

This project is for educational purposes only. Use responsibly and ethically.

---

**Remember**: This application is intentionally vulnerable. Use it only for educational purposes in controlled environments. The knowledge gained should be used to build more secure applications. 