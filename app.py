from flask import Flask, render_template_string, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import re

app = Flask(__name__)

# Security Configurations
app.secret_key = 'your_super_secret_session_key_change_in_production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# --- DATABASE MODEL ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

# Create tables within context
with app.app_context():
    db.create_all()

# --- HTML TEMPLATES ---
BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{ title }} - Secure Login System</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f6f9; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .card { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); width: 350px; }
        h2 { margin-top: 0; color: #333; text-align: center; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="email"], input[type="password"] { width: 100%; padding: 10px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }
        button { width: 100%; padding: 10px; background: #007bff; border: none; color: white; font-weight: bold; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .alert { padding: 10px; margin-bottom: 15px; border-radius: 4px; color: white; font-size: 14px; text-align: center; }
        .alert-error { background: #dc3545; }
        .alert-success { background: #28a745; }
        p { text-align: center; font-size: 14px; }
        a { color: #007bff; text-decoration: none; }
    </style>
</head>
<body>
    <div class="card">
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <div class="alert alert-{{ category }}">{{ message }}</div>
            {% endfor %}
          {% endif %}
        {% endwith %}
        {% block content %}{% endblock %}
    </div>
</body>
</html>
"""

REGISTER_TEMPLATE = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', """
<h2>Register</h2>
<form action="/register" method="POST">
    <div class="form-group">
        <label>Username</label>
        <input type="text" name="username" required>
    </div>
    <div class="form-group">
        <label>Email</label>
        <input type="email" name="email" required>
    </div>
    <div class="form-group">
        <label>Password</label>
        <input type="password" name="password" required minlength="6">
    </div>
    <button type="submit">Register</button>
</form>
<p>Already have an account? <a href="/login">Login here</a></p>
""")

LOGIN_TEMPLATE = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', """
<h2>Login</h2>
<form action="/login" method="POST">
    <div class="form-group">
        <label>Username</label>
        <input type="text" name="username" required>
    </div>
    <div class="form-group">
        <label>Password</label>
        <input type="password" name="password" required>
    </div>
    <button type="submit">Login</button>
</form>
<p>Don't have an account? <a href="/register">Register here</a></p>
""")

DASHBOARD_TEMPLATE = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', """
<h2>Welcome, {{ username }}!</h2>
<p style="color: #28a745; font-weight: bold;">✔ You are securely logged in.</p>
<p>Session State: Active</p>
<a href="/logout"><button style="background: #dc3545;">Logout</button></a>
""")

# --- HELPER VALIDATION FUNCTION ---
def is_valid_email(email):
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(regex, email) is not None

# --- ROUTES & CONTROLLERS ---

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        # Basic Input Validation
        if not username or not email or not password:
            flash('All fields are required!', 'error')
            return render_template_string(REGISTER_TEMPLATE, title="Register")

        if not is_valid_email(email):
            flash('Invalid email format!', 'error')
            return render_template_string(REGISTER_TEMPLATE, title="Register")

        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template_string(REGISTER_TEMPLATE, title="Register")

        # Check existing user using ORM (SQL Injection safe)
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or Email already exists.', 'error')
            return render_template_string(REGISTER_TEMPLATE, title="Register")

        # Hash Password using Bcrypt
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

        new_user = User(username=username, email=email, password_hash=hashed_pw)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template_string(REGISTER_TEMPLATE, title="Register")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # Safe Query against SQL Injection
        user = User.query.filter_by(username=username).first()

        # Check Hash Password match
        if user and bcrypt.check_password_hash(user.password_hash, password):
            # Session Management
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login Successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid Username or Password.', 'error')

    return render_template_string(LOGIN_TEMPLATE, title="Login")

@app.route('/dashboard')
def dashboard():
    # Protected Route Session Check
    if 'user_id' not in session:
        flash('Please login to access the dashboard.', 'error')
        return redirect(url_for('login'))
    return render_template_string(DASHBOARD_TEMPLATE, title="Dashboard", username=session['username'])

@app.route('/logout')
def logout():
    session.clear() # Clear session
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)