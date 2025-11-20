from flask import Flask, render_template, request, redirect, url_for, session, abort
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, TextAreaField, EmailField
from wtforms.validators import DataRequired, Email, Length, Regexp, ValidationError
from flask_bcrypt import Bcrypt
import sqlite3
import os
import secrets
import re

app = Flask(__name__)

#Strong secret key
app.config['SECRET_KEY'] = secrets.token_hex(32)

# Secure session configuration
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookie over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes timeout

# Enable CSRF protection
csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)

# Custom validators for input validation
def validate_no_sql_keywords(form, field):
    """Prevent SQL injection attempts in input"""
    sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION', 
                    'CREATE', 'ALTER', 'EXEC', 'EXECUTE', '--', ';', '/*', '*/']
    for keyword in sql_keywords:
        if keyword.lower() in field.data.lower():
            raise ValidationError(f'Invalid input detected. Please remove special SQL keywords.')

def validate_no_html_tags(form, field):
    """Prevent XSS attempts by blocking HTML tags"""
    if re.search(r'<[^>]+>', field.data):
        raise ValidationError('HTML tags are not allowed.')

# Form classes with validation
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message='Username is required'),
        Length(min=3, max=50, message='Username must be between 3 and 50 characters'),
        Regexp('^[A-Za-z0-9_]+$', message='Username must contain only letters, numbers, and underscores'),
        validate_no_sql_keywords
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required'),
        Length(min=6, message='Password must be at least 6 characters')
    ])

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message='Username is required'),
        Length(min=3, max=50, message='Username must be between 3 and 50 characters'),
        Regexp('^[A-Za-z0-9_]+$', message='Username must contain only letters, numbers, and underscores'),
        validate_no_sql_keywords
    ])
    email = EmailField('Email', validators=[
        DataRequired(message='Email is required'),
        Email(message='Invalid email address'),
        validate_no_sql_keywords
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required'),
        Length(min=8, message='Password must be at least 8 characters'),
        Regexp('^(?=.*[A-Za-z])(?=.*\\d)[A-Za-z\\d@$!%*#?&]+$', 
               message='Password must contain at least one letter and one number')
    ])

class ContactForm(FlaskForm):
    name = StringField('Name', validators=[
        DataRequired(message='Name is required'),
        Length(min=2, max=100, message='Name must be between 2 and 100 characters'),
        Regexp('^[A-Za-z\\s]+$', message='Name must contain only letters and spaces'),
        validate_no_sql_keywords,
        validate_no_html_tags
    ])
    email = EmailField('Email', validators=[
        DataRequired(message='Email is required'),
        Email(message='Invalid email address'),
        validate_no_sql_keywords
    ])
    phone = StringField('Phone', validators=[
        Length(max=20, message='Phone number too long'),
        Regexp('^[0-9+\\-\\s()]*$', message='Invalid phone number format')
    ])
    address = StringField('Address', validators=[
        Length(max=200, message='Address too long'),
        validate_no_sql_keywords,
        validate_no_html_tags
    ])
    message = TextAreaField('Message', validators=[
        DataRequired(message='Message is required'),
        Length(min=10, max=1000, message='Message must be between 10 and 1000 characters'),
        validate_no_sql_keywords,
        validate_no_html_tags
    ])

# parameterized queries
def get_db_connection():
    conn = sqlite3.connect('database_secure.db')
    conn.row_factory = sqlite3.Row
    return conn

# Secure database initialization
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT,
            address TEXT,
            message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        # Parameterized query to prevent SQL injection
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        # Password verification with bcrypt
        if user and bcrypt.check_password_hash(user['password'], password):
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        else:
            # Generic error message (no information disclosure)
            form.password.errors.append('Invalid username or password')
    
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data
        
        # Hash password before storage
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Parameterized query
            cursor.execute(
                "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                (username, hashed_password, email)
            )
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.close()
            # Generic error without exposing database details
            form.username.errors.append('Username or email already exists')
    
    return render_template('register.html', form=form)

@app.route('/dashboard')
def dashboard():
    # Proper session validation
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', username=session.get('username'))

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm()
    
    # CSRF protection is automatically handled by FlaskForm
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        phone = form.phone.data
        address = form.address.data
        message = form.message.data
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Parameterized query
            cursor.execute(
                "INSERT INTO contacts (name, email, phone, address, message) VALUES (?, ?, ?, ?, ?)",
                (name, email, phone, address, message)
            )
            conn.commit()
            conn.close()
            return render_template('contact.html', form=ContactForm(), 
                                 success="Thank you! Your message has been received.")
        except Exception as e:
            conn.close()
            # Generic error message
            form.message.errors.append('An error occurred. Please try again later.')
    
    return render_template('contact.html', form=form)

@app.route('/contacts')
def view_contacts():
    # Authentication check
    if 'user_id' not in session:
        abort(401)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM contacts ORDER BY created_at DESC")
    contacts = cursor.fetchall()
    conn.close()
    
    # Data is automatically escaped by Jinja2 (removed |safe filter)
    return render_template('contacts.html', contacts=contacts)

@app.route('/search')
def search():
    # Authentication required
    if 'user_id' not in session:
        abort(401)
    
    search_term = request.args.get('q', '')
    
    # Input validation
    if len(search_term) > 100:
        abort(400)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Parameterized query with wildcards
    cursor.execute(
        "SELECT * FROM contacts WHERE name LIKE ? OR email LIKE ?",
        (f'%{search_term}%', f'%{search_term}%')
    )
    results = cursor.fetchall()
    conn.close()
    
    return render_template('search.html', results=results, search_term=search_term)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# Custom error handlers (no information disclosure)
@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', 
                          error_code=404, 
                          error_message="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', 
                          error_code=500, 
                          error_message="An internal error occurred. Please try again later."), 500

@app.errorhandler(401)
def unauthorized(error):
    return render_template('error.html', 
                          error_code=401, 
                          error_message="Unauthorized access. Please login."), 401

@app.errorhandler(400)
def bad_request(error):
    return render_template('error.html', 
                          error_code=400, 
                          error_message="Bad request"), 400

# Disable debug mode in production
if __name__ == '__main__':
    init_db()
    app.run(debug=False)