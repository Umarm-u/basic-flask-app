from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'weak_secret_key_123'  # Weak secret key

# Initialize database
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT
        )
    ''')
    
    # Create contacts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT,
            address TEXT,
            message TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # VULNERABILITY: SQL Injection - Using string concatenation
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('dashboard'))
        else:
            # VULNERABILITY: Information disclosure in error messages
            return render_template('login.html', error=f"Invalid credentials for user: {username}")
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']  # VULNERABILITY: Plain text password storage
        email = request.form['email']
        
        # VULNERABILITY: No input validation
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        try:
            # VULNERABILITY: SQL Injection possible here too
            query = f"INSERT INTO users (username, password, email) VALUES ('{username}', '{password}', '{email}')"
            cursor.execute(query)
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except Exception as e:
            # VULNERABILITY: Exposing database errors
            return render_template('register.html', error=str(e))
    
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    # VULNERABILITY: No session validation
    if 'username' not in session:
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', username=session['username'])

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        # VULNERABILITY: No CSRF protection
        # VULNERABILITY: No input validation or sanitization
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        address = request.form['address']
        message = request.form['message']
        
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # VULNERABILITY: SQL Injection with string formatting
        query = f"INSERT INTO contacts (name, email, phone, address, message) VALUES ('{name}', '{email}', '{phone}', '{address}', '{message}')"
        
        try:
            cursor.execute(query)
            conn.commit()
            conn.close()
            # VULNERABILITY: XSS - Reflecting user input without sanitization
            return render_template('contact.html', success=f"Thank you {name}! Your message has been received.")
        except Exception as e:
            # VULNERABILITY: Error information disclosure
            return render_template('contact.html', error=f"Database error: {str(e)}")
    
    return render_template('contact.html')

@app.route('/contacts')
def view_contacts():
    # VULNERABILITY: No authentication check
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM contacts")
    contacts = cursor.fetchall()
    conn.close()
    
    # VULNERABILITY: XSS - Displaying user input without escaping
    return render_template('contacts.html', contacts=contacts)

@app.route('/search')
def search():
    # VULNERABILITY: SQL Injection via query parameters
    search_term = request.args.get('q', '')
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM contacts WHERE name LIKE '%{search_term}%' OR email LIKE '%{search_term}%'"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    
    return render_template('search.html', results=results, search_term=search_term)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# VULNERABILITY: Debug mode enabled in production
# VULNERABILITY: No custom error handlers
if __name__ == '__main__':
    init_db()
    app.run(debug=True)  # Debug mode exposes sensitive information