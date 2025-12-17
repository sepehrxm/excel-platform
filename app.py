from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import json
import os
from datetime import datetime
import openpyxl
import urllib.parse as urlparse

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'super_secret_key')  # Use env var in production

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database connection function
def get_db_connection():
    url = urlparse.urlparse(os.environ['DATABASE_URL'])
    conn = psycopg2.connect(
        database=url.path[1:],
        user=url.username,
        password=url.password,
        host=url.hostname,
        port=url.port
    )
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, email TEXT UNIQUE, password TEXT, is_admin INTEGER DEFAULT 0)''')
    c.execute('''CREATE TABLE IF NOT EXISTS sheet_data (id SERIAL PRIMARY KEY, data TEXT, readonly_columns TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS logs (id SERIAL PRIMARY KEY, user_email TEXT, action TEXT, timestamp TEXT)''')
    conn.commit()
    conn.close()

# User class (unchanged)
class User(UserMixin):
    def __init__(self, id, email, is_admin):
        self.id = id
        self.email = email
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    user = c.fetchone()
    conn.close()
    if user:
        return User(user[0], user[1], user[3])
    return None

# Routes (mostly unchanged, but with psycopg2)
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[2], password):
            user_obj = User(user[0], user[1], user[3])
            login_user(user_obj)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
#@login_required  # Temporarily comment this out to create first admin
def register():
    #if not current_user.is_admin:  # Temporarily comment this out
    #    flash('Only admins can register users')
    #    return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (email, password) VALUES (%s, %s)', (email, password))
            conn.commit()
            flash('User registered')
        except psycopg2.IntegrityError:
            flash('Email already exists')
        conn.close()
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT data, readonly_columns FROM sheet_data WHERE id = 1')
    sheet = c.fetchone()
    data = json.loads(sheet[0]) if sheet else []
    readonly_columns = sheet[1].split(',') if sheet and sheet[1] else []
    conn.close()

    if request.method == 'POST':
        if 'upload' in request.files:
            file = request.files['upload']
            if file.filename.endswith('.xlsx'):
                filepath = os.path.join('uploads', file.filename)  # Note: On Render, use /tmp or memory for temp files
                file.save(filepath)
                wb = openpyxl.load_workbook(filepath)
                ws = wb.active
                data = [[cell.value for cell in row] for row in ws.iter_rows()]
                conn = get_db_connection()
                c = conn.cursor()
                c.execute('INSERT INTO sheet_data (id, data) VALUES (1, %s) ON CONFLICT (id) DO UPDATE SET data = %s', (json.dumps(data), json.dumps(data)))
                conn.commit()
                conn.close()
                os.remove(filepath)  # Clean up
                flash('Excel uploaded')
            else:
                flash('Upload .xlsx files only')
        elif 'save_data' in request.form:
            new_data = json.loads(request.form['data'])
            conn = get_db_connection()
            c = conn.cursor()
            c.execute('SELECT data FROM sheet_data WHERE id=1')
            old_data_row = c.fetchone()
            old_data = json.loads(old_data_row[0]) if old_data_row else []
            changes = []
            for row_idx, row in enumerate(new_data):
                for col_idx, val in enumerate(row):
                    if val != old_data[row_idx][col_idx]:
                        changes.append(f'Cell [{row_idx},{col_idx}] changed from "{old_data[row_idx][col_idx]}" to "{val}"')
            if changes:
                log_entry = f'User {current_user.email} made changes: ' + '; '.join(changes)
                c.execute('INSERT INTO logs (user_email, action, timestamp) VALUES (%s, %s, %s)',
                          (current_user.email, log_entry, datetime.now().isoformat()))
            c.execute('UPDATE sheet_data SET data = %s WHERE id=1', (json.dumps(new_data),))
            conn.commit()
            conn.close()
            flash('Changes saved and logged')
        elif 'readonly_columns' in request.form and current_user.is_admin:
            readonly = request.form['readonly_columns']
            conn = get_db_connection()
            c = conn.cursor()
            c.execute('UPDATE sheet_data SET readonly_columns = %s WHERE id=1', (readonly,))
            conn.commit()
            conn.close()
            readonly_columns = readonly.split(',')
            flash('Read-only columns updated')

    return render_template('dashboard.html', data=json.dumps(data), readonly_columns=readonly_columns, is_admin=current_user.is_admin)

@app.route('/logs')
@login_required
def logs():
    if not current_user.is_admin:
        flash('Only admins can view logs')
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM logs ORDER BY timestamp DESC')
    logs = c.fetchall()
    conn.close()
    return render_template('logs.html', logs=logs)

if __name__ == '__main__':
    init_db()  # Init DB on start
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)