import eventlet
eventlet.monkey_patch()
import os
from flask import *
from flask_socketio import SocketIO, emit, join_room
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'
DATABASE = 'users.db'
socketio = SocketIO(app, async_mode='eventlet')

# --- Database Setup ---
def initialize_database():
    with sqlite3.connect(DATABASE) as db:
        cursor = db.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, password TEXT)")
        cursor.execute("CREATE TABLE IF NOT EXISTS groups (id INTEGER PRIMARY KEY, name TEXT, creator_id INTEGER)")
        cursor.execute("CREATE TABLE IF NOT EXISTS group_members (group_id INTEGER, user_id INTEGER)")
        cursor.execute("CREATE TABLE IF NOT EXISTS messages (group_id INTEGER, user_name TEXT, message TEXT)")
        db.commit()

# --- Home ---
@app.route('/')
def home():
    return render_template('home.html')

# --- Register ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        with sqlite3.connect(DATABASE) as db:
            cursor = db.cursor()
            cursor.execute("SELECT * FROM users WHERE email=?", (email,))
            if cursor.fetchone():
                return "User already registered"
            cursor.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", (name, email, password))
        return redirect('/login')
    return render_template('register.html')

# --- Login ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        with sqlite3.connect(DATABASE) as db:
            cursor = db.cursor()
            cursor.execute("SELECT id, password FROM users WHERE email=? AND name=?", (email, name))
            user = cursor.fetchone()

            if user and check_password_hash(user[1], password):
                session['user_id'] = user[0]
                session['user_name'] = name
                session['email'] = email
                return redirect('/dashboard')
            else:
                return "Invalid login"
    return render_template('login.html')

# --- Dashboard ---
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    with sqlite3.connect(DATABASE) as db:
        cursor = db.cursor()
        cursor.execute("""SELECT groups.id, groups.name FROM groups
                          JOIN group_members ON groups.id = group_members.group_id
                          WHERE group_members.user_id = ?""", (user_id,))
        groups = cursor.fetchall()
    return render_template('dashboard.html', groups=groups)

# --- Create Group ---
@app.route('/create_group', methods=['GET', 'POST'])
def create_group():
    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':
        group_name = request.form['group_name']
        creator_id = session['user_id']
        with sqlite3.connect(DATABASE) as db:
            cursor = db.cursor()
            cursor.execute("INSERT INTO groups (name, creator_id) VALUES (?, ?)", (group_name, creator_id))
            group_id = cursor.lastrowid
            cursor.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (group_id, creator_id))
        return redirect('/dashboard')

    return render_template('create_group.html')

# --- Group Chat Page ---
@app.route('/group/<int:group_id>', methods=['GET'])
def group_chat(group_id):
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    user_name = session['user_name']
    with sqlite3.connect(DATABASE) as db:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM group_members WHERE group_id=? AND user_id=?", (group_id, user_id))
        if not cursor.fetchone():
            return redirect('/dashboard')

        cursor.execute("SELECT name, creator_id FROM groups WHERE id=?", (group_id,))
        group = cursor.fetchone()
        group_name, creator_id = group[0], group[1]
        is_admin = user_id == creator_id

        cursor.execute("SELECT * FROM messages WHERE group_id=?", (group_id,))
        messages = cursor.fetchall()

    return render_template("chat.html", group_id=group_id, group_name=group_name, messages=messages,
                           username=user_name, is_admin=is_admin)

# --- Add Member ---
@app.route('/add_member/<int:group_id>', methods=['POST'])
def add_member(group_id):
    if 'user_id' not in session:
        return redirect('/login')
    user_id = session['user_id']
    member_email = request.form['member_email']

    with sqlite3.connect(DATABASE) as db:
        cursor = db.cursor()
        cursor.execute("SELECT creator_id FROM groups WHERE id=?", (group_id,))
        creator_id = cursor.fetchone()[0]
        if user_id != creator_id:
            message = "Only the group creator can add members"
        else:
            cursor.execute("SELECT id FROM users WHERE email=?", (member_email,))
            user = cursor.fetchone()
            if not user:
                message = "User is not registered"
            else:
                new_user_id = user[0]
                cursor.execute("SELECT * FROM group_members WHERE group_id=? AND user_id=?", (group_id, new_user_id))
                if cursor.fetchone():
                    message = "User already in group"
                else:
                    cursor.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (group_id, new_user_id))
                    message = "Added successfully"

        cursor.execute("SELECT name FROM groups WHERE id=?", (group_id,))
        group_name = cursor.fetchone()[0]
        cursor.execute("SELECT * FROM messages WHERE group_id=?", (group_id,))
        messages = cursor.fetchall()

    return render_template("chat.html", group_id=group_id, group_name=group_name, messages=messages,
                           message=message, is_admin=True, username=session['user_name'])

# --- Remove Member ---
@app.route('/remove_member/<int:group_id>', methods=['POST'])
def remove_member(group_id):
    if 'user_id' not in session:
        return redirect('/login')
    user_id = session['user_id']
    member_email = request.form['member_email']

    with sqlite3.connect(DATABASE) as db:
        cursor = db.cursor()
        cursor.execute("SELECT creator_id FROM groups WHERE id=?", (group_id,))
        creator_id = cursor.fetchone()[0]
        if user_id != creator_id:
            message = "Only the group creator can remove members"
        else:
            cursor.execute("SELECT id FROM users WHERE email=?", (member_email,))
            user = cursor.fetchone()
            if not user:
                message = "User not registered"
            else:
                remove_id = user[0]
                cursor.execute("SELECT * FROM group_members WHERE group_id=? AND user_id=?", (group_id, remove_id))
                if not cursor.fetchone():
                    message = "User not in group"
                else:
                    cursor.execute("DELETE FROM group_members WHERE group_id=? AND user_id=?", (group_id, remove_id))
                    message = "Removed successfully"

        cursor.execute("SELECT name FROM groups WHERE id=?", (group_id,))
        group_name = cursor.fetchone()[0]
        cursor.execute("SELECT * FROM messages WHERE group_id=?", (group_id,))
        messages = cursor.fetchall()

    return render_template("chat.html", group_id=group_id, group_name=group_name, messages=messages,
                           message=message, is_admin=True, username=session['user_name'])

# --- Exit Group ---
@app.route('/exit_group/<int:group_id>', methods=['POST'])
def exit_group(group_id):
    if 'user_id' not in session:
        return redirect('/login')
    user_id = session['user_id']
    with sqlite3.connect(DATABASE) as db:
        cursor = db.cursor()
        cursor.execute("SELECT creator_id FROM groups WHERE id=?", (group_id,))
        if user_id == cursor.fetchone()[0]:
            return render_template('home.html', message="Creator cannot exit their group")
        cursor.execute("DELETE FROM group_members WHERE group_id=? AND user_id=?", (group_id, user_id))
    return redirect('/dashboard')

# ================================
# 🔌 Real-time Message Handling
# ================================

@socketio.on("join")
def handle_join(data):
    join_room(str(data["group_id"]))

@socketio.on("send_message")
def handle_send(data):
    group_id = data["group_id"]
    username = data["username"]
    message = data["message"]

    with sqlite3.connect(DATABASE) as db:
        cursor = db.cursor()
        cursor.execute("INSERT INTO messages (group_id, user_name, message) VALUES (?, ?, ?)", (group_id, username, message))
        db.commit()

    emit("receive_message", data, to=str(group_id))

# --- Run App ---
if __name__ == '__main__':
    initialize_database()
    port = int(os.environ.get("PORT", 5000))
    initialize_database()
    socketio.run(app,debug=True, host="0.0.0.0", port=port)
