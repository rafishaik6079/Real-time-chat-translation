from flask import Flask, render_template, request, redirect, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'
DATABASE = 'users.db'

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
            existing_user = cursor.fetchone()
            if existing_user:
                return "User already registered with this email"
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
            user_data = cursor.fetchone()

            if user_data and check_password_hash(user_data[1], password):
                session['user_id'] = user_data[0]
                session['user_name'] = name
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
        cursor.execute("""
            SELECT groups.id, groups.name FROM groups
            JOIN group_members ON groups.id = group_members.group_id
            WHERE group_members.user_id = ?
        """, (user_id,))
        user_groups = cursor.fetchall()

    return render_template('dashboard.html', groups=user_groups)

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
            new_group_id = cursor.lastrowid
            cursor.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (new_group_id, creator_id))
        return redirect('/dashboard')

    return render_template('create_group.html')

# --- Group Chat ---
@app.route('/group/<int:group_id>', methods=['GET', 'POST'])
def group_chat(group_id):
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    user_name = session['user_name']

    with sqlite3.connect(DATABASE) as db:
        cursor = db.cursor()

        # Check if user is a member of the group
        cursor.execute("SELECT * FROM group_members WHERE group_id=? AND user_id=?", (group_id, user_id))
        membership = cursor.fetchone()

        if not membership:
            return redirect('/')

        # Handle message send
        if request.method == 'POST':
            message = request.form['message']
            cursor.execute("INSERT INTO messages (group_id, user_name, message) VALUES (?, ?, ?)", (group_id, user_name, message))

        cursor.execute("SELECT name FROM groups WHERE id=?", (group_id,))
        group_name = cursor.fetchone()[0]
        cursor.execute("SELECT * FROM messages WHERE group_id=?", (group_id,))
        messages = cursor.fetchall()

    return render_template("chat.html", group_id=group_id, group_name=group_name, messages=messages)

@app.route('/add_member/<int:group_id>', methods=['POST'])
def add_member(group_id):
    if 'user_id' not in session:
        return redirect('/login')
    
    logged_in_user_id = session['user_id']
    member_email = request.form['member_email']

    with sqlite3.connect(DATABASE) as db:
        cursor = db.cursor()

        # Check group creator
        cursor.execute("SELECT creator_id FROM groups WHERE id=?", (group_id,))
        creator_id = cursor.fetchone()[0]

        if logged_in_user_id != creator_id:
            message = "Only the group creator can add members"
        else:
            # Check if user exists
            cursor.execute("SELECT id FROM users WHERE email=?", (member_email,))
            user = cursor.fetchone()

            if not user:
                message = "User is not registered"
            else:
                user_id = user[0]
                # Check if already in group
                cursor.execute("SELECT * FROM group_members WHERE group_id=? AND user_id=?", (group_id, user_id))
                if cursor.fetchone():
                    message = "User already present in group"
                else:
                    cursor.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (group_id, user_id))
                    message = "Added successfully"

        # Load chat info again
        cursor.execute("SELECT name FROM groups WHERE id=?", (group_id,))
        group_name = cursor.fetchone()[0]
        cursor.execute("SELECT * FROM messages WHERE group_id=?", (group_id,))
        messages = cursor.fetchall()

    return render_template("chat.html", group_id=group_id, group_name=group_name, messages=messages, message=message)

# --- Remove Member ---
@app.route('/remove_member/<int:group_id>', methods=['POST'])
def remove_member(group_id):
    if 'user_id' not in session:
        return redirect('/login')

    logged_in_user_id = session['user_id']
    member_email = request.form['member_email']

    with sqlite3.connect(DATABASE) as db:
        cursor = db.cursor()

        # Check group creator
        cursor.execute("SELECT creator_id FROM groups WHERE id=?", (group_id,))
        creator_id = cursor.fetchone()[0]

        if logged_in_user_id != creator_id:
            message = "Only the group creator can remove members"
        else:
            # Check if user exists
            cursor.execute("SELECT id FROM users WHERE email=?", (member_email,))
            user = cursor.fetchone()

            if not user:
                message = "User is not registered"
            else:
                user_id = user[0]
                # Check if user is a member
                cursor.execute("SELECT * FROM group_members WHERE group_id=? AND user_id=?", (group_id, user_id))
                if not cursor.fetchone():
                    message = "User is not a member of this group"
                else:
                    cursor.execute("DELETE FROM group_members WHERE group_id=? AND user_id=?", (group_id, user_id))
                    message = "User removed successfully"

        # Load updated messages
        cursor.execute("SELECT name FROM groups WHERE id=?", (group_id,))
        group_name = cursor.fetchone()[0]
        cursor.execute("SELECT * FROM messages WHERE group_id=?", (group_id,))
        messages = cursor.fetchall()

    return render_template("chat.html", group_id=group_id, group_name=group_name, messages=messages, message=message)
@app.route('/exit_group/<int:group_id>', methods=['POST'])
def exit_group(group_id):
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']

    with sqlite3.connect(DATABASE) as db:
        cursor = db.cursor()

        # Get group creator
        cursor.execute("SELECT creator_id FROM groups WHERE id=?", (group_id,))
        creator_id = cursor.fetchone()[0]

        if user_id == creator_id:
            # Group creator can't exit — redirect to home with message
            return render_template('home.html', message="Group creator cannot exit their own group")

        # Remove member from group
        cursor.execute("DELETE FROM group_members WHERE group_id=? AND user_id=?", (group_id, user_id))

    return redirect('/dashboard')


# --- Run App ---
if __name__ == '__main__':
    initialize_database()
    app.run(debug=True)
