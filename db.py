import sqlite3

DATABASE = 'users.db'

with sqlite3.connect(DATABASE) as db:
    cursor = db.cursor()

    # Count total users
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]
    print(f"Total users: {total_users}")

    # List user names and their selected languages
    cursor.execute("SELECT name, language FROM users")
    users = cursor.fetchall()

    print("\nUser list with languages:")
    for name, language in users:
        print(f" - {name}: {language}")
