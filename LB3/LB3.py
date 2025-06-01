import sqlite3
import hashlib

def connect_db():
    conn = sqlite3.connect('users_second.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            login TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL
        )
    ''')
    conn.commit()
    return conn

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def add_user(conn, login, password, full_name):
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (login, password, full_name) VALUES (?, ?, ?)',
                       (login, hash_password(password), full_name))
        conn.commit()
        print(f"Користувача {login} додано успішно.")
    except sqlite3.IntegrityError:
        print("Помилка: користувач з таким логіном вже існує.")

def update_password(conn, login, new_password):
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET password = ? WHERE login = ?',
                   (hash_password(new_password), login))
    conn.commit()
    if cursor.rowcount:
        print("Пароль оновлено.")
    else:
        print("Користувач не знайдений.")

def authenticate_user(conn, login, password):
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM users WHERE login = ?', (login,))
    result = cursor.fetchone()
    if result:
        stored_password = result[0]
        if stored_password == hash_password(password):
            print("Автентифікація успішна.")
        else:
            print("Невірний пароль.")
    else:
        print("Користувач не знайдений.")

def main():
    conn = connect_db()
    while True:
        print("\nМеню:")
        print("1. Додати користувача")
        print("2. Оновити пароль")
        print("3. Перевірити автентифікацію")
        print("4. Вийти")
        choice = input("Ваш вибір: ")

        if choice == '1':
            login = input("Введіть логін: ")
            password = input("Введіть пароль: ")
            full_name = input("Введіть ПІБ: ")
            add_user(conn, login, password, full_name)
        elif choice == '2':
            login = input("Введіть логін: ")
            new_password = input("Введіть новий пароль: ")
            update_password(conn, login, new_password)
        elif choice == '3':
            login = input("Введіть логін: ")
            password = input("Введіть пароль: ")
            authenticate_user(conn, login, password)
        elif choice == '4':
            print("Вихід...")
            break
        else:
            print("Невірний вибір. Спробуйте ще раз.")

    conn.close()

if __name__ == "__main__":
    main()
