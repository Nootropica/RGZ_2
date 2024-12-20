from flask import Flask, render_template, request, redirect, url_for, session, flash, current_app
import sqlite3
from werkzeug.utils import secure_filename
import os
from werkzeug.security import generate_password_hash, check_password_hash
from math import ceil

app = Flask(__name__)

# Устанавливаем DB_TYPE в 'sqlite'
app.config['DB_TYPE'] = 'sqlite'

# Остальные настройки приложения
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'секретно-секретный секрет')

# Настройка загрузки файлов
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'RGZ_2', 'static', 'uploads')  # Абсолютный путь
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Проверка, является ли файл разрешенным
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Функция для подключения к базе данных
def db_connect():
    db_path = '/home/vladislavpechenkin/RGZ_2/database.db'
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row 
    cur = conn.cursor()
    return conn, cur

# Функция для закрытия соединения с базой данных
def db_close(conn, cur):
    conn.commit()
    cur.close()
    conn.close()

# Главная страница
@app.route('/')
def index():
    return render_template('index.html')

# Регистрация
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    email = request.form.get('email')
    password = request.form.get('password')
    name = request.form.get('name')
    age = request.form.get('age')
    gender = request.form.get('gender')
    seeking_gender = request.form.get('seeking_gender')
    about = request.form.get('about')

    # Обработка загрузки фотографии
    photo = request.files.get('photo')
    photo_path = None
    if photo and allowed_file(photo.filename):
        filename = secure_filename(photo.filename)
        photo_path = os.path.join('uploads', filename).replace('\\', '/')  # Исправлен путь
        photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    if not (email and password and name and age and gender and seeking_gender):
        return render_template('register.html', error='Заполните все обязательные поля')

    conn, cur = db_connect()

    # Проверка, существует ли пользователь с таким email
    cur.execute("SELECT * FROM users WHERE email=?;", (email,))
    existing_user = cur.fetchone()
    if existing_user:
        db_close(conn, cur)
        return render_template('register.html', error='Пользователь с таким email уже существует')

    # Хеширование пароля
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    # Добавление нового пользователя в базу данных
    cur.execute("""
        INSERT INTO users (email, password, name, age, gender, seeking_gender, about, photo)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?);
    """, (email, hashed_password, name, age, gender, seeking_gender, about, photo_path))

    db_close(conn, cur)
    flash('Регистрация прошла успешно', 'success')
    return redirect(url_for('index'))

# Авторизация
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        # Возвращаем простую HTML-страницу вместо login.html
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Вход</title>
        </head>
        <body>
            <h1>Вход</h1>
            <form method="POST">
                <label for="email">Email:</label>
                <input type="email" id="email" name="email" required><br><br>
                <label for="password">Пароль:</label>
                <input type="password" id="password" name="password" required><br><br>
                <button type="submit">Войти</button>
            </form>
        </body>
        </html>
        """

    email = request.form.get('email')
    password = request.form.get('password')

    if not (email and password):
        return "Заполните все поля", 400

    conn, cur = db_connect()

    # Поиск пользователя по email
    cur.execute("SELECT * FROM users WHERE email=?;", (email,))
    user = cur.fetchone()

    if not user or not check_password_hash(user['password'], password):
        db_close(conn, cur)
        return "Неверный email или пароль", 401

    db_close(conn, cur)
    session['user_id'] = user['id']
    flash('Вы успешно вошли в систему', 'success')
    return redirect(url_for('profile'))

# Выход
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Вы вышли из системы', 'success')
    return redirect(url_for('index'))

# Страница профиля
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    user_id = session.get('user_id')
    if not user_id:
        flash('Вы не авторизованы', 'error')
        return redirect(url_for('login'))

    conn, cur = db_connect()
    cur.execute("SELECT * FROM users WHERE id=?;", (user_id,))
    user = cur.fetchone()
    db_close(conn, cur)

    if request.method == 'POST':
        # Обработка редактирования анкеты
        name = request.form.get('name')
        age = request.form.get('age')
        gender = request.form.get('gender')
        seeking_gender = request.form.get('seeking_gender')
        about = request.form.get('about')
        photo = request.files.get('photo')

        # Обработка загрузки новой фотографии
        if photo and allowed_file(photo.filename):
            filename = secure_filename(photo.filename)
            photo_path = os.path.join('uploads', filename).replace('\\', '/')  # Исправлен путь
            photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            photo_path = user['photo']  # Если фото не загружено, оставляем старое

        conn, cur = db_connect()
        cur.execute("""
            UPDATE users SET name=?, age=?, gender=?, seeking_gender=?, about=?, photo=?
            WHERE id=?;
        """, (name, age, gender, seeking_gender, about, photo_path, user_id))
        db_close(conn, cur)
        flash('Анкета успешно обновлена', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)

# Скрытие анкеты
@app.route('/profile/hide', methods=['POST'])
def hide_profile():
    user_id = session.get('user_id')
    if not user_id:
        flash('Вы не авторизованы', 'error')
        return redirect(url_for('login'))

    conn, cur = db_connect()
    cur.execute("UPDATE users SET is_hidden=TRUE WHERE id=?;", (user_id,))
    db_close(conn, cur)
    flash('Ваша анкета скрыта', 'success')
    return redirect(url_for('profile'))

# Удаление аккаунта
@app.route('/profile/delete', methods=['POST'])
def delete_profile():
    user_id = session.get('user_id')
    if not user_id:
        flash('Вы не авторизованы', 'error')
        return redirect(url_for('login'))

    conn, cur = db_connect()
    cur.execute("DELETE FROM users WHERE id=?;", (user_id,))
    db_close(conn, cur)
    session.pop('user_id', None)
    flash('Ваш аккаунт удален', 'success')
    return redirect(url_for('index'))

# Поиск пользователей
# Поиск пользователей с постраничным выводом
@app.route('/search', methods=['GET', 'POST'])
def search():
    user_id = session.get('user_id')
    if not user_id:
        flash('Вы не авторизованы', 'error')
        return redirect(url_for('login'))

    conn, cur = db_connect()
    cur.execute("SELECT * FROM users WHERE id=?;", (user_id,))
    current_user = cur.fetchone()

    # Определение текущей страницы
    page = request.args.get('page', 1, type=int)
    per_page = 3  # Количество пользователей на странице

    if request.method == 'POST':
        name = request.form.get('name')
        age = request.form.get('age')

        # Фильтрация по имени и возрасту
        query = """
            SELECT * FROM users
            WHERE name LIKE ? AND age=? AND gender=? AND is_hidden=FALSE;
        """
        params = (f"%{name}%", age, current_user['seeking_gender'])
        cur.execute(query, params)
        users = cur.fetchall()

        # Подсчет общего количества страниц
        total_pages = ceil(len(users) / per_page)

        # Разбиение результатов на страницы
        start = (page - 1) * per_page
        end = start + per_page
        users_paginated = users[start:end]
    else:
        # По умолчанию показываем всех пользователей, соответствующих критериям поиска
        query = """
            SELECT * FROM users
            WHERE gender=? AND is_hidden=FALSE;
        """
        cur.execute(query, (current_user['seeking_gender'],))
        users = cur.fetchall()

        # Подсчет общего количества страниц
        total_pages = ceil(len(users) / per_page)

        # Разбиение результатов на страницы
        start = (page - 1) * per_page
        end = start + per_page
        users_paginated = users[start:end]

    db_close(conn, cur)
    return render_template('search.html', users=users_paginated, current_user=current_user, page=page, total_pages=total_pages)

if __name__ == '__main__':
    # Создание папки для загрузки файлов, если она не существует
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True)