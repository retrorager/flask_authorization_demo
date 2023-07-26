from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory, session, abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from wtforms import form
from is_safe_url import is_safe_url

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

app.config['UPLOAD_FOLDER'] = 'static/files'

app.secret_key = '600688c66e5fa8412fb7c0c17187c43e5ba03b4f2bf19613c66daab5c82f6ddd'
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

#Line below only required once, when creating DB.
# db.create_all()


@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user:
            flash('User Already Exists')
            return redirect(url_for('login'))
        else:
            new_user = User(
                email=request.form.get('email'),
                password=generate_password_hash(request.form.get('password'), method='pbkdf2:sha256', salt_length=8),
                name=request.form.get('name'),
            )
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('secrets', username=request.form.get('name')))
    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('User Not Found')
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Invalid Password')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('secrets', username=user.name))
    return render_template("login.html", logged_in=current_user.is_authenticated)


@app.route('/secrets/<username>')
@login_required
def secrets(username):
    if not current_user.is_authenticated:
        return app.login_manager.unauthorized()
    else:
        return render_template("secrets.html", username=username, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    pass


@app.route('/download')
def download():
    if not current_user.is_authenticated:
        return app.login_manager.unauthorized()
    else:
        return send_from_directory(app.config['UPLOAD_FOLDER'], 'cheat_sheet.pdf', as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
