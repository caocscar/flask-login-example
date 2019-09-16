from flask import Flask, render_template, redirect, url_for
from flask_login import LoginManager, login_required, login_user, logout_user, UserMixin, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
import os

application = Flask(__name__)
application.secret_key = b'whatisacsrf#$^@&^@#!&^:{>}'
login_manager = LoginManager()
login_manager.init_app(application)
login_manager.login_view = '/login'
bcrypt = Bcrypt(application)

class User(UserMixin):

    def __init__(self, email, username, pw_raw, authenticated):
        self.email = email
        self.username = username
        self.password = bcrypt.generate_password_hash(pw_raw).decode('UTF-8')  # 'UTF-8' needed for Python 3.X
        self.authenticated = authenticated

    def get_id(self):
        return self.email

    def is_authenticated(self):
        return self.authenticated

    @staticmethod
    def authenticate(username, pw_raw):
        fetched_user = user1 #hardcoded user1
        if fetched_user:
            authenticated_user = bcrypt.check_password_hash(fetched_user.password, pw_raw)
            fetched_user.authenticated = True
        else:
            authenticated_user = False
        return fetched_user, authenticated_user

class LoginForm(FlaskForm):
    username = StringField('Username')
    password = PasswordField('Password')
    submit = SubmitField('Submit')

user1 = User('flask@login', os.getenv('User'), os.getenv('Pwd'), False)

@login_manager.user_loader
def load_user(user_id):
    user1.email = user_id
    return user1

@application.route('/', methods=['GET'])
@login_required
def hello():
    return render_template("hello.html")
    
# Route for handling the login page logic
@application.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    form = LoginForm()
    if form.validate_on_submit():
        fetched_user, authenticated_user = User.authenticate(form.username.data, form.password.data)
        if fetched_user and authenticated_user:
            login_user(fetched_user, remember=True)
            return fetched_user and redirect(url_for('hello'))
    return render_template('login.html', form=form, error=error)

@application.route("/logout")
@login_required
def logout():
    user = current_user
    user.authenticated = False
    logout_user()
    return redirect(url_for('login'))

@login_manager.unauthorized_handler
def unauthorized():
    form = LoginForm()
    return render_template('login.html', form=form)

#%% Run Flask app
# python application.py    
if __name__ == '__main__':
    application.run()