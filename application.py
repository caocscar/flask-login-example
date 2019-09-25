from flask import Flask, render_template, redirect, url_for, request
from flask_login import LoginManager, login_required, login_user, logout_user, UserMixin, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
import os

application = Flask(__name__)
application.config['SECRET_KEY'] = os.urandom(18)
login_manager = LoginManager()
login_manager.init_app(application)
login_manager.login_view = '/login'
bcrypt = Bcrypt(application)

class User(UserMixin):

    def __init__(self, email, username, pw_raw, is_authenticated):
        self.email = email
        self.username = username
        self.password = bcrypt.generate_password_hash(pw_raw).decode('utf-8')  # convert from binary
        self.is_authenticated = is_authenticated

    def get_id(self):
        return self.email

    @property
    def is_authenticated(self):
        print('getting value')
        return self._is_authenticated

    @is_authenticated.setter
    def is_authenticated(self, value):
        print('setting value')
        self._is_authenticated = value

    def authenticate(self, username, pw_raw):
        if self.username == username:
            tf = bcrypt.check_password_hash(self.password, pw_raw)
            print('pwd', tf)
        else:
            tf = False
            print('username is', tf)
        self.is_authenticated = tf

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
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

@application.route('/beautiful', methods=['GET'])
@login_required
def beauty():
    return render_template("beautiful.html")

# Route for handling the login page logic
@application.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('beauty'))
    form = LoginForm()
    if form.validate_on_submit():
        user1.authenticate(form.username.data, form.password.data)
        if user1 and user1.is_authenticated:
            login_user(user1, remember=True)
            return user1 and redirect(url_for('hello'))
    return render_template('login.html', form=form, error=None)

@application.route("/logout")
@login_required
def logout():
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