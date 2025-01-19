# added logging for user information and post metadata, 
# CSRF protection, OAuth implementation, 
# and media post capabilities

# pip install flask-oauthlib flask-wtf

from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user, login_fresh
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import logging
from logging.handlers import RotatingFileHandler
from flask_oauthlib.client import OAuth, OAuthException
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['WTF_CSRF_CHECK_DEFAULT'] = True  # Enable CSRF protection

# Configure logging
if not app.debug:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/flask_security.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Flask security application startup')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.session_protection = "strong"
csrf = CSRFProtect(app)
oauth = OAuth(app)

# Configuration for OAuth (e.g., Google)
google = oauth.remote_app(
    'google',
    consumer_key='your_client_id',
    consumer_secret='your_client_secret',
    request_token_params={
        'scope': 'email profile',
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/00001',
    authorize_url='https://accounts.google.com/o/oauth2/auth'
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    oauth_id = db.Column(db.String(120), unique=True, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class PostForm(FlaskForm):
    content = TextAreaField('Content', validators=[DataRequired()])
    media = FileField('Media', validators=[FileAllowed(['jpg', 'png', 'gif'], 'Images only!')])
    submit = SubmitField('Post')

# Custom decorator for rate limiting
def rate_limit(limit=5, per=60):
    def decorator(f):
        @wraps(f)
        def rate_limited(*args, **kwargs):
            user_ip = request.remote_addr
            if user_ip not in session:
                session[user_ip] = []
            now = time.time()
            session[user_ip] = [t for t in session[user_ip] if now - t < per]
            if len(session[user_ip]) >= limit:
                return "Too many requests", 429
            session[user_ip].append(now)
            return f(*args, **kwargs)
        return rate_limited
    return decorator

@app.route('/register', methods=['GET', 'POST'])
@rate_limit()
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        app.logger.info(f'User {user.username} registered with email {user.email}')
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
@rate_limit()
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            app.logger.info(f'User {user.username} logged in')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
@login_required
def logout():
    app.logger.info(f'User {current_user.username} logged out')
    logout_user()
    return redirect(url_for('index'))

@app.route('/')
@login_required
def index():
    return render_template('index.html', user=current_user)

@app.route('/oauth/google')
def oauth_google():
    callback = url_for('oauth_authorized', next=request.args.get('next') or request.referrer or None, _external=True)
    return google.authorize(callback=callback)

@app.route('/oauth/google/authorized')
def oauth_authorized():
    resp = google.authorized_response()
    if resp is None:
        return 'Access denied: reason={} error={}'.format(
            request.args['error_reason'],
            request.args['error_description']
        )
    if isinstance(resp, OAuthException):
        return 'Error: {}'.format(resp.message)

    session['google_token'] = (resp['access_token'], '')
    me = google.get('userinfo')
    
    user_email = me.data['email']
    user = User.query.filter_by(email=user_email).first()
    
    if user is None:
        user = User(email=user_email, username=me.data.get('name', ''), oauth_id=me.data['id'])
        db.session.add(user)
        db.session.commit()
    
    login_user(user)
    app.logger.info(f'User {user.username} logged in via Google OAuth')
    return redirect(url_for('index'))

@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')

@app.route('/create_post', methods=['GET', 'POST'])
@login_required
def create_post():
    form = PostForm()
    if form.validate_on_submit():
        if form.media.data:
            filename = form.media.data.filename
            # Save the file
            media_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            form.media.data.save(media_path)
            post = Post(content=form.content.data, author=current_user, media=filename)
        else:
            post = Post(content=form.content.data, author=current_user)
        
        db.session.add(post)
        db.session.commit()
        app.logger.info(f'Post created by {current_user.username} with content: {post.content[:50]}...')
        flash('Your post has been created!', 'success')
        return redirect(url_for('index'))
    return render_template('create_post.html', title='Create Post', form=form)

if __name__ == '__main__':
    db.create_all()
    app.run(debug=False, ssl_context='adhoc')

"""
Configure your upload folder securely.
Use HTTPS in production for OAuth and all communications.
Implement proper error handling and logging for production scenarios.
Enhance security by regularly updating dependencies and performing security audits.

"""


#######################
