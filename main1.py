from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from flask_uploads import UploadSet, IMAGES, configure_uploads
import os
from flask_mail import Mail, Message

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOADED_PHOTOS_DEST'] = os.path.join('static', 'images')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_email_password'  # Use environment variables for security

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

photos = UploadSet('photos', IMAGES)
configure_uploads(app, photos)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    profile_image = db.Column(db.String(200), nullable=False, default='default.jpg')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    posts = db.relationship('Post', backref='group', lazy=True)
    members = db.relationship('GroupMembership', backref='group', lazy='dynamic')

class GroupMembership(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    can_post = db.Column(db.Boolean, default=True)  # Input restriction

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    media = db.Column(db.String(200))  # Path to media file
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = db.relationship('User', backref=db.backref('posts', lazy='dynamic'))

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    message = db.Column(db.String(200), nullable=False)
    is_read = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/create_group', methods=['POST'])
@login_required
def create_group():
    name = request.form.get('name')
    new_group = Group(name=name)
    db.session.add(new_group)
    db.session.commit()
    membership = GroupMembership(user_id=current_user.id, group_id=new_group.id, can_post=True)
    db.session.add(membership)
    db.session.commit()
    return redirect(url_for('group', group_id=new_group.id))

@app.route('/group/<int:group_id>')
@login_required
def group(group_id):
    group = Group.query.get_or_404(group_id)
    posts = Post.query.filter_by(group_id=group_id).all()
    can_post = GroupMembership.query.filter_by(user_id=current_user.id, group_id=group_id).first().can_post
    return render_template('group.html', group=group, posts=posts, can_post=can_post)

@app.route('/create_post', methods=['POST'])
@login_required
def create_post():
    group_id = request.form.get('group_id')
    content = request.form.get('content')
    media = request.files.get('media')
    membership = GroupMembership.query.filter_by(user_id=current_user.id, group_id=group_id).first()
    if not membership.can_post:
        flash('You do not have permission to post in this group.', 'danger')
        return redirect(url_for('group', group_id=group_id))

    post = Post(content=content, group_id=group_id, author_id=current_user.id)
    if media:
        filename = photos.save(media)
        post.media = filename
    db.session.add(post)
    db.session.commit()
    flash('Post created!', 'success')
    return redirect(url_for('group', group_id=group_id))

@app.route('/upload_image', methods=['POST'])
@login_required
def upload_image():
    if 'profile_image' not in request.files:
        flash('No file part')
        return redirect(url_for('profile'))
    file = request.files['profile_image']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('profile'))
    if file and photos.is_allowed(file.filename):
        filename = photos.save(file)
        current_user.profile_image = filename
        db.session.commit()
    return redirect(url_for('profile'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/send_notification', methods=['POST'])
@login_required
def send_notification():
    user_id = request.form.get('user_id')
    message = request.form.get('message')
    notification = Notification(user_id=user_id, message=message)
    db.session.add(notification)
    db.session.commit()
    # Send email notification
    user = User.query.get(user_id)
    if user:
        msg = Message('New Notification', recipients=[user.email])
        msg.body = message
        mail.send(msg)
    return jsonify({'status': 'success'})

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
