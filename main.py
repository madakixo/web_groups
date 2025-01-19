from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    posts = db.relationship('Post', backref='group', lazy=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/admin')
def admin_panel():
    # Only for admin
    return "Admin Panel"

@app.route('/create_group', methods=['POST'])
def create_group():
    name = request.form.get('name')
    new_group = Group(name=name)
    db.session.add(new_group)
    db.session.commit()
    return redirect(url_for('group', group_id=new_group.id))

@app.route('/group/<int:group_id>')
def group(group_id):
    group = Group.query.get_or_404(group_id)
    posts = Post.query.filter_by(group_id=group_id).all()
    return render_template('group.html', group=group, posts=posts)

@app.route('/create_post', methods=['POST'])
def create_post():
    group_id = request.form.get('group_id')
    content = request.form.get('content')
    post = Post(content=content, group_id=group_id)
    db.session.add(post)
    db.session.commit()
    return redirect(url_for('group', group_id=group_id))

@app.route('/settings')
def settings():
    return render_template('settings.html')

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)

"""
Database: This setup uses SQLite for simplicity, but for 19,999 groups and more interactions,
consider PostgreSQL or MySQL.
Security: The example includes basic password hashing but lacks comprehensive security measures. 
Authentication, authorization, and session management would need to be implemented for real-world use.
Profile Images: This skeleton does not handle file uploads for profile images. 
You would need to implement file handling and storage.
Scalability: For this scale of users and groups, consider using a microservices architecture 
or at least optimizing your SQL queries and indexes.


"""

###############3
