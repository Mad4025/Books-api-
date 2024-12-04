from flask import render_template, redirect, url_for, flash, request, session, g, Flask
from flask_login import login_user, login_required, logout_user, current_user, LoginManager, UserMixin
import requests
from authlib.integrations.flask_client import OAuth
import os
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')
db_path = os.getenv('SQLACHEMY_DATABASE_URI')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    role = db.Column(db.String(50), default='user')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) if user_id else None

@app.before_request
def set_global_user():
    g.current_user = current_user

# Set up Google's OAuth2
oauth = OAuth(app)
google = oauth.register("myApp",
    # Client_id and client_secret is individual and only found on console.cloud.google.com in your project in credentials
    client_id=os.getenv('CLIENT_ID'),
    client_secret=os.getenv('CLIENT_SECRET'),  # This is crucial for OIDC
    # Make sure you have enabled these scopes in OAuth consent screen.
    client_kwargs={'scope': 'openid profile email'},  # Use OIDC scope
    # Connect to server.
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',  # Important for OIDC
)





@app.route('/')
def index():
    user_admin = session.get('user_admin', False)
    profile_pic = session.get('profile_pic')
    return render_template('index.html', user_admin=user_admin, profile_pic=profile_pic)


@app.route('/search_books', methods=['GET', 'POST'])
def search_books():
    if request.method == 'POST':
        query = request.form.get('query')
        if query:
            url = 'https://www.googleapis.com/books/v1/volumes'
            params = {'q': query}
            response = requests.get(url, params=params)
            books = response.json().get('items', [])
            return render_template('pages/search_results.html', books=books)
    return render_template('pages/search_books.html')


# Takes you to google's login thing.
@app.route('/login/google')
def login_google():
    return oauth.myApp.authorize_redirect(redirect_uri=url_for('google_callback', _external=True))


# Where Google takes you after using their login thing.
@app.route('/auth/google/callback')
def google_callback():
    token = oauth.myApp.authorize_access_token()
    session['user'] = token

    # Login logic
    user_info = google.get('https://www.googleapis.com/oauth2/v3/userinfo').json()
    session['profile_pic'] = user_info['picture']  # Save profile picture URL
    user = User.query.filter_by(username=user_info['name']).first()

    # Add the emails that will have admin privileges.
    is_admin = user_info['email'] == os.getenv('EMAIL_HERE') # Replace with your admin email

    # To update user roles
    if not user:
        # user = filler data
        user = User(username=user_info['name'], role='user')
        db.session.add(user)
    else:
        if is_admin and user.role != 'admin':
            user.role = 'admin'
        elif not is_admin and user.role == 'admin':
            user.role = 'user'
    
    # Commit changes to the database
    db.session.commit()
    
    login_user(user)
    # Set admin permissions to True or False based on the previous logic
    session['user_admin'] = is_admin

    return redirect(url_for('index'))

# To log out the user.
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session['user_admin'] = False
    flash('You have been logged out.')
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host="localhost", port=5000, debug=True)