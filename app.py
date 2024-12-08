from flask import render_template, redirect, url_for, flash, request, session, g, Flask, jsonify
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
    password = db.Column(db.String(150), nullable=False)
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
    client_kwargs={'scope': 'openid profile email https://www.googleapis.com/auth/books'},  # Use OIDC scope
    # Connect to server.
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',  # Important for OIDC
)


@app.route('/', methods=['GET', 'POST'])
def index():
    user_admin = session.get('user_admin', False)
    profile_pic = session.get('profile_pic')
    name = session.get('name')
    return render_template('index.html', user_admin=user_admin, profile_pic=profile_pic, name=name)


# Takes you to google's login thing.
@app.route('/login/google')
def login_google():
    try:
        return oauth.myApp.authorize_redirect(redirect_uri=url_for('google_callback', _external=True))
    except requests.exceptions.ConnectionError:
        return "It seems you like you are currently not connected to the internet. To log in, you need an internet connection."


# Where Google takes you after using their login thing.
@app.route('/auth/google/callback')
def google_callback():
    token = oauth.myApp.authorize_access_token()
    session['user'] = token

    # Login logic
    user_info = google.get('https://www.googleapis.com/oauth2/v3/userinfo').json()
    session['profile_pic'] = user_info['picture']  # Save profile picture URL
    session['name'] = user_info['name']
    user = User.query.filter_by(username=user_info['name']).first()

    # Add the emails that will have admin privileges.
    is_admin = user_info['email'] == os.getenv('EMAIL_HERE') # Replace with your admin email

    # To update user roles
    if not user:
        # user = filler data
        user = User(username=user_info['name'], password='oauth_dummy_password', role='user')
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
    
    access_token = token['access_token']
    headers = {'Authorization': f'Bearer {access_token}'}
    bookshelves_url = 'https://www.googleapis.com/books/v1/mylibrary/bookshelves'
    # Retrieve user's library using Google Books API
    bookshelves_response = requests.get(bookshelves_url, headers=headers).json()
    session['bookshelves'] = bookshelves_response.get('items', [])

    return redirect(url_for('library'))

# To log out the user.
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session['user_admin'] = False
    flash('You have been logged out.')
    return redirect(url_for('index'))


@app.route('/admin')
@login_required
def admin():
    user_count = db.session.query(User).count()

    return render_template('pages/admin.html', user_count=user_count, user_admin=session['user_admin'], profile_pic=session['profile_pic'], name=session['name'])


@app.route('/library')
def library():
    try:
        try:
            access_token = session['user']['access_token']
        except KeyError:
            return redirect(url_for('login_google'))
    
    
        headers = {'Authorization': f'Bearer {access_token}'}

        # Fetch the user's library again to ensure updates
        bookshelves_url = 'https://www.googleapis.com/books/v1/mylibrary/bookshelves'
        bookshelves_response = requests.get(bookshelves_url, headers=headers).json()
        bookshelves = bookshelves_response.get('items', [])

        # For each shelf, fetch its contents
        library = []
        if current_user.is_authenticated:
            for shelf in bookshelves:
                shelf_id = shelf['id']
                volumes_url = f'https://www.googleapis.com/books/v1/mylibrary/bookshelves/{shelf_id}/volumes'
                volumes_response = requests.get(volumes_url, headers=headers).json()
                shelf_contents = volumes_response.get('items', [])
                library.extend(shelf_contents)
        return render_template('pages/library.html', books=library, user_admin=session['user_admin'], profile_pic=session['profile_pic'], name=session['name'])
    except requests.exceptions.ConnectionError:
        return "It seems you like you are currently not connected to the internet. To access your library, you need an internet connection."
        


@app.route('/add_to_library', methods=['POST'])
def add_to_library():
    try:
        data = request.json  # Parse the JSON request body
        if not data:
            print("No data received in request.")
            return {"error": "No data provided"}, 400
        book_id = data.get('book_id')
        if not book_id:
            print("No book_id provided.")
            return {"error": "Book ID is required"}, 400
        print(f"Valid request. Book ID: {book_id}")

        url = f'https://www.googleapis.com/books/v1/mylibrary/bookshelves/0/addVolume?volumeId={book_id}'
        headers = {'Authorization': f'Bearer {session["user"]["access_token"]}'}
        response = requests.post(url, headers=headers)
        if response.status_code != 204:
            return {"error": "Failed to add book to library"}, response.status_code

        return {"message": "Book added successfully"}, 200
    except Exception as e:
        print(f"Error in add_to_library: {e}")
        return {"error": "Something went wrong"}, 500


@app.route('/remove_from_library', methods=['POST'])
def remove_from_library():
    data = request.get_json()
    book_id = data.get('book_id')
    user_token = session.get('user', {}).get('access_token')

    if not user_token:
        return jsonify({'requires_login': True}), 401

    try:
        url = f'https://www.googleapis.com/books/v1/mylibrary/bookshelves/0/removeVolume?volumeId={book_id}'
        headers = {'Authorization': f'Bearer {user_token}'}
        response = requests.post(url, headers=headers)

        if response.status_code == 204:
            return jsonify({'message': 'Book removed successfully!'}), 204
        else:
            return jsonify({'error': 'Failed to remove book from Google'}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query', '')
    books = []
    if query:
        url = 'https://www.googleapis.com/books/v1/volumes'
        params = {'q': query}
        response = requests.get(url, params=params)
        books = response.json().get('items', [])
        return render_template('pages/search_results.html', query=query, books=books, user_admin=session.get('user_admin', False), profile_pic=session.get('profile_pic'), name=session.get('name'))
    else:
        flash("Please enter a search query.", "warning")
        return redirect(url_for('index'))


@app.route('/about')
def about():
    return render_template('pages/about.html', user_admin=session.get('user_admin', False), profile_pic=session.get('profile_pic'), name=session.get('name'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host="localhost", port=5000, debug=True)