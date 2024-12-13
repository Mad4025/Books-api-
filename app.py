from flask import render_template, redirect, url_for, flash, request, session, g, Flask, jsonify
from flask_login import login_user, login_required, logout_user, current_user, LoginManager, UserMixin
import requests
from authlib.integrations.flask_client import OAuth
import os
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
import random
import logging
from collections import Counter

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')
db_path = os.getenv('SQLACHEMY_DATABASE_URI')
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
    # Client_id and client_secret is individual and only found on console.cloud.google.com in your project under credentials
    client_id=os.getenv('CLIENT_ID'),
    client_secret=os.getenv('CLIENT_SECRET'),
    # Make sure you have enabled these scopes in OAuth consent screen.
    client_kwargs={'scope': 'openid profile email https://www.googleapis.com/auth/books'},  # Use all of the scopes you added in console.cloud.google.com
    # Connect to server.
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',  # Important for OIDC
)

@app.route('/', methods=['GET', 'POST'])
def index():
    amount_of_books = 12
    user_admin = session.get('user_admin', False)
    profile_pic = session.get('profile_pic')
    name = session.get('name')

    books = []
    user_library_books = set()
    top_categories = []

    # Step 1: Retrieve User's Library and Extract Top Categories
    if current_user.is_authenticated and 'user' in session:
        try:
            access_token = session['user']['access_token']
            headers = {'Authorization': f'Bearer {access_token}'}
            bookshelves_url = 'https://www.googleapis.com/books/v1/mylibrary/bookshelves'
            library_response = requests.get(bookshelves_url, headers=headers)

            if library_response.ok:
                bookshelves = library_response.json().get('items', [])
                logger.info(f"Bookshelves retrieved: {len(bookshelves)}")

                categories = []

                # Iterate through each bookshelf to collect categories
                for shelf in bookshelves:
                    shelf_id = shelf.get('id')
                    volumes_url = f'https://www.googleapis.com/books/v1/mylibrary/bookshelves/{shelf_id}/volumes'
                    volumes_response = requests.get(volumes_url, headers=headers)

                    if volumes_response.ok:
                        library_books = volumes_response.json().get('items', [])
                        logger.info(f"Books retrieved from shelf {shelf_id}: {len(library_books)}")

                        for book in library_books:
                            book_id = book.get('id')
                            if book_id:
                                user_library_books.add(book_id)

                            # Collect categories from each book
                            volume_info = book.get('volumeInfo', {})
                            book_categories = volume_info.get('categories', [])
                            if isinstance(book_categories, list):
                                categories.extend(book_categories)
                            elif isinstance(book_categories, str):
                                categories.append(book_categories)
                    else:
                        logger.warning(f"Failed to retrieve bookshelves for shelf ID {shelf_id}: {volumes_response.status_code}")

                # Determine the top 3 categories
                category_counts = Counter(categories)
                sanitized_categories = [cat.replace('&', 'and') for cat in category_counts.keys()]

                split_categories = []
                for cat in sanitized_categories:
                    if 'and' in cat:
                        split_categories.extend([part.strip() for part in cat.split('and')])
                    else:
                        split_categories.append(cat)

                # Standardize category terms by replacing spaces with hyphens and capitalizing
                standardized_categories = [cat.replace(' ', '-').title() for cat in split_categories[:3]]
                logger.info(f"Standardized Categories for Recommendation: {standardized_categories}")

                top_categories = standardized_categories
            elif library_response.status_code == 401:
                flash('Session expired. Please log in again.')
                return redirect(url_for('login_google'))
            else:
                logger.error(f"Error fetching bookshelves: {library_response.status_code}")
        except Exception as e:
            logger.error(f"Exception while fetching user library: {e}")

        # Step 2: Fetch Recommended Books Based on Top Categories
        if top_categories:
            logger.info(f"Top Categories: {top_categories}")
            api_key = os.getenv('GOOGLE_BOOKS_API_KEY')  # Ensure this is set in your .env

            if not api_key:
                logger.error("GOOGLE_BOOKS_API_KEY not found in environment variables.")
                flash("Internal error: API key not configured.")
                return render_template('index.html', books=books, user_admin=user_admin, profile_pic=profile_pic, name=name)

            # Initialize a set to keep track of unique book IDs to avoid duplicates
            unique_book_ids = set()

            # Iterate through each top category and fetch books
            for category in top_categories:
                query = f"subject:{category}"
                params = {
                    'q': query,
                    'maxResults': amount_of_books,  # Fetch up to 12 books per category
                    'key': api_key
                }
                response = requests.get('https://www.googleapis.com/books/v1/volumes', params=params)

                logger.info(f"Request URL: {response.url}")

                if response.ok:
                    response_data = response.json()
                    total_items = response_data.get('totalItems', 0)
                    logger.info(f"API Response for {query}: Total Items - {total_items}")

                    if total_items > 0:
                        items = response_data.get('items', [])
                        for book in items:
                            book_id = book.get('id')
                            if book_id and book_id not in unique_book_ids:
                                book['in_library'] = book_id in user_library_books
                                books.append(book)
                                unique_book_ids.add(book_id)

                                # Stop if we've collected 20 books
                                if len(books) >= amount_of_books:
                                    break
                    else:
                        logger.warning(f"No books found for category: {category}")
                else:
                    logger.error(f"Failed to fetch books for category {category}: {response.status_code}")
                    logger.error(f"Response Content: {response.text}")

                if len(books) >= amount_of_books:
                    break

        # Step 3: Fallback Mechanism if No Books Found from Categories
        if not books:
            fallback_query = 'technology'
            params = {
                'q': fallback_query,
                'maxResults': amount_of_books,
                'key': os.getenv('GOOGLE_BOOKS_API_KEY')
            }
            fallback_response = requests.get('https://www.googleapis.com/books/v1/volumes', params=params)

            logger.info(f"Fallback Request URL: {fallback_response.url}")

            if fallback_response.ok:
                fallback_data = fallback_response.json()
                fallback_total = fallback_data.get('totalItems', 0)
                logger.info(f"Fallback API Response: Total Items - {fallback_total}")

                if fallback_total > 0:
                    fallback_books = fallback_data.get('items', [])[:amount_of_books]
                    for book in fallback_books:
                        book_id = book.get('id')
                        if book_id and book_id not in unique_book_ids:
                            book['in_library'] = book_id in user_library_books
                            books.append(book)
                            unique_book_ids.add(book_id)

                    logger.info(f"Fallback books retrieved: {len(fallback_books)}")
                else:
                    logger.warning("No books found in fallback query.")
            else:
                logger.error(f"Failed to fetch books for fallback query: {fallback_response.status_code}")
                logger.error(f"Fallback Response Content: {fallback_response.text}")

    return render_template('index.html', books=books, user_admin=user_admin, profile_pic=profile_pic, name=name)

# Takes you to google's login thing.
@app.route('/login/google')
def login_google():
    try:
        return oauth.myApp.authorize_redirect(redirect_uri="https://brightread.it4.iktim.no/auth/google/callback")
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
    app.run(host="10.4.0.81", port=5001, debug=True)