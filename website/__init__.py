# all imports
import base64
import os
from flask import Flask, jsonify, render_template, redirect, url_for, request, session, send_file, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from . import forms
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
# from flask_hashing import Hashing
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
from authlib.integrations.flask_client import OAuth

db = SQLAlchemy()  # create sql object
login_manager = LoginManager()  # flask login object
'''all variable for image share on chat area '''
ALLOWED_EXTENSIONS = ['pdf', 'gif', 'png', 'jpg', 'jpeg']
FILE_PATH = os.path.dirname(__file__)
IMAGE_FILE_PATH = os.path.join(FILE_PATH, 'static\display_image')
UPLOAD_FOLDER = IMAGE_FILE_PATH
MAX_BUFFER_SIZE = 50 * 1000 * 1000  # 50 MB for flask data share
FILENAME=None

class User(UserMixin, db.Model):
    '''creating user database'''
    __tablename__ = 'users'  # define table name in database
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(), nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username
class Google_Users(UserMixin, db.Model):
    '''creating user database'''
    __tablename__ = 'google_users'  # define table name in database
    id= db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_url= db.Column(db.String())

    def __repr__(self):
        return '<User %r>' % self.username


def allowed_file(filename):
    '''check file extantion for image'''
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def create_app():
    '''creating main flask app here'''
    app = Flask(__name__)
    app.secret_key = '190c28f9af971afc0efbb9a283affe260ed4bb39ba104a981a0a1af731be9e56'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:Rathore1_@localhost/abhicodekrega'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

    '''initialising'''
    # hashing = Hashing(app)
    login_manager.init_app(app)
    bcrypt = Bcrypt(app)
    db.init_app(app)
    socketio = SocketIO(app, max_http_buffer_size=MAX_BUFFER_SIZE)
    oauth = OAuth(app)

  
    @login_manager.user_loader  # load current user from login
    def user_loader(user_id):
        '''pre defind funciton for flask-login'''
        return User.query.get(user_id)  # get user id form database as user_id using "Usermixin" inheritance in class "User"
        
   
        
    '''creating endpoints'''
    @app.route("/", methods=['GET', 'POST'])
    def Home():
        user = current_user  # get current user using flask login
        try:
            if user.id:  # use user_loader function to get user id  of flask-login
                return render_template('index.html', user=user.username)
                    

        except:
            return render_template('index.html', user=False)

    @ app.route('/login/google/')
    def google():
        '''take doveloper info to use googel sign in  using google cloud search'''

        GOOGLE_CLIENT_ID = '945381964984-4h8bch1lge90p47rompluehqflrij194.apps.googleusercontent.com'
        GOOGLE_CLIENT_SECRET = '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'

        CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'
        oauth.register(
            name='google',
            client_id=GOOGLE_CLIENT_ID,
            client_secret=GOOGLE_CLIENT_SECRET,
            server_metadata_url=CONF_URL,
            client_kwargs={
                'scope': 'openid email profile'
            }
        )

        # Redirect to google_auth function
        redirect_uri = url_for('google_auth', _external=True)
        # print(redirect_uri)
        return oauth.google.authorize_redirect(redirect_uri)
    
    @ app.route('/login/google/auth/', methods=['GET', 'POST'])
    def google_auth():
        '''give user's needed information on this endpoint called callback'''
        token = oauth.google.authorize_access_token()
        google_user = oauth.google.parse_id_token(token, nonce=None)
        user = User(username=google_user['name'],
                    email=google_user['email'], password='None')
        
        if User.query.filter_by(email=google_user['email']).first():
            # login_user(user, remember=True)
            # return redirect('/')
            user = User.query.filter_by(email=google_user['email']).first()
        else:    
            db.session.add(user)
            db.session.commit()
        login_user(user, remember=True)
        return redirect('/')


    @app.route('/register/', methods=['GET', 'POST'], strict_slashes=False)
    def register():
        '''endpoint for registration '''
        error = False
        e_error = None  # stands for email error
        u_error = None  # stands for user error
        form = forms.register_form()  # another class from forms.py
        if request.method == 'POST':
            if form.validate_on_submit():  # flask-wtf things for  user validation
                if User.query.filter_by(email=form.email.data).first():
                    error = True
                    e_error = "Email already registered!"
                if User.query.filter_by(username=form.username.data).first():
                    error = True
                    u_error = "username already taken!"

                else:
                    pwd = bcrypt.generate_password_hash(
                        form.password.data)  # bcrypt is good for hashing
                    # pwd=hashing.hash_value(form.password.data, salt='abcd')
                    user = User(username=form.username.data,
                                email=form.email.data, password=pwd)
                    db.session.add(user)
                    db.session.commit()
                    # login user as current user ..from flask-login
                    login_user(user, remember=True)

                    return redirect(url_for('Home'))

        return render_template('form.html', form=form, error=error, e_error=e_error, u_error=u_error)

    @app.route('/login/', methods=['GET', 'POST'], strict_slashes=False)
    def login():
        '''endpoint for login'''

        login_error = False
        v_error = None  # stands for validation error

        form = forms.login_form()  # class from forms.py
        if request.method == 'POST':
            if form.validate_on_submit():  # from flask-wtforms
                user = User.query.filter_by(email=form.email.data).first()
                if user:
                    login_error = True
                    v_error = "Email or Password incorrect!"  # overwriting v_error

                    # if hashing.check_value(user.password,form.password.data, salt='abcd'):
                    # bcrypt use different hashes for same password
                    if bcrypt.check_password_hash(user.password, form.password.data):
                        login_user(user, remember=True)

                        return redirect(url_for('Home'))
                    return render_template('form.html', form=form, login_error=login_error, v_error=v_error)
                else:
                    login_error = True  # true if user not registered
                    v_error = "Email or Password incorrect!"  # overwriting v_error

        return render_template('form.html', form=form, login_error=login_error, v_error=v_error)

    @app.route("/logout", methods=["GET", "POST"])
    @login_required
    def logout():
        """Logout the current user."""
        user = current_user
        logout_user()  # flask-login thing
        # session.pop('user',None)
        return render_template("index.html")

    @app.route('/downloads', methods=["GET", "POST"])
    @login_required
    def downloads():
        '''downlaad the image file '''
        if FILENAME!=None:       
            PATH = os.path.join(IMAGE_FILE_PATH, FILENAME)
            return send_file(PATH, as_attachment=True)
        
        return redirect(url_for('online'))
        
        

    @app.route('/online', methods=["GET", "POST"])
    @login_required
    def online():
        global FILENAME
        '''endpoint for chating'''
        user = current_user  # flask-login
        # username=user.username.encode('utf-8')
        # username= base64.b64encode(username)

        if request.method == 'POST':  # whole POST request for image file from client/user

            if 'file' not in request.files:
                return "no file part in upload"
            file = request.files['file']
            if file.filename == '':
                return "please select a file"
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                FILENAME = filename
            
                emit('image_reciever', [user.username, filename],
                     namespace='/', broadcast=True)
            else:
                return "please check file again!"


        # event for take message and broadcast to all clients
        @socketio.on('message')
        def handle_message(message):
            # print('username',username)
            emit('reciever', [user.username, message],
                 broadcast=True, include_self=False)
            # print(user.username+" : "+str(message))

        # broadcast the diconnect msg to all clients
        @socketio.on('disconnect')
        def disconnect():
            emit('new_user', [f'{user.username} disconnected', 'red'],
                 broadcast=True, include_self=False)  # include_self=False means except me

        # broadcast the user connect msg to all clients
        @socketio.on('connect_user')
        def connect(msg):
            emit('new_user', [f'{user.username} connected',
                 'green'], broadcast=True, include_self=True)
            # print(f'{user.username } connected')

        @socketio.on('encr')  # encrypt the user messeges
        def encr(msg):
            data = base64.b64decode(msg)  # using base64 for decode
            print(data.decode('utf-8'))

        @socketio.on_error_default
        def default_error_handler(e):  # handle all socket errors
            print(request.event['message'])
            print(request.event['args'])
            print(e)

        # online.html for all chating interface
        return render_template('online.html', user=user.username)

    @login_manager.unauthorized_handler
    def unauthorized_handler():  # if user is not authorised than come to this
        return 'Unauthorized', 401  # rather i can use a templete other than "Unauthorized"

    return app, socketio  # return flask "app" and "socketio"
