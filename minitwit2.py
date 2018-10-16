# -*- coding: utf-8 -*-
"""
    MiniTwit
    ~~~~~~~~
    A microblogging application written with Flask and sqlite3.
    :copyright: (c) 2015 by Armin Ronacher.
    :license: BSD, see LICENSE for more details.
"""

import time
import json
from sqlite3 import dbapi2 as sqlite3
from hashlib import md5
import unittest
from datetime import datetime
from flask import jsonify
from flask import Response
from flask.json import JSONEncoder
from flask import Flask, request, session, url_for, redirect, \
     render_template, abort, g, flash, _app_ctx_stack
from werkzeug import check_password_hash, generate_password_hash
from flask_sessionstore import Session
from flask_basicauth import BasicAuth
from flask import current_app,request,Response

# configuration
DATABASE = '/tmp/minitwit.db'
PER_PAGE = 30
DEBUG = True
SECRET_KEY = b'_5#y2L"F4Q8z\n\xec]/'
UserList = []

# create our little application :)
app = Flask('minitwit')
app.config.from_object(__name__)
app.config.from_envvar('MINITWIT_SETTINGS=/examples/minitwit/File_2.cfg', silent=True)
app.config['BASIC_AUTH_FORCE'] = True
#session
app = Flask(__name__)
SESSION_TYPE= 'filesystem'
app.config.from_object(__name__)
Session(app)

app = Flask(__name__)
app.config['BASIC_AUTH_USERNAME'] = 'PrabhBhullar06'
app.config['BASIC_AUTH_PASSWORD'] = 'avengers3456'
#api = Api(app,prefix="/api/v1")
basic_auth = BasicAuth(app)
app.config['BASIC_AUTH_FORCE'] = True

#BaicAuth
class BasicAuth(object):
    def __init__(self, app=None):
        if app is not None:
            self.app = app
            self.init_app(app)
        else:
            self.app = None

    def init_app(self, app):
        #Initialize this BasicAuth extension for the given application.
        #:param app: a :class:`~flask.Flask` instance
    
        app.config.setdefault('BASIC_AUTH_FORCE', False)
        app.config.setdefault('BASIC_AUTH_REALM', '')

@app.before_request
def require_basic_auth():
        if not current_app.config['BASIC_AUTH_FORCE']:
            return
        if not self.authenticate():
            return self.challenge()

def check_credentials(self, username, password):
    """
        Check if the given username and password are correct.
        By default compares the given username and password to
        ``BASIC_AUTH_USERNAME`` and ``BASIC_AUTH_PASSWORD``
        configuration variables.
        :param username: a username provided by the client
        :param password: a password provided by the client
        :returns: `True` if the username and password combination was correct,
        and `False` otherwise."""
    if g.user:
        return 'user successful'
        error = None
        
        if request.method == 'POST':
            user = query_db('''select * from user where
                username = ?''', [request.form['username']], one=True)
            if user is None:
                error = 'Invalid username'
            elif not check_password_hash(user['pw_hash'],
                                                        request.form['password']):
                                error = 'Invalid password'
            else:
                                        flash('You were logged in')
            session['user_id'] = user['user_id']
            return redirect(url_for('timeline'))
            return render_template('login.html', error=error)
        correct_username = current_app.config['BASIC_AUTH_USERNAME']
        correct_password = current_app.config['BASIC_AUTH_PASSWORD']
        return username == correct_username and password == correct_password

def authenticate(self):
    """
        Check the request for HTTP basic access authentication header and try
        to authenticate the user.
        :returns: `True` if the user is authorized, or `False` otherwise.
        """
    auth = request.authorization
    return (
                auth and auth.type == 'basic' and
                self.check_credentials(auth.username, auth.password)
                )

def challenge(self):
    """
        Challenge the client for username and password.
        This method is called when the client did not provide username and
        password in the request, or the username and password combination was
        wrong.
        :returns: a :class:`~flask.Response` with 401 response code, including
        the required authentication scheme and authentication realm.
        """
    realm = current_app.config['BASIC_AUTH_REALM']
    return Response(
                                status=401,
                                headers={'WWW-Authenticate': 'Basic realm="%s"' % realm}
                                )

def required(self, view_func):
    """
        A decorator that can be used to protect specific views with HTTP
        basic access authentication.
        """
    @wraps(view_func)
    def wrapper(*args, **kwargs):
            if self.authenticate():
                return view_func(*args, **kwargs)
            else:
                return self.challenge()
                return wrapper

# def check_credentials(self, username, password):
#correct_username = current_app.config['BASIC_AUTH_USERNAME']
#       correct_username = current_app.config['BASIC_AUTH_PASSWORD']
#       return username == correct_username and password == correct_password


@app.route('/api/secret')
@basic_auth.required
def api_secret():
    return jsonify({'message':get_secret_message()})



@app.route('/set/')
def set():
    session['key'] = 'value'
    return 'ok'

@app.route('/get/')
def get():
    return session.get('key', 'not set')

def test_flasksqlalchemy_session(self):
    app = flask.Flask(__name__)
    app.debug = True
    app.config['SESSION_TYPE'] = 'sqlalchemy'
    app.config['SQLALCHEMY_DATABASE_URI'] = '/tmp/minitwit.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
    session = Session(app)
    session.app.session_interface.db.create_all()

@app.route('/set', methods=['POST'])
def set_val():
    flask.session['value'] = flask.request.form['value']
    return 'value set'

#@app.route('/get')
#def get():
#   return flask.session['value']

@app.route('/delete', methods=['POST'])
def delete():
    del flask.session['value']
    return 'value deleted'
    
    c = app.test_client()
    self.assertEqual(c.post('/set', data={'value': '42'}).data, b'value '
                                                                b'set')
    self.assertEqual(c.get('/get').data, b'42')
    c.post('/delete')


def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    top = _app_ctx_stack.top
    if not hasattr(top, 'sqlite_db'):
        top.sqlite_db = sqlite3.connect(app.config['DATABASE'])
        top.sqlite_db.row_factory = sqlite3.Row
    return top.sqlite_db


@app.teardown_appcontext
def close_database(exception):
    """Closes the database again at the end of the request."""
    top = _app_ctx_stack.top
    if hasattr(top, 'sqlite_db'):
        top.sqlite_db.close()


def init_db():
    """Initializes the database."""
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()


@app.cli.command('initdb')
def initdb_command():
    """Creates the database tables."""
    init_db()
    print('Initialized the database.')

import click
from flask import Flask

def populate_db():
    """Initializes the database."""
    db = get_db()
    with app.open_resource('population.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()


@app.cli.command('populatedb')
def populatedb_command():
    """Creates the database tables."""
    populate_db()
    print('Populated the database.')


def query_db(query, args=(), one=False):
    """Queries the database and returns a list of dictionaries."""
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv


def get_user_id(username):
    """Convenience method to look up the id for a username."""
    rv = query_db('select user_id from user where username = ?',
                  [username], one=True)
    return rv[0] if rv else None


def format_datetime(timestamp):
    """Format a timestamp for display."""
    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d @ %H:%M')


def gravatar_url(email, size=80):
    """Return the gravatar image for the given email address."""
    return 'https://www.gravatar.com/avatar/%s?d=identicon&s=%d' % \
        (md5(email.strip().lower().encode('utf-8')).hexdigest(), size)


@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        g.user = query_db('select * from user where user_id = ?',
                          [session['user_id']], one=True)

@app.route('/statuses/home_timeline')
def home_timeline():
    if not g.user:
        return redirect(url_for('public_timeline'))
    messages = \
        query_db('''
        select message.*, user.* from message, user
        where message.author_id = user.user_id
        order by message.pub_date desc limit ?''',
                 [PER_PAGE])
    
    for emp in messages:
        empDict = {
            'user_id': emp[0],
            'username': emp[5],
            'email': emp[6],
            'pw_hash': emp[7],
            'status' : 200
            }
    UserList.append(empDict)
    return json.dumps(UserList)
    
    
@app.route('/statuses/public_timeline')
def public_timelineapi():
    """Displays the latest messages of all users."""
    mapToJson()
    return json.dumps(UserList)

    
@app.route('/statuses/user_timeline/<username>')
def user_timelineapi(username):
    """Display's a users tweets."""
    profile_user = query_db('select * from user where username = ?',
                            [username], one=True)
    if profile_user is None:
        abort(404)
    followed = False
    if g.user:
        followed = query_db('''select 1 from follower where
            follower.who_id = ? and follower.whom_id = ?''',
            [session['user_id'], profile_user['user_id']],
            one=True) is not None
    mapToJson()
    js = json.dumps(UserList)
    resp = Response(js, status=200, mimetype='application/json')
    return resp
    

def mapToJson():
    messages = \
        query_db('''
        select message.*, user.* from message, user
        where message.author_id = user.user_id
        order by message.pub_date desc limit ?''', [PER_PAGE])
    print(messages)
    for emp in messages:
        empDict = {
            'user_id': emp[0],
            'username': emp[5],
            'email': emp[6],
            'messages': emp[2]
            }
    UserList.append(empDict)


@app.route('/friendships/create/<username>', methods=['POST'])
def follow_userapi(username):
    """Adds the current user as follower of the given user."""
    if not g.user:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    createFollower(whom_id,username)
    #flash('You are now following "%s"' % username)
    return username

def createFollower(whom_id,username):
    db = get_db()
    db.execute('insert into follower (who_id, whom_id) values (?, ?)',
              [session['user_id'], whom_id])
    db.commit()


@app.route('/friendships/<username>', methods=['DELETE'])
def unfollow_userapi(username):
    """Removes the current user as follower of the given user."""
    if not g.user:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    deleteFollower(whom_id,username)
    return username


def deleteFollower(whom_id,username):
    db = get_db()
    db.execute('delete from follower where who_id=? and whom_id=?',
              [session['user_id'], whom_id])
    db.commit()
    flash('You are no longer following "%s"' % username)



@app.route('/statuses/update', methods=['POST'])
def add_messageapi():
    """Registers a new message for the user."""
    if 'user_id' not in session:
        abort(401)
    else:
       form1 = request.form['text']
    addmessage(form1)
    return 'your message was recorded'

def addmessage(form1):
    db = get_db()
    db.execute('''insert into message (author_id, text, pub_date)
          values (?, ?, ?)''', (session['user_id'], form1,
                                int(time.time())))
    db.commit()

@app.route('/account/verify_credentials', methods=['GET'])
def loginapi():
    """Logs the user in."""
    loginHelper(request)
    return 'user successful'
    check_credentials(self,username,password)




@app.route('/account/verify_credentials',methods=['DELETE'])
def logoutapi():
    """Logs the user out."""
    flash('You were logged out')
    session.pop('user_id', None)
    return 'user logged out'


@app.route('/')
def timeline():
    """Shows a users timeline or if no user is logged in it will
    redirect to the public timeline.  This timeline shows the user's
    messages as well as all the messages of followed users.
    """
    if not g.user:
        return redirect(url_for('public_timeline'))
    return render_template('timeline.html', messages=query_db('''
        select message.*, user.* from message, user
        where message.author_id = user.user_id and (
            user.user_id = ? or
            user.user_id in (select whom_id from follower
                                    where who_id = ?))
        order by message.pub_date desc limit ?''',
        [session['user_id'], session['user_id'], PER_PAGE]))


@app.route('/public')
def public_timeline():
    """Displays the latest messages of all users."""
    return render_template('timeline.html', messages=query_db('''
        select message.*, user.* from message, user
        where message.author_id = user.user_id
        order by message.pub_date desc limit ?''', [PER_PAGE]))


@app.route('/<username>')
def user_timeline(username):
    """Display's a users tweets."""
    profile_user = query_db('select * from user where username = ?',
                            [username], one=True)
    if profile_user is None:
        abort(404)
    followed = False
    if g.user:
        followed = query_db('''select 1 from follower where
            follower.who_id = ? and follower.whom_id = ?''',
            [session['user_id'], profile_user['user_id']],
            one=True) is not None
    return render_template('timeline.html', messages=query_db('''
            select message.*, user.* from message, user where
            user.user_id = message.author_id and user.user_id = ?
            order by message.pub_date desc limit ?''',
            [profile_user['user_id'], PER_PAGE]), followed=followed,
            profile_user=profile_user)


@app.route('/<username>/follow')
def follow_user(username):
    """Adds the current user as follower of the given user."""
    if not g.user:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    db = get_db()
    db.execute('insert into follower (who_id, whom_id) values (?, ?)',
              [session['user_id'], whom_id])
    db.commit()
    flash('You are now following "%s"' % username)
    return redirect(url_for('user_timeline', username=username))


@app.route('/<username>/unfollow')
def unfollow_user(username):
    """Removes the current user as follower of the given user."""
    if not g.user:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    deleteFollower(whom_id,username)
    return redirect(url_for('user_timeline', username=username))


@app.route('/add_message', methods=['POST'])
def add_message():
    """Registers a new message for the user."""
    if 'user_id' not in session:
        abort(401)
    if request.form['text']:
        db = get_db()
        db.execute('''insert into message (author_id, text, pub_date)
          values (?, ?, ?)''', (session['user_id'], request.form['text'],
                                int(time.time())))
        db.commit()
        flash('Your message was recorded')
    return redirect(url_for('timeline'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Logs the user in."""
    if g.user:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        user = query_db('''select * from user where
            username = ?''', [request.form['username']], one=True)
        if user is None:
            error = 'Invalid username'
        elif not check_password_hash(user['pw_hash'],
                                     request.form['password']):
            error = 'Invalid password'
        else:
            flash('You were logged in')
            session['user_id'] = user['user_id']
            return redirect(url_for('timeline'))
    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registers the user."""
    if g.user:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        if not request.form['username']:
            error = 'You have to enter a username'
        elif not request.form['email'] or \
                '@' not in request.form['email']:
            error = 'You have to enter a valid email address'
        elif not request.form['password']:
            error = 'You have to enter a password'
        elif request.form['password'] != request.form['password2']:
            error = 'The two passwords do not match'
        elif get_user_id(request.form['username']) is not None:
            error = 'The username is already taken'
        else:
            db = get_db()
            db.execute('''insert into user (
              username, email, pw_hash) values (?, ?, ?)''',
              [request.form['username'], request.form['email'],
               generate_password_hash(request.form['password'])])
            db.commit()
            flash('You were successfully registered and can login now')
            return redirect(url_for('login'))
    return render_template('register.html', error=error)


@app.route('/logout')
def logout():
    """Logs the user out."""
    flash('You were logged out')
    session.pop('user_id', None)
    return redirect(url_for('public_timeline'))


# add some filters to jinja
app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.filters['gravatar'] = gravatar_url

if __name__ == '__main__':
    app.run(port=5001)
    app.run(debug=True)
