from __future__ import absolute_import
from flask import Flask, render_template, flash, request, redirect, jsonify, url_for
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Offering, Tag, Comment, User, File
import string
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
import httplib2
from flask import session as login_session
import random
import json
from flask import make_response
import requests
from werkzeug.utils import secure_filename
from flask import send_from_directory
import datetime
from google.cloud import storage
from werkzeug.exceptions import BadRequest
import six
from google.cloud import vision
from google.cloud.vision import types

PROJECT_ID = 'pycharm-194111'
CLOUD_STORAGE_BUCKET = 'pycharm-194111.appspot.com'
MAX_CONTENT_LENGTH = 8 * 1024 * 1024
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

COLOURS = set(['red', 'orange', 'yellow', 'green', 'cyan', 'blue',
               'indigo', 'violet', 'purple', 'magenta', 'pink', 'brown', 'white', 'gray', 'black'])

SECRET_KEY = 'secret'
DATA_BACKEND = 'cloudsql'
CLOUDSQL_USER = 'marc'
CLOUDSQL_PASSWORD = '7Ggda0dqaD0ovIIu'
CLOUDSQL_DATABASE = 'offerings'

CLOUDSQL_CONNECTION_NAME = 'pycharm-194111:europe-west2:babiesgrowdatabase'

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "BabiesGrow"

app = Flask(__name__)


engine = create_engine('mysql+pymysql://root:7Ggda0dqaD0ovIIu@/offerings?unix_socket=/cloudsql/pycharm-194111:europe-west2:babiesgrowdatabase')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# https://stackoverflow.com/questions/46381128/building-progressive-web-apps-using-python-flask
@app.route('/sw.js', methods=['GET'])
def sw():
    return app.send_static_file('sw.js')


# Start of upload to cloud storage code
# Code taken from below and modified slightly
# https://github.com/GoogleCloudPlatform/getting-started-python/blob/master/3-binary-data/bookshelf/storage.py


def _get_storage_client():
    return storage.Client(
        project='pycharm-194111')


def _check_extension(filename):
    if '.' not in filename or filename.split('.').pop().lower() not in ALLOWED_EXTENSIONS:
        raise BadRequest(
            "{0} has an invalid name or extension".format(filename))


def _safe_filename(filename):
    """
    Generates a safe filename that is unlikely to collide with existing objects
    in Google Cloud Storage.

    ``filename.ext`` is transformed into ``filename-YYYY-MM-DD-HHMMSS.ext``
    """
    filename = secure_filename(filename)
    date = datetime.datetime.utcnow().strftime("%Y-%m-%d-%H%M%S")
    basename, extension = filename.rsplit('.', 1)
    return "{0}-{1}.{2}".format(basename, date, extension)


# [START upload_image_file]
def upload_image_file(file):
    """
    Upload the user-uploaded file to Google Cloud Storage and retrieve its
    publicly-accessible URL.
    """
    if not file:
        return None

    public_url = upload_file(
        file.read(),
        file.filename,
        file.content_type
    )

    app.logger.info(
        "Uploaded file %s as %s.", file.filename, public_url)

    return public_url
# [END upload_image_file]


# [START upload_file]
def upload_file(file_stream, filename, content_type):
    """
    Uploads a file to a given Cloud Storage bucket and returns the public url
    to the new object.
    """
    _check_extension(filename)
    filename = _safe_filename(filename)

    client = _get_storage_client()
    bucket = client.bucket('pycharm-194111.appspot.com')
    blob = bucket.blob(filename)

    blob.upload_from_string(
        file_stream,
        content_type=content_type)

    url = blob.public_url

    if isinstance(url, six.binary_type):
        url = url.decode('utf-8')

    return url
# [END upload_file]

# End of upload to cloud storage code


# Creating new offering object
@app.route('/offerings/new/', methods=['GET', 'POST'])
def newOffering():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newOffering = Offering(title=request.form['title'], location=request.form['location'],
                               date=datetime.date.today(), user_id=login_session['user_id'])
        session.add(newOffering)
        session.commit()
        flash("New Offering added")
        return redirect(url_for('load_file', offering_id=newOffering.id))
    else:
        return render_template('newoffering.html')


# Routed to image upload. Image will retrive the cloud storage url and save it to file object
@app.route('/offerings/<int:offering_id>/new', methods=['GET', 'POST'])
def load_file(offering_id):
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        image_url = upload_image_file(request.files.get('file'))
        newFile = File(image=image_url, offering_id=offering_id, user_id=login_session['user_id'])
        session.add(newFile)
        session.commit()
        return redirect(url_for('uploaded_file', offering_id=offering_id, file_id=newFile.id))
    else:
        return render_template('uploads.html')


# Calling the Vision API on uploaded image and saving the labels recognised as tags
# https://github.com/GoogleCloudPlatform/python-docs-samples/blob/master/vision/cloud-client/detect/detect.py
@app.route('/offerings/<int:offering_id>/new/file/<int:file_id>')
def uploaded_file(offering_id, file_id):
    pic = session.query(File).filter_by(id=file_id).one()
    return render_template('uploadedfile.html', pic=pic, file_id=file_id, offering_id=offering_id)


@app.route('/offerings/<int:offering_id>/new/file/<int:file_id>/analyze')
def analyze_file(offering_id, file_id):
    #offering = session.query(Offering).filter_by(id=offering_id).one()
    pic = session.query(File).filter_by(id=file_id).one()

    client = vision.ImageAnnotatorClient()
    image = types.Image()
    image.source.image_uri = pic.image

    response = client.label_detection(image=image)
    labels = response.label_annotations

    for label in labels:
        if label.description in COLOURS:
            newTag = Tag(tag_name=label.description, offering_id=offering_id)
            session.add(newTag)
            session.commit()

    response2 = client.logo_detection(image=image)
    logos = response2.logo_annotations

    for logo in logos:
        newTag = Tag(tag_name=logo.description, offering_id=offering_id)
        session.add(newTag)
        session.commit()

    response3 = client.web_detection(image=image)
    annotations = response3.web_detection

    if annotations.web_entities:
        for entity in annotations.web_entities:
            if entity.score > 0.68:
                newTag = Tag(tag_name=entity.description, offering_id=offering_id)
                session.add(newTag)
                session.commit()
                tags = session.query(Tag).filter_by(offering_id=offering_id).all()
    return render_template('analyzedfile.html', pic=pic, tags=tags, file_id=file_id, offering_id=offering_id)

# http://flask.pocoo.org/docs/0.12/patterns/fileuploads/
# Return uploaded file code from Flask docs
@app.route('/offerings/<int:offering_id>/new/file/<int:file_id>/tags')
def uploadedfile(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)

# Code for login follows the Udacity tutorial Authentication & Authorization: OAuth
# @reference http://https://classroom.udacity.com/courses/ud330/lessons/3967218625/concepts/39636486150923

# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    # Render Login Template return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)

# Connecting to Facebook
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token


    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]


    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange we have to
        split the token first on commas and select the first index which gives us the key : value
        for the server access token then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used directly in the graph
        api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.12/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.12/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


# For logging out
@app.route('/fbdisconnect', methods=['POST'])
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "You have been logged out"

# Disconnect based on provider


@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have logged out.")
        return redirect(url_for('offering'))
    else:
        flash("You were not logged in")
        return redirect(url_for('offering'))


# Validate the state token
@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Acquire authorisation code
    code = request.data

    try:
        # Upgrade auth code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps('Failed to upgrade the authorisation code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check token is valid
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # Abort if there was an error in access token info
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Confirm access token is for the correct user
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps("User ID does not match Token ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Confirm the access token is correct for this app
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps("Token ID does not match to application"), 401)
        print "Token ID does not match to application"
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check to see if the user is already logged in
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('User is already logged in'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store access token in the session
    login_session['provider'] = 'google'
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get the user's info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()

    # Store user data to  create a response
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # Check if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# Disconnect by revoking user's access token

@app.route('/gdisconnect')
def gdisconnect():
    # @ ref https://github.com/udacity/ud330/pull/54/files
    access_token = login_session.get('access_token')
    url = 'https://accounts.google.com/o/oauth2/revoke?token={}'.format(access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        return "You have been logged out."
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session['email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUsers(user_id):
    user = session.query(User).filter_by(id=user_id).all()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# Code for structuring the data and developing  API endpoints
# inspired by the Udacity course  - Full Stack Foundations


@app.route('/')
@app.route('/offerings/')
def offering():
    offerings = session.query(Offering).all()
    files = session.query(File).all()
    return render_template('offerings.html', offerings=offerings, files=files)


@app.route('/offerings/<offering_location>/')
def offeringLocation(offering_location):
    offerings = session.query(Offering).filter_by(location=offering_location)
    files = session.query(File).all()
    return render_template('offeringlocation.html', offerings=offerings, files=files,
                           offering_location=offering_location)


@app.route('/offerings/tag/<int:tag_id>/')
def offeringByTag(tag_id):
    tag = session.query(Tag).filter_by(id=tag_id).one()
    taglist = session.query(Tag).all()
    offerings = session.query(Offering).all()
    files = session.query(File).all()
    return render_template('offeringtags.html', offerings=offerings, files=files, tag=tag, taglist=taglist)


@app.route('/offerings/JSON')
def offeringJSON():
    offerings = session.query(Offering).all()
    return jsonify(offerings=[i.serialize for i in offerings])


@app.route('/offerings/user/<int:user_id>/')
def offeringsByUser(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    offerings = session.query(Offering).filter_by(user_id=user_id).all()
    files = session.query(File).all()
    return render_template('offerings.html', offerings=offerings, files=files, user=user)


@app.route('/offerings/<int:offering_id>/')
def offeringDetail(offering_id):
    offering = session.query(Offering).filter_by(id=offering_id).one()
    owner = getUserInfo(offering.user_id)
    files = session.query(File).filter_by(offering_id=offering_id).all()
    tags = session.query(Tag).filter_by(offering_id=offering_id).all()
    comments = session.query(Comment).filter_by(offering_id=offering_id).all()
    commenter = getUsers(Comment.user_id)
    if 'username' not in login_session or owner.id != login_session['user_id']:
        return render_template('publicOfferingDetail.html', offering=offering, tags=tags, comments=comments,
                                  offering_id=offering_id, files=files, owner=owner, commenter=commenter)
    else:
        return render_template('offeringDetail.html', offering=offering, tags=tags, comments=comments,
                               offering_id=offering_id, files=files, owner=owner, commenter=commenter)


@app.route('/offerings/<int:offering_id>/JSON')
def offeringDetailJSON(offering_id):
    offering = session.query(Offering).filter_by(id=offering_id).one()
    tags = session.query(Tag).filter_by(offering_id=offering_id).all()
    comments = session.query(Comment).filter_by(offering_id=offering_id).all()
    return jsonify(offering=offering.serialize, Tags=[i.serialize for i in tags],
                   Comment=[j.serialize for j in comments])


@app.route('/offerings/<int:offering_id>/edit/', methods=['GET', 'POST'])
def editOffering(offering_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedOffering = session.query(Offering).filter_by(id=offering_id).one()
    if request.method == 'POST':
        if request.form['title']:
            editedOffering.title = request.form['title']
            flash("Offering updated")
            return redirect(url_for('offering'))
    else:
        return render_template('editoffering.html', offering=editedOffering)


@app.route('/offerings/<int:offering_id>/delete/', methods=['GET', 'POST'])
def deleteOffering(offering_id):
    if 'username' not in login_session:
        return redirect('/login')
    offeringToDelete = session.query(Offering).filter_by(id=offering_id).one()
    if offeringToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert" \
               "('You are not authorized to delete this offering.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(offeringToDelete)
        session.commit()
        flash("Offering deleted")
        return redirect(url_for('offering', offering_id=offering_id))
    else:
        return render_template('deleteoffering.html', offering=offeringToDelete)


@app.route('/offerings/<int:offering_id>/tag/new/', methods=['GET', 'POST'])
def newTag(offering_id):
    if 'username' not in login_session:
        return redirect('/login')
    offering = session.query(Offering).filter_by(id=offering_id).one()
    if request.method == 'POST':
        newTag = Tag(tag_name=request.form['tag_name'].lower(), offering_id=offering.id)
        session.add(newTag)
        flash('Tag Added')
        session.commit()
        return redirect(url_for('offeringDetail', offering_id=offering_id))
    else:
        return render_template('newtag.html')


@app.route('/offerings/<int:offering_id>/tag/<int:tag_id>/delete/', methods=['GET', 'POST'])
def deleteTag(offering_id, tag_id):
    if 'username' not in login_session:
        return redirect('/login')
    offering = session.query(Offering).filter_by(id=offering_id).one()
    tagToDelete = session.query(Tag).filter_by(id=tag_id).one()
    if offering.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert" \
               "('You are not authorized to remove this Tag.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(tagToDelete)
        session.commit()
        flash("Tag deleted")
        return redirect(url_for('offeringDetail', offering_id=offering_id))
    else:
        return render_template('deletetag.html', tag=tagToDelete, offering_id=offering_id)


@app.route('/offerings/<int:offering_id>/', methods=['GET', 'POST'])
def newComment(offering_id):
    if 'username' not in login_session:
        return redirect('/login')
    offering = session.query(Offering).filter_by(id=offering_id).one()
    if request.method == 'POST':
        newComment = Comment(body=request.form['body'], offering_id=offering.id, user_id=login_session['user_id'])
        session.add(newComment)
        flash('Comment Added')
        session.commit()
        return redirect(url_for('offeringDetail', offering_id=offering_id))


@app.route('/offerings/<int:offering_id>/file/<int:file_id>/delete/', methods=['GET', 'POST'])
def deleteFile(offering_id, file_id):
    if 'username' not in login_session:
        return redirect('/login')
    offering = session.query(Offering).filter_by(id=offering_id).one()
    fileToDelete = session.query(File).filter_by(id=file_id).one()
    if offering.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert" \
               "('You are not authorized to delete this offering.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(fileToDelete)
        session.commit()
        flash("Image deleted")
        return redirect(url_for('offering', offering_id=offering_id))
    else:
        return render_template('deletefile.html', file=fileToDelete, offering_id=offering_id)

if __name__ == '__main__':
    app.debug = True
    app.run()


#https://media.readthedocs.org/pdf/flask/stable/flask.pdf
# set the secret key. keep this really secret:
app.secret_key = 'A0Zr98j/3yX R~XHH!jmN]LWX/,?RT'

