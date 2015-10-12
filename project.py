import os, random, string, httplib2, json, requests
from flask import Flask, render_template, request, redirect, jsonify, url_for, flash, make_response, Markup, session as login_session, send_from_directory
from werkzeug import secure_filename
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Place, Thing, User

#File Upload adapted from http://flask.pocoo.org/docs/0.10/patterns/fileuploads/
# and http://stackoverflow.com/questions/30237504/flask-and-sqlalchemy-get-uploaded-file-using-path-stored-on-database
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = set(['png', 'PNG', 'jpg', 'JPG', 'jpeg', 'JPEG', 'gif', 'GIF'])

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

#Connect to Database and create database session
engine = create_engine('sqlite:///thingsyouseeallover.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


################################################################################
################################################################################
################################################################################
#
# Image Handling
#
################################################################################
################################################################################
################################################################################

#Allowed file extensions check function
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

#Show an uploaded Image
@app.route('/images/<filename>')
def uploaded_image(filename):
  return send_from_directory(app.config['UPLOAD_FOLDER'],filename)


################################################################################
################################################################################
################################################################################
#
# API Endpoints
#
################################################################################
################################################################################
################################################################################

#JSON APIs to view info about Places and Things You See All Over
@app.route('/place/<int:place_id>/thing/JSON')
def placeJSON(place_id):
  place = session.query(Place).filter_by(id = place_id).one()
  things = session.query(Thing).filter_by(place_id = place_id).all()
  return jsonify(Things=[t.serialize for t in things])

@app.route('/place/<int:place_id>/thing/<int:thing_id>/JSON')
def stuffJSON(place_id, thing_id):
  thing = session.query(Thing).filter_by(id = thing_id).one()
  return jsonify(thing = thing.serialize)

@app.route('/place/JSON')
def placesJSON():
  places = session.query(Place).all()
  return jsonify(places= [p.serialize for p in places])

################################################################################
################################################################################
################################################################################
#
# Login Procedures
#
################################################################################
################################################################################
################################################################################

@app.route('/login/')
def showLogin():
  state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
  login_session['state'] = state
  return render_template('login.html', STATE=state)

################################################################################
#
# Login Procedures: GitHub
#
################################################################################

@app.route('/ghcallback')
def ghcallback():
    # Get the code from url, store as 'code'
    code = request.args.get('code')

    # Get the client_id and client_secret from the client secrets JSON
    client_id = json.loads(open('client_secrets_github.json', 'r').read())[
        'web']['client_id']
    client_secret = json.loads(
        open('client_secrets_github.json', 'r').read())['web']['client_secret']
    
    # Get the state from url, confirm match with login state or abort
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Send code back to GitHub, store the response as 'result'
    url = 'https://github.com/login/oauth/access_token?client_id=%s&client_secret=%s&code=%s' % (client_id, client_secret, code)
    h = httplib2.Http()
    result = h.request(url, 'POST', headers={'Accept':'application/json'})[1]

    # Read 'result' JSON, store the access_token to the login_session
    data = json.loads(result)
    login_session['provider'] = 'github'
    login_session['access_token'] = data["access_token"]

    # Trade the access_token for the user data, store the response as 'userdata'
    url = 'https://api.github.com/user?access_token=%s' % (login_session['access_token'])
    h = httplib2.Http()
    userdata = h.request(url, 'GET')[1]

    # Read 'userdata' JSON, store the access_token to the login_session
    data = json.loads(userdata)
    if data['email']:
      login_session['email'] = data['email']
    else:
      login_session['email'] = data["id"]
    login_session['picture'] = data['avatar_url']
    login_session['username'] = data['name']
    login_session['github_id'] = data["id"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    flash("Now logged in as %s" % login_session['username'])
    return redirect(url_for('showPlaces'))


################################################################################
#
# Login Procedures: Facebook
#
################################################################################

@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    # Check the login state, set the login state to 'access_token'
    if request.args.get('state') != login_session['state']:
      response = make_response(json.dumps('Invalid state parameter.'), 401)
      response.headers['Content-Type'] = 'application/json'
      return response
    access_token = request.data

    # Get the app_id and app_secret from the client secrets JSON
    app_id = json.loads(open('client_secrets_facebook.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('client_secrets_facebook.json', 'r').read())['web']['app_secret']

    # Send the app_id, app_secret, and access_token to Facebook, store the response as 'result'
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Get the token from 'result', store as 'token'
    token = result.split("&")[0]

    # Send token back to Facebook, store the response as 'result'
    url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Transform 'result' into JSON, split out the data into the login_session
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout, let's strip out the information before the equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture separately
    url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token
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

#Facebook Disconnect
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must be included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "You have been logged out."


################################################################################
#
# Login Procedures: Google
#
################################################################################

@app.route('/gconnect', methods=['POST'])
def gconnect():
  # Check the login state, set the login state to 'code'
  if request.args.get('state') != login_session['state']:
    response = make_response(json.dumps('Invalid state parameter'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response
  code = request.data
  try:
    # Upgrade the authorization code into a credentials object
    oauth_flow = flow_from_clientsecrets('client_secrets_google.json', scope='')
    oauth_flow.redirect_uri = 'postmessage'
    credentials = oauth_flow.step2_exchange(code)
  except FlowExchangeError:
    response = make_response(
      json.dumps('Failed to upgrade the authorization code.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response

  CLIENT_ID = json.loads(
    open('client_secrets_google.json', 'r').read())['web']['client_id']

  # Check that the access token is valid
  access_token = credentials.access_token
  url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
  h = httplib2.Http()
  result = json.loads(h.request(url, 'GET')[1])
  if result.get('error') is not None:
    response = make_response(
      json.dumps(result.get('error')), 500)
    response.headers['Content-Type'] = 'application/json'

  # Verify that the access token is used for the intended user
  gplus_id = credentials.id_token['sub']
  if result['user_id'] != gplus_id:
    response = make_response(
      json.dumps("Token's user ID doesn't match given user ID."), 401)
    response.headers['Content-Type'] = 'application/json'
    return response

  # Verify that the access token is valid for this app
  if result['issued_to'] != CLIENT_ID:
    response = make_response(
      json.dumps("Token's client ID doesn't match app's."), 401)
    response.headers['Content-Type'] = 'application/json'
    return response

  # Check if the user is already logged in
  stored_credentials = login_session.get('credentials')
  stored_gplus_id = login_session.get('gplus_id')
  if stored_credentials is not None and gplus_id == stored_gplus_id:
    response = make_response(
      json.dumps('Current user is already connected.'), 200)
    response.headers['Content-Type'] = 'application/json'

  # Store the access token in the session for later use.
  login_session['credentials'] = credentials.access_token
  login_session['gplus_id'] = gplus_id

  # Get user info
  userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
  params = {'access_token': credentials.access_token, 'alt':'json'}
  answer = requests.get(userinfo_url, params=params)
  data = json.loads(answer.text)

  login_session['provider'] = 'google'
  login_session['username'] = data['name']
  login_session['picture'] = data['picture']
  login_session['email'] = data['email']

  # See if user exists, otherwise make a new one
  user_id = getUserID(login_session['email'])
  if not user_id:
    user_id = createUser(login_session)
  login_session['user_id'] = user_id

  output = ''
  output +='<h1>Welcome, '
  output += login_session['username']
  output += '!</h1>'
  output += '<img src="'
  output += login_session['picture']
  output += ' " style="width:300px; height:300px; border-radius:150px;">'
  flash("You are now logged in as %s" %login_session['username'])
  return output

#Google Disconnect
@app.route('/gdisconnect')
def gdisconnect():
  # Only works for a connected user
  credentials = login_session.get('credentials')
  if credentials is None:
    response = make_response(
      json.dumps("Current user is not connected"), 401)
    response.headers['Content-Type'] = 'application/json'
    return response
  # Execute HTTP GET to revoke token
  access_token = credentials
  url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
  h = httplib2.Http()
  result = h.request(url, 'GET')[0]

  if result['status'] != '200':
    # Something went wrong with disconnect
    response = make_response(
      json.dumps("Failed to disconnect"), 400)
    response.headers['Content-Type'] = 'application/json'
    return response

################################################################################
#
# Login Procedures: Disconnect
#
################################################################################

@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        if login_session['provider'] == 'github':
            del login_session['github_id']
            del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showPlaces'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showPlaces'))


################################################################################
################################################################################
################################################################################
#
# Places
#
################################################################################
################################################################################
################################################################################

################################################################################
#
# Places: Show All
#
################################################################################

@app.route('/')
@app.route('/places/')
def showPlaces():
  places = session.query(Place).order_by(Place.name)
  if 'username' not in login_session:
    return render_template('places-public.html', places = places)
  else:
    return render_template('places.html', places = places)

################################################################################
#
# Place: Create
#
################################################################################

@app.route('/place/new/', methods=['GET','POST'])
def newPlace():
  if 'username' not in login_session:
    return redirect('/login')
  if request.method == 'POST':
    file = request.files['image']
    if file and allowed_file(file.filename):
      filename = secure_filename(file.filename)
      file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    else:
      filename = 'placeholder.jpg'
    place = Place(
      name = request.form['name'], 
      user_id = login_session['user_id'],
      image = filename)
    session.add(place)
    flash("New place to see stuff: %s" % place.name)
    session.commit()
    return redirect(url_for('showPlaces'))
  else:
    return render_template('newplace.html')

################################################################################
#
# Place: Edit
#
################################################################################

@app.route('/place/<int:place_id>/edit/', methods = ['GET', 'POST'])
def editPlace(place_id):
  if 'username' not in login_session:
    return redirect('/login')
  place = session.query(Place).filter_by(id = place_id).one()
  creator = getUserInfo(place.user_id)
  if creator.id == login_session['user_id']:
    if request.method == 'POST':
      if request.form['name']:
        place.name = request.form['name']
      if request.files['image']:
        file = request.files['image']
        if file and allowed_file(file.filename):
          filename = secure_filename(file.filename)
          file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        place.image = filename      
      session.add(place)
      session.commit()
      flash('%s successfully edited!' % place.name)
      return redirect(url_for('showThings', place_id=place_id))
    else:
      return render_template('editplace.html', place = place)
  else:
    message = Markup("You don&rsquo;t have permissions to edit %s" % place.name)
    flash(message)
    return redirect(url_for('showPlaces'))

################################################################################
#
# Place: Delete
#
################################################################################

@app.route('/place/<int:place_id>/delete/', methods = ['GET','POST'])
def deletePlace(place_id):
  place = session.query(Place).filter_by(id = place_id).one()
  if 'username' not in login_session:
    return redirect('/login')
  if place.user_id != login_session['user_id']:
    message = Markup("You don&rsquo;t have permissions to delete %s" % place.name)
    flash(message)
    return redirect(url_for('showPlaces'))
  if request.method == 'POST':
    session.delete(place)
    flash('%s Successfully Deleted' % place.name)
    session.commit()
    return redirect(url_for('showPlaces'))
  else:
    return render_template('deleteplace.html',place = place)

################################################################################
################################################################################
################################################################################
#
# Things
#
################################################################################
################################################################################
################################################################################

################################################################################
#
# Things: Show all the Things from One Place
#
################################################################################

@app.route('/place/<int:place_id>/')
@app.route('/place/<int:place_id>/thing/')
def showThings(place_id):
    c = session.query(Place).filter_by(id = place_id).one()
    p = session.query(Thing).filter_by(place_id = c.id).filter(Thing.kind_of_thing == 'People').order_by(Thing.name).all()
    l = session.query(Thing).filter_by(place_id = c.id).filter(Thing.kind_of_thing == 'Plants').order_by(Thing.name).all()
    a = session.query(Thing).filter_by(place_id = c.id).filter(Thing.kind_of_thing == 'Animals').order_by(Thing.name).all()
    m = session.query(Thing).filter_by(place_id = c.id).filter(Thing.kind_of_thing == 'Machines').order_by(Thing.name).all()
    o = session.query(Thing).filter_by(place_id = c.id).filter(Thing.kind_of_thing == 'Other').order_by(Thing.name).all()
    creator = getUserInfo(c.user_id)
    if 'username' not in login_session or creator.id != login_session['user_id']:
      return render_template('things-public.html', place=c, people=p, plants=l, animals=a, machines=m, other=o, creator=creator)
    else:
      return render_template('things.html', place=c, people=p, plants=l, animals=a, machines=m, other=o, creator=creator)

################################################################################
#
# Thing: Create
#
################################################################################

@app.route('/place/<int:place_id>/thing/new/',methods=['GET','POST'])
def newThing(place_id):
  if 'username' not in login_session:
    return redirect('/login')
  if request.method == 'POST':
      file = request.files['image']
      if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
      else:
        filename = 'placeholder.jpg'
      t = Thing(
        name = request.form['name'], 
        description = request.form['description'], 
        kind_of_thing = request.form['kind_of_thing'], 
        place_id = place_id, 
        user_id = login_session['user_id'],
        image = filename)
      session.add(t)
      session.commit()
      flash("It's something you see all over: %s" % (t.name))
      return redirect(url_for('showThings', place_id = place_id))
  else:
      return render_template('newthing.html', place_id = place_id)

################################################################################
#
# Thing: Edit
#
################################################################################

@app.route('/place/<int:place_id>/thing/<int:thing_id>/edit', methods=['GET','POST'])
def editThing(place_id, thing_id):
  if 'username' not in login_session:
    return redirect('/login')
  t = session.query(Thing).filter_by(id = thing_id).one()
  if request.method == 'POST':
    if request.form['name']:
      t.name = request.form['name']
    if request.form['description']:
      t.description = request.form['description']
    if request.form['kind_of_thing']:
      t.kind_of_thing = request.form['kind_of_thing']
    if request.files['image']:
      file = request.files['image']
      if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
      t.image = filename      
    session.add(t)
    session.commit() 
    flash("%s edited successfully!" % t.name)
    return redirect(url_for('showThings', place_id = place_id))
  else:
    return render_template('editthing.html', place_id = place_id, thing_id = thing_id, item = t)

################################################################################
#
# Thing: Delete
#
################################################################################

@app.route('/place/<int:place_id>/thing/<int:thing_id>/delete', methods = ['GET','POST'])
def deleteThing(place_id,thing_id):
  if 'username' not in login_session:
    return redirect('/login')
  t = session.query(Thing).filter_by(id = thing_id).one() 
  if request.method == 'POST':
    session.delete(t)
    session.commit()
    flash('%s deleted successfully' % t.name)
    return redirect(url_for('showThings', place_id = place_id))
  else:
    return render_template('deletething.html', place_id = place_id, item = t)


################################################################################
################################################################################
################################################################################
#
# User Handling
#
################################################################################
################################################################################
################################################################################

def getUserID(email):
  try:
    user = session.query(User).filter_by(email = email).one()
    return user.id
  except:
    return None

def getUserInfo(user_id):
  user = session.query(User).filter_by(id = user_id).one()
  return user

def createUser(login_session):
  newUser = User(
    name = login_session['username'], 
    email = login_session['email'],
    picture = login_session['picture'])
  session.add(newUser)
  session.commit()
  user = session.query(User).filter_by(email = login_session['email']).one()
  return user.id

################################################################################
################################################################################
################################################################################
#
# App Config
#
################################################################################
################################################################################
################################################################################

if __name__ == '__main__':
  app.secret_key = '\xe1\xad\xdf\xc2\xa66\xde\xc8\xdb\x0f\x05\xac\x89\x06\xb0\x8d&\xa0Z\xe1\xb8\xbc-\xf6'
  app.debug = True
  app.run(host = '0.0.0.0', port = 5000)
