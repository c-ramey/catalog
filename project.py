from flask import Flask, render_template, request
from flask import redirect,  url_for, jsonify, flash, make_response
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db_setup import User, Base, Category, Item
from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from oauth2client.client import GoogleCredentials
import random
import string
import httplib2
import requests
import json
app = Flask(__name__)

# variables for Google Signin
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "catalog-ramey1234"

# Database session setup
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# Login routines
@app.route('/login/')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase+string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/logout/')
def showLogout():
    access_token = login_session.get('access_token')
    print access_token
    if access_token is None:
        response = make_response(json.dumps('User is not connected'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    del login_session['access_token']
    del login_session['gplus_id']
    del login_session['username']
    del login_session['picture']
    del login_session['email']
    response = make_response(json.dumps("You are disconnected"), 200)
    response.headers['Content-Type'] = 'application/json'
    return redirect('/categories')


@app.route('/gconnect', methods=['POST', 'GET'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid State Parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    code = request.data
    try:
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps('Failed to upgrade auth code'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # is access_token valid
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    # store the result of request
    result = json.loads(h.request(url, 'GET')[1])
    # if result contains any errors the message is sent to server
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
    # verify if this the right access_token
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps('Users ids do not match'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # is this token was issued for this app
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps('Token id does not match app id'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # checks is the user already logged in not to reset all info
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('User is already connected'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id
    # user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'
    user_id = getUserID(data['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    output = ''
    output += '<h3>Welcome, '
    output += login_session['username']
    output += '</h3>'
    return output


# User routines
def createUser(login_session):
    """
    createUser(login_session): creates a user
    Args:
        login_session(data-type: session) has info about the current logged user
    Returns:
        user id from database
    """
    user = User(name=login_session['username'],
                email=login_session['email'],
                picture=login_session['picture'])
    session.add(user)
    session.commit()
    user_db = session.query(User).filter_by(email=login_session['email']).one()
    return user_db.id


def getUserInfo(user_id):
    """
    getUserInfo(user_id): get user-info by id
    Args:
        user_id(data-type: int) a unique value
        that identifies a user in DB
    Returns:
        user info (username, email, picture)
    """
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    """
    getUserID(email): get user-info by email
    Args:
        email(data-type: string) a unique value
        that identifies a user in DB
    Returns:
        user.id or None if no such email in DB
    """
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# webpage view routes
@app.route('/')
@app.route('/categories/')
def showCategories():
    """
    showCategories(): shows a list of categories
    Args:
        None
    Returns:
        renders a template with a list of categories
    """
    categories = session.query(Category).all()
    if 'username' not in login_session:
        return render_template('public_categories.html', categories=categories)
    else:
        return render_template('categories.html', categories=categories,
                               user=login_session['email'],
                               picture=login_session['picture'])


@app.route('/categories/<int:category_id>/')
@app.route('/categories/<int:category_id>/items/')
def showItems(category_id):
    """
    showItems(): shows a list of items of a specific category
    Args:
        category_id (data-type: int) primary key of Category class
    Returns:
        renders a template with a list of items of the category
    """
    category = session.query(Category).filter_by(id=category_id).one_or_none()
    if category is None:
        return "No such element"
    items = session.query(Item).filter_by(category_id=category_id).all()
    if 'username' not in login_session:
        return render_template('public_items.html', category=category, items=items)
    return render_template('items.html', items=items,
                           category=category, user=login_session['email'])


@app.route('/categories/new/', methods=['GET', 'POST'])
def newCategory():
    """
    newCategory(): creates a Category
    Args:
        None
    Returns:
        redirects to the method that shows the
        list of categories
    """
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newCategory = Category(name=request.form['name'],
                         description=request.form['description'],
                         user_id=login_session['user_id'])
        session.add(newCategory)
        session.commit()
        flash('Category was successfully added to the catalog')
        return redirect(url_for('showCategories'))
    else:
        return render_template('newCategory.html')


@app.route('/categories/<int:category_id>/items/new/',
           methods=['GET', 'POST'])
def newItem(category_id):
    """
    newItem(category_id): adds a Item to Category
    Args:
        category_id (data type: int): primary key of Category class
    Returns:
        redirects to the method that shows the
        list of items of category if successful
    """
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        if 'type' not in request.form:
            type = 'eItem'
        else:
            type = request.form['type']
        newItem = Item(name=request.form['name'],
                           description=request.form['description'],
                           user_id=login_session['user_id'], category_id=category_id)
        session.add(newItem)
        session.commit()
        flash('Item was successfully added to the list')
        return redirect(url_for('showItems', category_id=category_id))
    else:
        return render_template('newItem.html', category_id=category_id)


@app.route('/categories/<int:category_id>/edit/', methods=['GET', 'POST'])
def editCategory(category_id):
    """
    editCategory(category_id): edits a category
    Args:
        category_id (data type: int): primary key of Category class
    Returns:
        redirects to the method that shows the
        list of categories if successful
    """
    if 'username' not in login_session:
        return redirect('/login')
    categoryToEdit = session.query(Category).filter_by(id=category_id).one_or_none()
    if categoryToEdit is None:
        return ("<script>function myFunction() {alert('No such element');"
                "window.history.back();}</script>"
                "<body onload='myFunction()''>")
    if categoryToEdit.user_id != login_session['user_id']:
        return ("<script>function myFunction() {alert('No access');"
                "window.history.back();}</script>"
                "<body onload='myFunction()''>")
    if request.method == 'POST':
        if request.form['name']:
            categoryToEdit.name = request.form['name']
        if request.form['description']:
            categoryToEdit.description = request.form['description']
        session.add(categoryToEdit)
        session.commit()
        flash('Category %s was successfully edited' % categoryToEdit.name)
        return redirect(url_for('showCategories'))
    else:
        return render_template('editCategory.html', category=categoryToEdit)


@app.route('/categories/<int:category_id>/items/<int:item_id>/edit/',
           methods=['GET', 'POST'])
def editItem(category_id, item_id):
    """
    editItem(category_id, item_id): edits a Item
    Args:
        category_id (data type: int): id of a category item belongs to
        item_id (data type: int): primary key for a item
    Returns:
        redirects to the method that shows the list
        of items of the category if successful
    """
    if 'username' not in login_session:
        return redirect('/login')
    itemToEdit = session.query(Item).filter_by(id=item_id).one_or_none()
    if itemToEdit is None:
        return ("<script>function myFunction() {alert('No such element');"
                "window.history.back();}</script>"
                "<body onload='myFunction()''>")
    if itemToEdit.user_id != login_session['user_id']:
        return ("<script>function myFunction()"
                "{alert('No access');window.history.back();}"
                "</script><body onload='myFunction()''>")
    if request.method == 'POST':
        if request.form['name']:
            itemToEdit.name = request.form['name']
        if request.form['description']:
            itemToEdit.description = request.form['description']
        itemToEdit.id = item_id
        itemToEdit.category_id = category_id
        session.add(itemToEdit)
        session.commit()
        flash('Item %s was successfully edited' % itemToEdit.name)
        return redirect(url_for('showItems', category_id=category_id))
    else:
        return render_template('editItem.html', category_id=category_id,
                               item_id=item_id, item=itemToEdit)


@app.route('/categories/<int:category_id>/delete/', methods=['GET', 'POST'])
def deleteCategory(category_id):
    """
    deleteCategory(category_id): deletes a Category
    Args:
        category_id (data type: int): primary key of category
    Returns:
        redirects to the method that shows the
        list of categories if successful
    """
    if 'username' not in login_session:
        return redirect('/login')
    categoryToDelete = session.query(Category).filter_by(id=category_id).one_or_none()
    if categoryToDelete is None:
        return ("<script>function myFunction() {alert('No such element');"
                "window.history.back();}</script>"
                "<body onload='myFunction()''>")
    if categoryToDelete.user_id != login_session['user_id']:
        return ("<script>function myFunction()"
                "{alert('No access');"
                "window.history.back();"
                "}</script><body onload='myFunction()''>")
    if request.method == 'POST':
        session.delete(categoryToDelete)
        session.commit()
        flash('Category was successfully deleted from the catalog')
        return redirect(url_for('showCategories', category_id=category_id))
    else:
        return render_template('deleteCategory.html', category=categoryToDelete)


@app.route('/categories/<int:category_id>/items/<int:item_id>/delete/',
           methods=['GET', 'POST'])
def deleteItem(category_id, item_id):
    """
    deleteItem(category_id, item_id): deletes a Item
    Args:
        category_id (data type: int): id of a category item belongs to
        item_id (data type: int): primary key for a item
    Returns:
        redirects to the method that shows the
        list of items of category if successful
    """
    if 'username' not in login_session:
        return redirect('/login')
    itemToDelete = session.query(Item).filter_by(id=item_id).one_or_none()
    if itemToDelete is None:
        return ("<script>function myFunction() {alert('No such element');"
                "window.history.back();"
                "window.history.back();}</script>"
                "<body onload='myFunction()''>")
    if itemToDelete.user_id != login_session['user_id']:
        return ("<script>function myFunction()"
                "{alert('No access');}</script><body onload='myFunction()''>")
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Item was successfully deleted from the list')
        return redirect(url_for('showItems', category_id=category_id))
    else:
        return render_template('deleteItem.html', item=itemToDelete)


# JSON API endpoints
@app.route('/categories/JSON/')
def categoriesJSON():
    categories = session.query(Category).all()
    return jsonify(categories=[g.serialize for g in categories])


@app.route('/categories/<int:category_id>/items/JSON/')
def showItemsJSON(category_id):
    category = session.query(Category).filter_by(id=category_id).one_or_none()
    if category is None:
        return "No such element."
    items = session.query(Item).filter_by(category_id=category_id).all()
    return jsonify(items=[b.serialize for b in items])


if __name__ == '__main__':
    app.secret_key = '_this_is_magic_'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
