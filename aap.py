from flask_cors import CORS
import os
import mysql.connector
from flask import Flask, render_template, request, redirect, url_for, flash, make_response, jsonify, abort, session, get_flashed_messages
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, decode_token
import json
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
from mysql.connector import Error


mycon=mysql.connector.connect(host="localhost",user="root",password="password",database="iss_proj")
mycursor=mycon.cursor()

app = Flask(__name__)
CORS(app,supports_credentials = True)

app.config["JWT_TOKEN_LOCATION"] = ["headers", "cookies", "json", "query_string"]
app.config['JWT_SECRET_KEY'] = 'super-secret'
app.config['JWT_COOKIE_SECURE'] = False # Only for development, set to True for production
app.secret_key = 'your_secret_key_here'
app.config['JWT_ACCESS_COOKIE_PATH'] = '/user'

jwt = JWTManager(app)

ussername=""

# MySQL Configuration
db_connection = mysql.connector.connect(
    host="localhost",
    user="root",
    password="password",
    database="iss_proj"
)

# Function to execute MySQL queries
def execute_query(query, values=None):
    cursor = db_connection.cursor(dictionary=True)
    if values:
        cursor.execute(query, values)
    else:
        cursor.execute(query)
    db_connection.commit()
    cursor.close()

# Secret key for session management
app.secret_key = os.urandom(24)

def convertphotoToBinaryData(file_val):
    return file_val.read()

# Function to check if user is logged in
def is_logged_in():
    return 'logged_in' in session

@app.route('/')
def final():
    return render_template('final.html')

@app.route('/landing')
def landing():
    return render_template('landing.html')

# Route for user registration
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Fetch form data
        name = request.form['name']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Insert user into database
        execute_query("INSERT INTO users (name, email, username, password) VALUES (%s, %s, %s, %s)", (name, email, username, hashed_password))

        # Redirect to login page
        return redirect(url_for('login'))

    return render_template('signup.html')

# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Fetch form data
        username = request.form['username']
        session['username'] = username
        print("session data: ",session)
        password = request.form['password']

        # Get user by email
        cursor = db_connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        cursor.close()
        
        if(user['username']=="admin"):
                response = make_response(redirect(url_for('admin_page')))

        if user and check_password_hash(user['password'], password):
            # Generate JWT token
    
            session['logged_in'] = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            print(session)
            
            
            
            
            if(user['username']=="admin"):
                response = make_response(redirect(url_for('admin_page')))
            else: 
                access_token = create_access_token(identity=username, expires_delta=timedelta(days=7))   
                response = make_response(redirect(url_for('photos', username=username)))
                response.set_cookie('access_token_cookie', value=access_token, max_age=3600, httponly=True)
            return response
        flash("Invalid","error")    
            
            
    return render_template('login.html')

@app.route('/admin')
def admin_page():
    if 'logged_in' in session and session['logged_in'] and session['username'] == "admin":
        cursor = db_connection.cursor(dictionary=True)
        cursor.execute("SELECT username, name, email FROM users")
        users = cursor.fetchall()
        cursor.close()
        return render_template('admin.html', users=users)
    else:
        return redirect(url_for('login'))

@app.route('/photos/<username>',  methods=['GET', 'POST'])
@jwt_required()
def photos(username):
    current_user = get_jwt_identity()
    print("Current user:", current_user)
    if current_user != username:
        print("Error: Current user does not match requested user.")
        abort(403)  # Return a forbidden error (HTTP status code 403)
    return render_template('photos.html',username=username)
    
@app.route('/recieve', methods=['POST'])
def receive_array():
    print("Receiving files...")
    print(session)
    user_id = session["user_id"]
    if 'uploaded_files[]' in request.files:
        files = request.files.getlist('uploaded_files[]')
        for file in files:
            print("File received:", file.filename)
            file_data=convertphotoToBinaryData(file)
            execute_query("INSERT INTO photos (username, filename, photo) VALUES (%s, %s, %s)", (user_id, file.filename, file_data))
            print("inserted")
        return 'Files received successfully!'
    else:
        return 'No files received in the request.'
    
    
@app.route('/video/<username>', methods=['GET', 'POST'])
@jwt_required()
def re_direct(username):
    current_user = get_jwt_identity()
    print("Current user:", current_user)
    if current_user != username:
        print("Error: Current user does not match requested user.")
        abort(403)  # Return a forbidden error (HTTP status code 403)
    return render_template('video.html',username=username)
        

@app.route('/video')
@jwt_required()
def video():
    access_token_cookie = request.cookies.get('access_token_cookie')
    if access_token_cookie:
        try:
            decoded = decode_token(access_token_cookie)
            username = decoded.get('sub')
            return redirect(url_for('re_direct', username=username))
        except Exception as e:
            print("Error decoding token:", e)

    else:
        # Handle the case when the access token is missing
        return jsonify({'error': 'Access token missing'}), 401


if __name__ == '__main__':
    app.run(debug=True)