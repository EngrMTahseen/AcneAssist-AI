from flask import Flask, request, render_template, redirect, session, jsonify, url_for,flash
from flask_sqlalchemy import SQLAlchemy
import yagmail, random, string
import pickle
import json, os
from googleplaces import GooglePlaces, types, lang
from sqlalchemy.exc import IntegrityError
import bcrypt
from werkzeug.utils import secure_filename
import torch
from PIL import Image
import numpy as np
import shutil
from pathlib import Path

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
app.secret_key = 'secret_key'
API_KEY = 'AIzaSyBNpBnIkQqo5O1mtneHUBQt2q5PN3p9lao'
google_places = GooglePlaces(API_KEY)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['RESULT_FOLDER'] = 'static/results'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

    def __init__(self, email, password, name):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        new_password = request.form['new_password']

        # Validate input
        if not email or not new_password:
            flash('Email and new password are required!', 'error')
            return redirect(url_for('reset_password'))

        # Check if the email exists
        user = User.query.filter_by(email=email).first()

        if user is None:
            flash('Email not found!', 'error')
            return redirect(url_for('reset_password'))

        # Hash the new password
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Update the user's password
        user.password = hashed_password
        db.session.commit()

        flash('Password updated successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html')

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

    def __init__(self, email, password):
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))


with app.app_context():
    db.create_all()

    # Seed the database with an initial admin
    if not Admin.query.filter_by(email='testemail007219@gmail.com').first():
        admin = Admin(email='testemail007219@gmail.com', password='12345')
        db.session.add(admin)
        db.session.commit()


@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        admin = Admin.query.filter_by(email=email).first()
        if admin and admin.check_password(password):
            session['admin_email'] = admin.email
            return redirect('/admin_dashboard')
        else:
            return render_template('admin_login.html', error='Invalid credentials')
    return render_template('admin_login.html')


@app.route('/admin_dashboard')
def admin_dashboard():
    if 'admin_email' not in session:
        return redirect('/admin_login')
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

@app.route('/')
def index():
    return render_template('index.html')


# Add this constant for OTP length
OTP_LENGTH = 6


# Function to generate OTP
def generate_otp():
    otp = ''.join(random.choices(string.digits, k=OTP_LENGTH))
    return otp


# Function to send OTP via email
def send_otp_email(email, otp):
    # Replace 'your_email' and 'your_password' with your actual email credentials
    yag = yagmail.SMTP('sanamkhattak00000@gmail.com', 'ptfhtegmqnblwymz')
    yag.send(to=email, subject='OTP Verification', contents=f'Your OTP is: {otp}')


# Route to resend OTP
@app.route('/resend_otp', methods=['POST'])
def resend_otp():
    email = request.form.get('email')
    if email:
        # Generate new OTP
        otp = generate_otp()

        # Expire the old OTP
        session.pop('otp', None)

        # Store new OTP in session
        session['otp'] = otp

        # Send new OTP via email
        send_otp_email(email, otp)

    # Redirect back to the OTP verification page
    return redirect('/verify_otp')


# Modify your registration route to include OTP verification
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # Generate OTP
        otp = generate_otp()

        # Send OTP via email
        send_otp_email(email, otp)

        # Store OTP in session
        session['otp'] = otp
        session['name'] = name
        session['email'] = email
        session['password'] = password

        # Redirect to OTP verification page
        return redirect('/verify_otp')

    return render_template('register.html')


# Route for OTP verification
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        user_otp = request.form['otp']
        stored_otp = session.get('otp')

        if user_otp == stored_otp:
            # If OTP matches, save user data to the database
            name = session.get('name')
            email = session.get('email')
            password = session.get('password')

            try:
                new_user = User(name=name, email=email, password=password)
                db.session.add(new_user)
                db.session.commit()

                # Clear session data after successful registration
                session.pop('otp')
                session.pop('name')
                session.pop('email')
                session.pop('password')

                return render_template('otp.html', success=True)
            except IntegrityError:
                # If email already exists, redirect to the email_registered page
                return render_template('/email_registered.html')

        else:
            return render_template('otp.html', error='Invalid OTP')

    return render_template('otp.html')


@app.route("/dashboard")
def dashboard():
    return render_template("base.html", content="Testing")

@app.route("/contact")
def contact():
    return render_template("whatsapp.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session['email'] = user.email
            return redirect('/dashboard')
        else:
            return render_template('login.html', error='Invalid user')

    return render_template('login.html')


@app.route('/submit', methods=['POST'])
def submit_form():
    try:
        # Retrieve form data
        data = {
            "Full Name": request.form['full_name'],
            "Date of Birth": request.form['dob'],
            "Email": request.form['email'],
            "Phone Number": request.form['phone'],
            "Address": request.form['address'],
            "City": request.form['city'],
            "State": request.form['state'],
            "Postal Code": request.form['postal_code'],
            "Blood Group": request.form['blood_group'],
            "Blood Pressure": request.form['blood_pressure'],
            "Insurance Provider": request.form['insurance_provider'],
            "Insurance Policy Number": request.form['insurance_policy_number'],
            "Medical History": request.form['medical_history'],
            "Gender": request.form['gender']
        }

        # Save data to JSON file
        json_filename = 'medical_registration.json'
        with open(json_filename, 'w') as json_file:
            json.dump(data, json_file)

        # Send email with attachment using yagmail
        doctor_email = 'rajausamagull123@gmail.com'
        yag = yagmail.SMTP('sanamkhattak00000@gmail.com', 'ptfhtegmqnblwymz')
        yag.send(
            to=doctor_email,
            subject="New Medical Registration Form Submission",
            contents="Please find attached a new medical registration form submission.",
            attachments=json_filename
        )

        return jsonify({'status': 'success', 'message': 'Form submitted successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/nearby_hospitals', methods=['GET'])
def nearby_hospitals():
    lat = request.args.get('lat')
    lng = request.args.get('lng')
    radius = request.args.get('radius', 1000)  # Default radius

    if not lat or not lng:
        return render_template('NBH.html', error='Location not provided')

    # Perform the nearby search
    query_result = google_places.nearby_search(
        lat_lng={'lat': float(lat), 'lng': float(lng)},
        radius=int(radius),
        types=[types.TYPE_HOSPITAL]
    )

    hospitals = []
    for place in query_result.places:
        place.get_details()
        hospitals.append({
            'name': place.name,
            'lat': place.geo_location['lat'],
            'lng': place.geo_location['lng'],
            'address': place.formatted_address
        })

    return render_template('NBH.html', hospitals=hospitals)

@app.route("/medical")
def medical():
    return render_template("medical_form.html")


@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect('/login')



@app.route('/appointment')
def appointment():
    return render_template('appointment.html')


UPLOAD_FOLDER = 'static/uploads/'
RESULT_FOLDER = 'static/results/'

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['RESULT_FOLDER'] = RESULT_FOLDER

# Ensure the directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULT_FOLDER, exist_ok=True)

# Load your model here
model_path = os.path.join('static', 'models', 'last.pt')
model = torch.hub.load('computervisioneng/yolov9', 'custom', path=model_path)

def detect_acne(image_path):
    img = Image.open(image_path).convert('RGB')
    img = np.array(img)
    results = model(img)

    # Always save as image0.jpg
    result_image_path = os.path.join(app.config['RESULT_FOLDER'], 'image0.jpg')
    results._run(save=True, save_dir=Path(app.config['RESULT_FOLDER']))

    # Extract class names and counts
    results_df = results.pandas().xyxy[0]  # Pandas DataFrame of detections
    class_counts = results_df['name'].value_counts().to_dict()  # Counts of each class

    return 'image0.jpg', class_counts

@app.route('/home', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)

        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            result_image_filename, class_counts = detect_acne(file_path)

            return render_template('home.html', uploaded_image=filename, result_image=result_image_filename, class_counts=class_counts)

    return render_template('home.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0',debug=True)

