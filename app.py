from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import random, string, csv, os, datetime
from forms import RegistrationForm, LoginForm, ResetPasswordForm
from flask_mail import Mail, Message
from dotenv import load_dotenv
from encryption import encrypt, decrypt

#Constants
ACCOUNT_METADATA_LENGTH = 6

#Database paths
writeToLogin = open('loginInfo', 'w')

app = Flask(__name__)
mail= Mail(app)
load_dotenv()


app.config['SECRET_KEY'] = '47a9cee106fa8c2c913dd385c2be207d'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'nickidummyacc@gmail.com'
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USE_TLS'] = False
mail = Mail(app)



def generate_password(keyword, length, use_numbers, use_symbols):
    characters = string.ascii_letters  # Always use letters

    if use_numbers:
        characters += string.digits

    if use_symbols:
        characters += string.punctuation

    # Ensure the password is at least as long as the keyword
    if length < len(keyword):
        return ""

    # Add random characters to the keyword until the desired length is reached
    while len(keyword) < length:
        keyword += random.choice(characters)

    # Pattern is basically every third character from the keyword (subjected to change)
    password = ""
    for i in range(length):
        if i % 3 == 0 and i//3 < len(keyword):
            password += keyword[i//3]
        else:
            password += random.choice(characters)

    return password


def get_passwords(user):
    # Open csv file
    file = open('loginInfo.csv')
    type(file)
    csvreader = csv.reader(file)
    for csvAccount in csvreader: # Reads each account in csv
        if user == csvAccount[0]: # Checks if account matches user
            userAccounts = []
            # Splits account data into lists of size 3 (In pattern [website, email, password])
            for accountDataIdx in range(len(csvAccount) - ACCOUNT_METADATA_LENGTH):
                dataChunk = csvAccount[accountDataIdx + ACCOUNT_METADATA_LENGTH]
                if accountDataIdx % (ACCOUNT_METADATA_LENGTH) == 0:
                    userAccounts.append([])
                userAccounts[-1].append(dataChunk)
            
            userAccounts.sort(key=lambda x: x[0]) # Sorts data alphabetically by website
            return userAccounts
    return []


def check_password_strength(password):
    strength = {'status': 'Weak', 'score': 0, 'color': 'red'}

    # Check if password is None or empty and return weak strength immediately
    if not password:
        return strength

    if len(password) >= 8:
        strength['score'] += 1

    if any(char.isdigit() for char in password):
        strength['score'] += 1

    if any(char.isupper() for char in password):
        strength['score'] += 1

    if any(char in string.punctuation for char in password):
        strength['score'] += 1

    # Update status and color based on score
    if strength['score'] == 4:
        strength['status'] = 'Very Strong'
        strength['color'] = 'green'
    elif strength['score'] == 3:
        strength['status'] = 'Strong'
        strength['color'] = 'lightgreen'
    elif strength['score'] == 2:
        strength['status'] = 'Moderate'
        strength['color'] = 'orange'
    elif strength['score'] == 1:
        strength['status'] = 'Weak'
        strength['color'] = 'red'

    return strength



@app.route('/create_password', methods=['GET', 'POST'])
def create_password():
    password = ""
    strength = None
    error = None
    keyword = ""
    length = 8  # Default length
    use_numbers = False
    use_symbols = False

    if request.method == 'POST':
        keyword = request.form.get('keyword')
        length = int(request.form.get('length'))
        use_numbers = 'numbers' in request.form
        use_symbols = 'symbols' in request.form

        # Validate options
        if not use_numbers and not use_symbols:
            error = "Please select at least one option: Use Numbers or Use Symbols."
        else:
            password = generate_password(keyword, length, use_numbers, use_symbols)
            strength = check_password_strength(password)
            if not password:
                error = "Failed to generate password. Ensure the keyword is shorter than the desired password length."

        return render_template('createPassword.html', password=password, strength=strength, error=error, keyword=keyword, length=length, use_numbers=use_numbers, use_symbols=use_symbols)

    return render_template('createPassword.html', password=password, keyword=keyword, length=length, use_numbers=use_numbers, use_symbols=use_symbols)


@app.route('/')
def base():  # put application's code here
    return render_template('base.html')

# will be deleting the base html as an app route once other pages are set up

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Initialize email and password variables
        email = None
        password = None

        # Check if the request is JSON (from the extension)
        if request.is_json:
            data = request.get_json()
            email = data.get('email')
            password = data.get('password')
        else:
            # Handle form submission (from the web app)
            cform = LoginForm()
            if cform.validate_on_submit():
                email = cform.email.data
                password = cform.password.data
            else:
                return render_template("login.html", form=cform)

        # Ensure that email and password are not None
        if email is not None and password is not None:
            # Common login logic for both extension and web app
            with open('loginInfo.csv', 'r') as file:
                csvreader = csv.reader(file)
                for account in csvreader:
                    # Pad the account list to ensure it has at least 5 elements
                    padded_account = account + [None] * (5 - len(account))

                    username, account_email, dob, account_password, _ = padded_account

                    if email == account_email and password == account_password:
                        if request.is_json:
                            # JSON response for the extension
                            return jsonify({"status": "success", "username": username, "email": email})
                        else:
                            # Handle session and redirect for web app
                            session['username'] = username
                            session['email'] = email
                            return redirect(url_for('settings'))

        # Handle invalid email or password
        error_message = "Invalid email or password"
        if request.is_json:
            return jsonify({"status": "failure", "message": error_message}), 401
        else:
            flash(error_message)
            return render_template("login.html", form=cform)

    return render_template("login.html", form=LoginForm())



@app.route('/logout')
def logout():
    # Clear the user's session
    session.clear()

    return redirect(url_for('login'))

def send_2fa_verification_email(email, pin):
    msg = Message("Your MasterVault 2FA PIN",
                  sender='nickidummyacc@gmail.com',
                  recipients=[email])
    msg.body = f'Your 2FA verification PIN is: {pin}'
    mail.send(msg)

def send_verification_email(email):
    msg = Message("Welcome to MasterVault",
                  sender='nickidummyacc@gmail.com',
                  recipients=[email])
    msg.body = 'Hello, your account has been registered successfully! Thank you for using MasterVault. (This is a test program for a college project)'
    mail.send(msg)



@app.route('/register', methods=['GET', 'POST'])
def register():
    cform = RegistrationForm()
    if cform.validate_on_submit():
        with open('loginInfo.csv', 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([cform.username.data, cform.email.data, cform.dob.data, cform.password.data])

            # Send verification email after successfully saving account details
            send_verification_email(cform.email.data)

            flash('Account created successfully! An email will be sent to you .', 'success')
            return redirect(url_for('login'))
    return render_template("register.html", form=cform)


@app.route('/master_password_setup', methods=['GET', 'POST'])
def master_password():
    return render_template('masterPassword.html')


@app.route('/resetPassword', methods=['GET', 'POST'])
def resetPassword():
    return render_template('resetPassword.html')


@app.route('/settings', methods=['GET'])
def settings():
    return render_template('settings.html')

# Temporary storage for 2FA codes
temporary_2fa_storage = {}

@app.route('/enable_2fa', methods=['POST'])
def enable_2fa():
    user_email = request.json.get('email')
    update_2fa_status(user_email, True)
    return jsonify({'message': '2FA has been enabled'}), 200

@app.route('/disable_2fa', methods=['POST'])
def disable_2fa():
    user_email = request.json.get('email')
    update_2fa_status(user_email, False)
    return jsonify({'message': '2FA has been disabled'}), 200

def update_2fa_status(email, status):
    updated = False
    data = []
    status_string = 'Enabled' if status else 'Disabled'

    with open('loginInfo.csv', 'r', newline='') as file:
        csvreader = csv.reader(file)
        for row in csvreader:
            if row and row[1] == email:
                if len(row) >= 5:  # Check if the 2FA status column exists
                    row[4] = status_string  # Update the 2FA status
                else:
                    row.append(status_string)  # Append the 2FA status
                updated = True
            data.append(row)

    if updated:
        with open('loginInfo.csv', 'w', newline='') as file:
            csvwriter = csv.writer(file)
            csvwriter.writerows(data)

    return updated

@app.route('/get_2fa_status')
def get_2fa_status():
    if 'username' in session:
        user = get_user_by_username(session['username'])

        two_fa_status = user['2fa_enabled'] == 'Enabled'
        return jsonify({'2fa_enabled': two_fa_status})
    else:
        return jsonify({'error': 'User not logged in'}), 401

def get_user_by_username(username):
    with open('loginInfo.csv', 'r', newline='') as file:
        csvreader = csv.reader(file)
        for row in csvreader:
            if row and row[0] == username:
                # Convert row to dict
                user = {
                    'username': row[0],
                    'email': row[1],
                    'dob': row[2],
                    'password': row[3],
                    '2fa_enabled': row[4] if len(row) > 4 else 'Disabled'
                }
                return user


@app.route('/setup_2fa', methods=['POST'])
def setup_2fa():
    user_email = request.json.get('email')
    pin = random.randint(1000, 9999)
    send_2fa_verification_email(user_email, pin)
    store_pin(user_email, pin)
    return jsonify({'message': 'A 2FA PIN has been sent to your email'}), 200

@app.route('/verify_2fa', methods=['POST'])
def verify_2fa():
    data = request.get_json()
    print("Received data:", data)  # Log received data

    if not data or 'email' not in data or 'pin' not in data:
        return jsonify({'message': 'Email and PIN are required'}), 400

    user_email = data['email']
    entered_pin = data['pin']
    print("Email:", user_email, "Entered PIN:", entered_pin)  # Log specifics

    if is_valid_pin(user_email, entered_pin):
        return jsonify({'message': '2FA verification successful!'}), 200
    else:
        return jsonify({'message': 'Invalid or expired PIN'}), 400
    
@app.route('/passwordList', methods=['GET'])
def passwordList():
    # Check if the user is logged in
    if 'username' in session:
        # Get the username from the session
        username = session['username']

        # Call the get_passwords function to retrieve the passwords associated with the user
        user_passwords = get_passwords(username)

        # Render an HTML table to display the passwords
        return render_template('passwordList.html', passwords=user_passwords)
    else:
        # Redirect to the login page if the user is not logged in
        flash('Please log in to access your passwords.', 'warning')
        return redirect(url_for('login'))

@app.route('/passwordView/<website>/<email>/<password>', methods=['GET', 'POST'])
def passwordView(website, email, password):
    return render_template('passwordView.html', website=website, email=email, password=password)

def send_2fa_verification_email(email, pin):
    msg = Message("Your MasterVault 2FA PIN",
                  sender='nickidummyacc@gmail.com',
                  recipients=[email])
    msg.body = f'Your 2FA verification PIN is: {pin}, Please note this code is only valid for 10 minutes.'
    mail.send(msg)

def store_pin(email, pin):
    temporary_2fa_storage[email] = {
        'pin': pin, 'timestamp': datetime.datetime.now()
    }

def is_valid_pin(email, entered_pin):
    pin_data = temporary_2fa_storage.get(email)
    print("Stored PIN data for", email, ":", pin_data)  # Log stored PIN data

    if pin_data and str(pin_data['pin']) == str(entered_pin):
        time_diff = datetime.datetime.now() - pin_data['timestamp']
        if time_diff.total_seconds() <= 600:  # 10 minutes validity
            return True
    return False

if __name__ == '__main__':
    app.run(debug=True)