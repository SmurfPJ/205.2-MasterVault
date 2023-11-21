from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import random, string, csv, os, datetime
from forms import RegistrationForm, LoginForm
from flask_mail import Mail, Message
from dotenv import load_dotenv
from encryption import encrypt, decrypt
from datetime import datetime
import datetime

#Constants
ACCOUNT_METADATA_LENGTH = 3


# Encrypt data
# def encryptData():

#     file = open('userData.csv')
#     type(file)
#     csvreader = csv.reader(file)
#     for csvAccount in csvreader:
#         for accountDataIdx in range(len(csvAccount) - 1):
#                 dataChunk = csvAccount[accountDataIdx + 1]

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

    # Add random characters to the keyword until desired length is reached
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
    file = open('userData.csv')
    type(file)
    csvreader = csv.reader(file)
    for csvAccount in csvreader: # Reads each account in csv
        if user == csvAccount[0]: # Checks if account matches user
            userAccounts = []
            # Splits account data into lists of size 3 (In pattern [website, email, password])
            for accountDataIdx in range(len(csvAccount) - 1):
                dataChunk = csvAccount[accountDataIdx + 1]
                dataChunk
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
            with open('loginInfo.csv', 'r') as file:
                csvreader = csv.reader(file)
                for account in csvreader:
                    # Ensure account has enough fields
                    padded_account = account + [None] * (9 - len(account))
                    username, account_email, dob, account_password, _2fa_status, master_password_set, lock_state, lock_duration, lock_timestamp = padded_account

                    dob = dob
                    _2fa_status = _2fa_status

                    if email == account_email and password == account_password:
                        if request.is_json:
                            # JSON response for the extension
                            return jsonify({"status": "success", "username": username, "email": email})
                        else:
                            # Handle session for web app
                            session['username'] = username
                            session['email'] = email

                            # Check if master password is set
                            if not master_password_set or master_password_set.lower() == 'false':
                                return redirect(url_for('master_password'))

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
            writer.writerow([
                cform.username.data,
                cform.email.data,
                cform.dob.data,
                cform.password.data,
                'empty']) # Default 2FA status

            # Send verification email after successfully saving account details
            send_verification_email(cform.email.data)

            flash('Account created successfully! An email will be sent to you.', 'success')
            return redirect(url_for('login'))
    return render_template("register.html", form=cform)


@app.route('/master_password', methods=['GET', 'POST'])
def master_password():
    if request.method == 'POST':
        master_password = request.form['master_password']
        master_password
        email = session['email']

        # Save the master password to the user's account
        save_master_password(email, master_password)

        # Flash a success message
        flash('Master password set up successfully!', 'success')

        return redirect(url_for('passwordList'))

    return render_template('masterPassword.html')

def save_master_password(email, master_password):
    data = []
    updated = False
    with open('loginInfo.csv', 'r', newline='') as file:
        csvreader = csv.reader(file)
        for row in csvreader:
            if row and row[1] == email:
                if len(row) < 6:
                    row.append(master_password)
                else:
                    row[5] = master_password
                updated = True
            data.append(row)

    if updated:
        with open('loginInfo.csv', 'w', newline='') as file:
            csvwriter = csv.writer(file)
            csvwriter.writerows(data)

@app.route('/addPassword', methods=['GET', 'POST'])
def addPassword():
    if request.method == 'POST':
        username = session['username']
        website = request.form['website']
        email = request.form['email']
        password = request.form['password']

        saveNewPassword(username, website, email, password)

        return redirect(url_for('passwordList'))

    return render_template('addPassword.html')

def saveNewPassword(username, website, email, password):
    data = []
    updated = False

    with open('userData.csv', 'r', newline='') as file:
        csvreader = csv.reader(file)
        for row in csvreader:
            if row and row[0] == username:
                if len(row) % 3 == 1:
                    row.extend([website, email, password])
                else:
                    row[-3:] = [website, email, password]
                updated = True
            data.append(row)

    if not updated:
        data.append([username, website, email, password])

    with open('userData.csv', 'w', newline='') as file:
        csvwriter = csv.writer(file)
        csvwriter.writerows(data)

@app.route('/passwordView/<website>/<email>/<password>', methods=['GET', 'POST'])
def passwordView(website, email, password):
    if request.method == 'POST':
        # print("Data received:")
        # print("Website:", request.form['website'])
        # print("Email:", request.form['email'])
        # print("Password:", request.form['password'])
        username = session['username']
        newWebsite = request.form['website']
        newEmail = request.form['email']
        newPassword = request.form['password']
        saveChanges(username, website, email, password, newWebsite, newEmail, newPassword)
        return redirect(url_for('passwordList'))
    return render_template('passwordView.html', website=website, email=email, password=password)


def saveChanges(username, old_website, old_email, old_password, new_website, new_email, new_password):
    data = []
    with open('userData.csv', 'r', newline='') as file:
        csvreader = csv.reader(file)
        for row in csvreader:
            if row and row[0] == username:
                for webIdx in range(int((len(row) - 1) / 3)):
                    if row[webIdx * 3 + 1] == old_website and row[webIdx * 3 + 2] == old_email and row[webIdx * 3 + 3] == old_password:
                        row[webIdx * 3 + 1] = new_website
                        row[webIdx * 3 + 2] = new_email
                        row[webIdx * 3 + 3] = new_password
            data.append(row)

    with open('userData.csv', 'w', newline='') as file:
        csvwriter = csv.writer(file)
        csvwriter.writerows(data)

    # print(data)


@app.route('/resetPassword', methods=['GET', 'POST'])
def resetPassword():
    if request.method == 'POST':
        master_password = request.form['newPassword']
        username = session['username']

        resetPassword(username, master_password)

        return redirect(url_for('passwordList'))

    return render_template('resetPassword.html')

def resetPassword(username, newPassword):
    data = []
    updated = False
    with open('loginInfo.csv', 'r', newline='') as file:
        csvreader = csv.reader(file)
        for row in csvreader:
            if row and row[0] == username:
                if len(row) < 6:
                    row.append(newPassword)
                else:
                    row[3] = newPassword
                updated = True
            data.append(row)

    if updated:
        with open('loginInfo.csv', 'w', newline='') as file:
            csvwriter = csv.writer(file)
            csvwriter.writerows(data)


@app.route('/passwordList', methods=['GET'])
def passwordList():
    # Check if the user is logged in
    if 'username' in session:
        # Get the username from the session
        username = session['username']
        user_passwords = get_passwords(username)
        return render_template('passwordList.html', passwords=user_passwords)
    
    else:
        # Redirect to the login page if the user is not logged in
        flash('Please log in to access your passwords.', 'warning')
        return redirect(url_for('login'))

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


@app.route('/lock_account', methods=['POST'])
def lock_account():
    data = request.get_json()
    email = session.get('email')
    lock_duration = data.get('lockDuration')
    success = lock_account_in_csv(email, lock_duration)  # function to lock the account

    if success:
        # Store lock state in the session
        session['lock_state'] = 'locked'
        session['unlock_time'] = datetime.datetime.now() + datetime.timedelta(minutes=int(lock_duration))
        return jsonify({'status': 'success', 'message': 'Account locked'})
    else:
        return jsonify({'status': 'error', 'message': 'Failed to lock account'})


@app.route('/check_lock', methods=['GET'])
def check_lock():
    email = session.get('email')
    lock_state, unlock_timestamp = get_lock_state_from_csv(email)
    current_time = datetime.now()

    # Check if there's an unlock timestamp and convert it to a datetime object
    if unlock_timestamp:
        unlock_time = datetime.strptime(unlock_timestamp, '%Y-%m-%d %H:%M:%S')
    else:
        unlock_time = None

    if lock_state == 'Locked' and unlock_time and current_time < unlock_time:
        return jsonify({'locked': True, 'unlock_time': unlock_time.strftime('%Y-%m-%d %H:%M:%S')})
    else:
        update_lock_state_in_csv(email, 'Unlocked')
        return jsonify({'locked': False})

def get_lock_state_from_csv(email):
    with open('loginInfo.csv', 'r', newline='') as file:
        csvreader = csv.reader(file)
        for row in csvreader:
            if row and row[1] == email:
                return row[6], row[7]  # Return the lock state and lock duration
    return 'Unlocked', 'empty'  # Default to 'Unlocked' if not found

def update_lock_state_in_csv(email, lock_state, lock_duration='empty', timestamp='empty'):
    data = []
    updated = False
    with open('loginInfo.csv', 'r', newline='') as file:
        csvreader = csv.reader(file)
        for row in csvreader:
            if row and row[1] == email:
                row[6] = lock_state
                row[7] = lock_duration
                row[8] = timestamp
                updated = True
            data.append(row)

    if updated:
        with open('loginInfo.csv', 'w', newline='') as file:
            csvwriter = csv.writer(file)
            csvwriter.writerows(data)
    return updated



@app.route('/unlock_account', methods=['POST'])
def unlock_account():
    data = request.get_json()
    email = session.get('email')  # assuming you store email in session upon login
    master_password = data.get('master_password')

    # check master password and update lock status in CSV
    success = verify_and_unlock_account(email, master_password)

    if success:
        # Clear lock state from the session
        session.pop('lock_state', None)
        session.pop('unlock_time', None)
        return jsonify({'status': 'success', 'message': 'Account unlocked'})
    else:
        return jsonify({'status': 'error', 'message': 'Incorrect master password'}), 401


def verify_and_unlock_account(email, master_password):
    data = []
    unlocked = False

    with open('loginInfo.csv', 'r', newline='') as file:
        csvreader = csv.reader(file)
        for row in csvreader:
            if row and row[1] == email:

                if row[5] == master_password:
                    unlocked = True
                    row[6] = 'Unlocked'
                    row[7] = 'empty'     # Set lock duration to 'empty'
                    row[8] = 'empty'     # Set lock timestamp to 'empty'
            data.append(row)

    # Rewrite the CSV file with the updated data
    if unlocked:
        with open('loginInfo.csv', 'w', newline='') as file:
            csvwriter = csv.writer(file)
            csvwriter.writerows(data)

    return unlocked



def lock_account_in_csv(email, lock_duration):
    data = []
    locked = False
    lock_duration_in_minutes = int(lock_duration) * 10  # Convert lock duration to minutes

    with open('loginInfo.csv', 'r', newline='') as file:
        csvreader = csv.reader(file)
        for row in csvreader:
            if row and row[1] == email:
                locked = True
                current_timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                if len(row) >= 9:  # Check if row has enough elements
                    row[6] = 'Locked'
                    row[7] = str(lock_duration_in_minutes)
                    row[8] = current_timestamp
                else:

                    row += ['Locked', str(lock_duration_in_minutes), current_timestamp]
            data.append(row)

    # Rewrite the CSV file with the updated data
    if locked:
        with open('loginInfo.csv', 'w', newline='') as file:
            csvwriter = csv.writer(file)
            csvwriter.writerows(data)

    return locked

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

@app.route('/delete_account', methods=['POST'])
def delete_account():
    # Check if the user is authenticated
    if 'email' not in session:
        return jsonify({"success": False, "message": "User not logged in."}), 401

    email = session['email']

    # Initialize variables
    data = []
    account_deleted = False

    with open('loginInfo.csv', 'r', newline='') as file:
        csvreader = csv.reader(file)
        for row in csvreader:
            if row[1] != email:
                data.append(row)
            else:
                account_deleted = True

        # Write the updated data back to the CSV file
    if account_deleted:
        with open('loginInfo.csv', 'w', newline='') as file:
            csvwriter = csv.writer(file)
            csvwriter.writerows(data)

        # Clear the user's session and log them out
        session.pop('email', None)
        session.pop('username', None)

        return jsonify({"success": True, "message": "Account successfully deleted."})
    else:
        return jsonify({"success": False, "message": "Account not found."})



if __name__ == '__main__':
    app.run(debug=True)