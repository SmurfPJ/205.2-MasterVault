from flask import Flask, render_template, request, redirect, url_for, session, flash
import random
import string
from forms import RegistrationForm, LoginForm
import csv

#Database paths
writeToLogin = open('loginInfo', 'w')

app = Flask(__name__)
app.config['SECRET_KEY'] = '47a9cee106fa8c2c913dd385c2be207d'


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
    cform = LoginForm()
    if cform.validate_on_submit():
        with open('loginInfo.csv', 'r') as file:
            csvreader = csv.reader(file)
            for account in csvreader:
                username, email, _, password = account
                if cform.email.data == email and cform.password.data == password:
                    session['username'] = username
                    session['email'] = email
                    return redirect(url_for('settings'))
            flash('Invalid email or password!')
    return render_template("login.html", form=cform)

@app.route('/logout')
def logout():
    # Clear the user's session
    session.clear()

    return redirect(url_for('login'))


@app.route('/register', methods=['GET','POST'])
def register():
    cform = RegistrationForm()
    if cform.validate_on_submit(): # Checks if all data is valid
        with open('loginInfo.csv', 'a', newline='') as file: # Saves data to csv
            writer = csv.writer(file)
            writer.writerow([cform.username.data, cform.email.data, cform.dob.data, cform.password.data])
            flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    return render_template("register.html", form=cform)


@app.route('/master_password_setup', methods=['GET', 'POST'])
def master_password():
    return render_template('masterPassword.html')


@app.route('/settings', methods=['GET'])
def settings():
    return render_template('settings.html')


if __name__ == '__main__':
    app.run(debug=True)