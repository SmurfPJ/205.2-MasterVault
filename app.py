from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)


@app.route('/')
def base():  # put application's code here
    return render_template('base.html')

# will be deleting the base html as an app route once other pages are set up

@app.route('/login', methods=['GET', 'POST'])
def login():
    return render_template('login.html')

@app.route('/register', methods=['GET','POST'])
def register():
    return render_template('register.html')

@app.route('/master_password_setup', methods=['GET', 'POST'])
def master_password():
    return render_template('masterPassword.html')

@app.route('/settings', methods=['GET'])
def settings():
    return render_template('settings.html')



if __name__ == '__main__':
    app.run(debug=True)
