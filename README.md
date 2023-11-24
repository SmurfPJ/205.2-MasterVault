# 205.2-MasterVault
MasterVault is a Flask-based password management application designed for secure storage and management of passwords. It features functionalities like user authentication, 
password generation, encryption, and two-factor authentication (2FA).


## Features
* **Secure Login & Registration:** Users can create accounts and log in securely.

* **Password Management:** Add, view, edit, or delete stored passwords.

* **Password Generation:** Generate strong, unique passwords based on user-defined criteria.

* **Password Strength Checker:** Evaluates the strength of passwords.

* **Two-Factor Authentication (2FA):** Enhance security with optional 2FA.

* **Account Locking:** Ability to lock accounts for specified durations.

* **Encryption:** Sensitive data is encrypted for additional security.

* **Email Notifications:** Sends emails for verification and 2FA PINs.


## Setup & Installation
1. **Clone the Repository:** Start by cloning this repository to your local machine.
   
2. **Install Dependencies:** Use **'pip install -r requirements.txt'** to install the necessary Python packages.
   
3. **Run the Application:** Execute **'python app.py'** to start the Flask server.

## Usage
* **Register:** Create a new account by providing a username, email, and password.
  
* **Login:** Access your account using your credentials.
  
* **Password Management:** Add new passwords, view saved ones, or modify existing entries.
  
* **Generate Password:** Use the built-in tool to create strong passwords.
  
* **Account Settings:** Enable/disable 2FA, lock your account, or reset your password.


## Security Features
* **Encryption:** All sensitive data is encrypted using a custom encryption method.
  
* **2FA:** Optional two-factor authentication adds an extra layer of security.
  
* **Account Locking:** Temporarily lock your account to prevent unauthorized access.

## Email Integration
* **Verification Emails:** Sent upon account creation.
  
* **2FA Emails:** Sent when 2FA is enabled, containing a PIN for verification.
   



