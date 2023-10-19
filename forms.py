from flask_wtf import FlaskForm
from wtforms import *
from wtforms.validators import DataRequired, EqualTo, Email, Length

class RegistrationForm(FlaskForm):
    username = StringField('Username',validators=[DataRequired(),Length(min=3,max=50)])
    email = EmailField('Email',validators=[DataRequired(),Email()])
    dob = DateField('Date of Birth',validators=[DataRequired()])
    password = PasswordField('Password',validators=[DataRequired()])
    confirm_password = PasswordField('Confirm password',validators=[DataRequired(),EqualTo('password')])
    submit_bn = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email',validators=[DataRequired(),Email()])
    password = PasswordField('Password',validators=[DataRequired()])
    submit_bn = SubmitField('Log in')