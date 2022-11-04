#all imports
from wtforms import (
    StringField,
    PasswordField,
    BooleanField,
    IntegerField,
    DateField,
    TextAreaField,
)

from flask_wtf import FlaskForm
from wtforms.validators import InputRequired, Length, EqualTo, Email, Regexp ,Optional
from flask_login import current_user
from wtforms import ValidationError,validators



class login_form(FlaskForm):
    '''creates a login form'''
    email = StringField(validators=[InputRequired(), Email(), Length(1, 64)])
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=72)])
    # Placeholder labels to enable form rendering
    username = StringField(
        validators=[Optional()]
    )


class register_form(FlaskForm):
    '''creates a register form'''
    username = StringField(
        validators=[
            InputRequired(),
            Length(3, 25, message="Please provide a valid name"),
            Regexp(
                "^[A-Za-z][A-Za-z0-9_.]*$",
                0,
                "Usernames must have only letters, " "numbers, dots or underscores",
            ),
        ]
    )
    email = StringField(validators=[InputRequired(), Email(), Length(1, 64)])
    password = PasswordField(validators=[InputRequired(), Length(8, 72)])
    confirm_password = PasswordField(
        validators=[
            InputRequired(),
            Length(8, 72),
            EqualTo("password", message="Passwords must match !"),
        ]
    )
