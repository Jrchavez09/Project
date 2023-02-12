from flask import Blueprint, render_template, flash, redirect, url_for
from flask_login import login_user, logout_user, login_required

from inner_air import db
from inner_air.models import User
from inner_air.user.forms import LoginForm, RegistrationForm

user_bp = Blueprint('user', __name__)


@user_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.query(User).filter_by(email=form.email.data).first()
        if user and user.verify_password(attempted_password=form.password.data):
            login_user(user)
            flash(f'Success! You are logged in as: { user.firstname }', category='success')
            return redirect(url_for('profile.profile'))
        else:
            flash('You have entered an invalid email address or password.', category='danger')
    return render_template('user/login.html', form=form)


@user_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            firstname=form.firstname.data,
            email=form.email.data,
            password=form.password.data
        )

        if db.session.query(User).filter_by(email=form.email.data).first() is None:
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash(f'Account created successfully for {form.firstname.data}', category='success')
            flash('A confirmation email has been sent via email.', category='success')
            return redirect(url_for('profile.profile'))
        else:
            flash('This email already exists. Try logging in, or register with a different email', category='danger')
    return render_template('user/register.html', form=form)

@user_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('you\'ve been logged out', category='info')
    return redirect(url_for('main.home'))