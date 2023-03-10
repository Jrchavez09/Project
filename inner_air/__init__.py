from flask import Flask
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager


app = Flask(__name__)
DB_NAME = 'inner-air.db'

app.config['SECRET_KEY'] = '`5J<-lgHQaae_|LR*h)0%}`#k?sW@IK],P-9,A/}d`Ly&GwruSUh#omM]AdXwNP'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

"""                                                                                                            
    mail settings                                                                                              

    IMPORTANT:                                                                                                 
        Please, the email below was only created for testing purposes. Normally, I wouldn't store the information                                                                                                               
        here. So please if you decide to change it, and use your own, before uploading it to Github remove your email                                                                                                           
        and password.                                                                                          

    note:                                                                                                      
        I plan on changing this in the future.                                                                 
"""
app.config['MAIL_DEFAULT_SENDER'] = 'c626521@gmail.com'
app.config['SECURITY_PASSWORD_SALT'] = 'a56ad0d9ed8e7ed487f2939f1d161e27'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'c626521@gmail.com'
app.config['MAIL_PASSWORD'] = 'nlamndkhhwpitmjz'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

login_manager = LoginManager()
login_manager.init_app(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)

"""
    registering blueprints
"""
from inner_air.main.routes import main_bp
from inner_air.user.routes import user_bp
from inner_air.profile.routes import profile_bp
from inner_air.exercises.routes import exercises_bp
from inner_air.user_list.routes import userlist_bp

app.register_blueprint(main_bp)
app.register_blueprint(user_bp)
app.register_blueprint(profile_bp)
app.register_blueprint(exercises_bp)
app.register_blueprint(userlist_bp)

"""
    flask-login
"""
login_manager.login_view = 'user.login'

"""
    DB creation
"""
from inner_air import setup
