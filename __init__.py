from flask import Flask, Blueprint
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
#from flask_login_multi.login_manager import LoginManager
from flask_login import LoginManager
from flask_admin import Admin
from flask_mail import Mail
from webapp.config import Config
from flask_migrate import Migrate
from flask_moment import Moment



db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
login_manager.login_view = 'users.login'

migrate = Migrate()
moment = Moment()

admin = Admin()
# Add administrative views here



login_manager.login_message_category = "info"

mail = Mail()



def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(Config)
    
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    admin.init_app(app)
    migrate.init_app(app, db)
    moment.init_app(app)
    
    with app.app_context():
            
        from webapp.myadmin.admin import myadmin
        from webapp.users.routes import users
        from webapp.posts.routes import posts
        from webapp.main.routes import main
        from webapp.errors.handlers import errors
        from .models import Permission

        #admin_app = Blueprint('admin', __name__, url_prefix="/admin")  
        #user_app = Blueprint('user', __name__, url_prefix="/user")

        app.register_blueprint(myadmin)
        app.register_blueprint(users)
        app.register_blueprint(posts)
        app.register_blueprint(main)
        app.register_blueprint(errors)
        


        #db.create_all()

        return app


'''

login_manager.blueprint_login_views = {
    'association': "users.login",
    'scholar': "users.loginScholar",
    'individual': "users.loginIndividual"
}



admin_app = Blueprint('admin', __name__, url_prefix="/admin")  
'''