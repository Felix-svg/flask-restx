from datetime import timedelta
from sqlalchemy import MetaData
from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_restx import Api
from flask_jwt_extended import JWTManager

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = "FGHHS3FSGT337I3SKSYUI3O"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["JWT_BLACKLIST_ENABLED"] = True
app.config["JWT_COOKIE_SECURE"] = True
app.config["JWT_COOKIE_SAMESITE"] = "Lax"
app.config["JWT_COOKIE_HTTPONLY"] = True

app.json.compact = False

metadata = MetaData()
db = SQLAlchemy(metadata=metadata)

migrate = Migrate(app, db)
db.init_app(app)

jwt = JWTManager(app)
bcrypt = Bcrypt(app)
api = Api(app)

blacklist = set()
