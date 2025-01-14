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
app.json.compact = False

metadata = MetaData()
db = SQLAlchemy(metadata=metadata)

migrate = Migrate(app, db)
db.init_app(app)

jwt = JWTManager(app)
bcrypt = Bcrypt(app)
api = Api(app)
