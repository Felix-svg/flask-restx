import datetime
from sqlalchemy_serializer import SerializerMixin
from config import db, bcrypt


class User(db.Model, SerializerMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(55), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String, nullable=False)
    is_verified = db.Column(db.Boolean, default=False)

    login_activities = db.relationship("LoginActivity", back_populates="user")

    serialize_rules = ("-password_hash",)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def set_username(self) -> str:
        self.username = f"@{self.username.lower()}"
        return self.username


class LoginActivity(db.Model,SerializerMixin):
    __tablename__ = "login_activities"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    successful = db.Column(db.Boolean, default=True)

    user = db.relationship("User", back_populates="login_activities")