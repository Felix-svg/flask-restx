import re
from flask_restx import Resource
from flask import request
from models import User
from config import db, api


PASSWORD_REGEX = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
)


def is_strong_password(password):
    return re.match(PASSWORD_REGEX, password) is not None


@api.route("/index")
class Index(Resource):
    def get(self):
        return {"message": "Flask-RESTx API"}, 200


@api.route("/api/users")
class Users(Resource):
    def get(self):
        try:
            users = [user.to_dict() for user in User.query.all()]
            return users, 200
        except Exception as e:
            return {"error": "Internal Server Error: " + str(e)}, 500

    def post(self):
        try:
            data = request.get_json()

            if not data:
                return {"error": "No user data provided"}, 400

            username = data.get("username")
            email = data.get("email")
            password = data.get("password")

            if not username or not email or not password:
                return {"error": "Missing required fields"}, 400

            username_exists = User.query.filter(User.username == username).first()
            if username_exists is not None:
                return {"message": "Username already taken"}, 409

            email_exists = User.query.filter(User.email == email).first()
            if email_exists is not None:
                return {"message": "Email already taken"}, 409

            if not is_strong_password(password):
                return {
                    "error": "Password must be at least 8 characters long, "
                    "contain both uppercase and lowercase letters, "
                    "include at least one numerical digit, and "
                    "contain at least one special character"
                }, 400

            new_user = User(username=username, email=email)
            new_user.set_username()
            new_user.set_password(password)

            db.session.add(new_user)
            db.session.commit()

            return {"message": "User created successfully"}, 201
        except Exception as e:
            return {"error": "Internal Server Error: " + str(e)}, 500


@api.route("/api/users/<int:id>")
class UserByID(Resource):
    def get(self, id):
        try:
            user = User.query.filter(User.id == id).first()

            if not user:
                return {"error": "Not found"}, 404

            return user.to_dict(), 200
        except Exception as e:
            return {"error": "Internal Server Error: " + str(e)}, 500

    def patch(self, id):
        try:
            user = User.query.filter(User.id == id).first()

            if not user:
                return {"error": "Not found"}, 404

            data = request.get_json()

            if not data:
                return {"error": "No user data provided"}, 400

            username = data.get("username")
            email = data.get("email")
            password = data.get("password")

            if not username or not email or not password:
                return {"error": "Missing required fields"}, 400

            if username:
                user.username = username
                user.set_username()

            if email:
                user.email = email

            if password:
                user.set_password(password)

            db.session.commit()

            return {"message": "User updated successfully"}, 200
        except Exception as e:
            return {"error": "Internal Server Error: " + str(e)}, 500

    def delete(self, id):
        try:
            user = User.query.filter(User.id == id).first()

            if not user:
                return {"error": "Not found"}, 404

            db.session.delete(user)
            db.session.commit()

            return {"message": "User deleted successfully"}, 200
        except Exception as e:
            return {"error": "Internal Server Error: " + str(e)}, 500
