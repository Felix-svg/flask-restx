import re
from flask_jwt_extended import (
    create_access_token,
    get_jwt,
    get_jwt_identity,
    jwt_required,
    set_access_cookies,
    unset_jwt_cookies,
)
from flask_restx import Resource
from flask_mail import Message
from flask import jsonify, make_response, request, url_for
from models import LoginActivity, User
from config import db, api, blacklist, jwt, mail
import logging


@jwt.token_in_blocklist_loader
def check_if_token_is_blacklisted(jwt_header, jwt_payload):
    return jwt_payload["jti"] in blacklist


PASSWORD_REGEX = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
)


def is_strong_password(password):
    return re.match(PASSWORD_REGEX, password) is not None


def send_verification_email(user):
    token = user.verification_token
    verification_url = url_for("verify_email", token=token, _external=True)

    msg = Message(
        "Verify Your Email", sender="noreply@example.com", recipients=[user.email]
    )
    msg.body = f"Click the link to verify your email: {verification_url}"
    mail.send(msg)


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
            logging.error(f"Error fetching users: {e}")
            return {"error": "Something went wrong. Please try again later."}, 500

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
            logging.error(f"Error creating user: {e}")
            return {"error": "Something went wrong. Please try again later."}, 500


@api.route("/api/users/<int:id>")
class UserByID(Resource):
    def get(self, id):
        try:
            user = User.query.filter(User.id == id).first()

            if not user:
                return {"error": "Not found"}, 404

            return user.to_dict(), 200
        except Exception as e:
            logging.error(f"Error fetching user: {e}")
            return {"error": "Something went wrong. Please try again later."}, 500

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
            logging.error(f"Error updating user: {e}")
            return {"error": "Something went wrong. Please try again later."}, 500

    def delete(self, id):
        try:
            user = User.query.filter(User.id == id).first()

            if not user:
                return {"error": "Not found"}, 404

            db.session.delete(user)
            db.session.commit()

            return {"message": "User deleted successfully"}, 200
        except Exception as e:
            logging.error(f"Error deleting user: {e}")
            return {"error": "Something went wrong. Please try again later."}, 500


def get_client_ip():
    """Get client IP address"""
    return request.headers.get("X-Forwarded-For", request.remote_addr)


def get_user_agent():
    """Get user agent string from request headers"""
    return request.headers.get("User-Agent", "Unknown")


@api.route("/api/login")
class Login(Resource):
    def post(self):
        try:
            data = request.get_json()

            if not data:
                return {"error": "No user data provided"}, 400

            # email = data.get("email")
            credential = data.get("credential")  # email or username
            password = data.get("password")

            # if not email or not password:
            #     return {"error": "Missing required fields"}, 400
            if not credential or not password:
                return {"error": "Missing required fields"}, 400

            # user = User.query.filter(User.email == email).first()
            user = User.query.filter(
                (User.email == credential) | (User.username == credential)
            ).first()

            if not user or not user.check_password(password):
                if user:
                    db.session.add(
                        LoginActivity(
                            user_id=user.id,
                            ip_address=get_client_ip(),
                            user_agent=get_user_agent(),
                            successful=False,
                        )
                    )
                    db.session.commit()
                return {"error": "Invalid email or password"}, 401

            # if not user.is_verified:
            #     return {"message": "Please verify your email before logging in"}, 403

            db.session.add(
                LoginActivity(
                    user_id=user.id,
                    ip_address=get_client_ip(),
                    user_agent=get_user_agent(),
                    successful=True,
                )
            )
            db.session.commit()

            access_token = create_access_token(identity=str(user.id))
            response = make_response(
                jsonify(
                    {
                        "message": "Login successful",
                        "access_token": access_token,
                        "user": user.to_dict(rules=["-id", "-login_activities"]),
                    }
                )
            )

            set_access_cookies(response, access_token)

            return response
        except Exception as e:
            logging.error(f"Login error: {e}")
            return {"error": "Something went wrong. Please try again later."}, 500


@api.route("/api/login-history")
class LoginHistory(Resource):
    @jwt_required()
    def get():
        user_id = get_jwt_identity()
        activities = (
            LoginActivity.query.filter_by(user_id=user_id)
            .order_by(LoginActivity.timestamp.desc())
            .limit(10)
            .all()
        )

        return (
            jsonify(
                [
                    {
                        "ip_address": act.ip_address,
                        "user_agent": act.user_agent,
                        "timestamp": act.timestamp,
                        "successful": act.successful,
                    }
                    for act in activities
                ]
            ),
            200,
        )


@api.route("/api/verify/<token>")
class VerifyEmail(Resource):
    def get(token):
        user = User.query.filter_by(verification_token=token).first()
        if not user:
            return {"error": "Invalid or expired token"}, 400

        user.is_verified = True
        user.verification_token = None
        db.session.commit()
        return {"message": "Email verified successfully! You can now log in."}


@api.route("/api/logout-other-sessions")
class LogoutOtherSessions(Resource):
    @jwt_required()
    def logout_other_sessions():
        user_id = get_jwt_identity()

        # Delete all login activities except the latest one
        latest_activity = (
            LoginActivity.query.filter_by(user_id=user_id)
            .order_by(LoginActivity.timestamp.desc())
            .first()
        )
        if latest_activity:
            LoginActivity.query.filter(
                LoginActivity.user_id == user_id, LoginActivity.id != latest_activity.id
            ).delete()
            db.session.commit()

        return jsonify({"message": "Logged out of all other sessions."}), 200


@api.route("/api/logout")
class Logout(Resource):
    @jwt_required()
    def post(self):
        try:
            jwt_data = get_jwt()

            jti = jwt_data.get("jti")

            if not jti:
                return {"error": "Invalid token, missing jti"}, 422

            blacklist.add(jti)

            response = make_response(
                jsonify({"message": "Successfully logged out"}), 200
            )
            unset_jwt_cookies(response)

            return response
        except Exception as e:
            logging.error(f"Logout error: {e}")
            return {"error": "Something went wrong. Please try again later."}, 500


@api.route("/api/protected")
class Protected(Resource):
    @jwt_required()
    def get(self):
        try:
            return {"message": "Protected route"}, 200
        except Exception as e:
            logging.error(f"Logout error: {e}")
            return {"error": "Something went wrong. Please try again later."}, 500
