from config import db,app
from models import User

with app.app_context():
    print("Deleting existing records")
    User.query.delete()

    print("Seeding started")
    new_user: User = User(username="John", email="john@mail.com")
    new_user.set_username()
    new_user.set_password("1234")

    db.session.add(new_user)
    db.session.commit()

    print("Seeding complete!")
