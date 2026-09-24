import unittest
from app.app import app
from app.models.scan import db
from app.models.user import User

class AuthTestCase(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        app.config["WTF_CSRF_ENABLED"] = False
        self.client = app.test_client()

        with app.app_context():
            db.create_all()
            user = User(username="testuser")
            user.set_password("password")
            db.session.add(user)
            db.session.commit()

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_login_success(self):
        response = self.client.post("/login", data={
            "username": "testuser",
            "password": "password"
        }, follow_redirects=True)
        self.assertIn(b"SentinelScan", response.data)
        self.assertIn(b"Logout", response.data)

    def test_login_failure(self):
        response = self.client.post("/login", data={
            "username": "testuser",
            "password": "wrongpassword"
        }, follow_redirects=True)
        self.assertIn(b"Invalid username or password", response.data)

    def test_protected_routes(self):
        response = self.client.get("/")
        # Should redirect to login
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.location)

if __name__ == "__main__":
    unittest.main()
