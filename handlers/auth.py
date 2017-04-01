import re
from models import User
from main import BlogHandler


# Validation fuctions for register inputs
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


class SignupHandler(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        # Pass username & email to form if error
        params = dict(username = self.username,
                      email = self.email)

        # Check for invalid input and add to params
        if not valid_username(self.username):
            params['error_username'] = "Username not valid"
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "Password not valid"
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Passwords don't match"
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "Email not valid"
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class RegisterHandler(SignupHandler):
    def done(self):

        user = User.by_name(self.username)

        # Show error message if username exists
        if user:
            error = "Username already exists."
            self.render('signup-form.html', error_username = error)
        # Register user if username doesnt exists
        else:
            user = User.register(self.username, self.password, self.email)
            user.put()

            self.login(user)
            self.redirect('/')


class LoginHandler(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        user = User.login(username, password)
        if user:
            self.login(user)
            self.redirect('/')
        else:
            error = "Invalid Login"
            self.render('login-form.html', error = error)


class LogoutHandler(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/')
