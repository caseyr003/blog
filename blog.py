import os
import re
import hmac

import webapp2
import jinja2

from google.appengine.ext import db

from models import User, Post, Comment, Like


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

# Set Secret
secret = 'GLK37HU92HJ3K244LJS'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)


class BlogHandler(BlogHandler):
    def get(self):
        posts = Post.all().order('-created')

        self.render('front.html', posts = posts)


class PostHandler(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        # If post doesn't exist, 404 error
        if not post:
            self.error(404)
            return

        self.render("post.html", post = post)


class EditHandler(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent = blog_key())
        post = db.get(key)

        # If not logged in redirect to home page
        if not self.user:
            self.redirect('/login')

        # If post doesn't exist, 404 error
        if not post:
            self.error(404)
            return

        self.render("edit.html", post = post)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent = blog_key())
        post = db.get(key)

        # If not logged in redirect to home page
        if not self.user:
            self.redirect('/login')

        # If post doesn't exist, 404 error
        if not post:
            self.error(404)
            return

        # Get post information from form
        title = self.request.get('title')
        content = self.request.get('content')

        # If title/content exists and user is current user, Edit Post
        if title and content:
            if self.user.key().id() == post.user_key.key().id():
                post.subject = title
                post.content = content

                post.put()

                return self.redirect('/post/%s' % str(post.key().id()))
        # Else display error
        else:
            error = "Make sure all fields are complete"
            self.render("edit.html", post = post, title = title,
                        content = content, error = error)


class EditCommentHandler(BlogHandler):
    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id),
                               parent = blog_key())
        comment = db.get(key)

        # If not logged in redirect to login page
        if not self.user:
            self.redirect('/login')

        # If comment doesn't exist, 404 error
        if not comment:
            self.error(404)
            return

        self.render("editcomment.html", comment = comment)

    def post(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id),
                               parent = blog_key())
        comment = db.get(key)

        # If not logged in redirect to login page
        if not self.user:
            self.redirect('/login')

        # If comment doesn't exist, 404 error
        if not comment:
            self.error(404)
            return

        # Get comment information from form
        content = self.request.get('content')

        # If comment exists and user is current user, Edit Comment
        if content:
            if self.user.key().id() == comment.user_key.key().id():
                comment.content = content

                comment.put()

                return self.redirect('/post/%s' % str(comment.post_key.key().id()))

        # Else display error
        else:
            error = "Make sure all fields are complete"
            self.render("editcomment.html", comment = comment, error = error)


class DeleteHandler(BlogHandler):
    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        # If not logged in redirect to login page
        if not self.user:
            self.redirect('/login')

        # If post doesn't exist, 404 error
        if not post:
            self.error(404)
            return

        # If user is the post user, Delete post
        if self.user.key().id() == post.user_key.key().id():
            post.delete()
            return self.redirect('/')


class DeleteCommentHandler(BlogHandler):
    def post(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
        comment = db.get(key)

        # If not logged in redirect to login page
        if not self.user:
            self.redirect('/login')

        # If comment doesn't exist, redirect to home page
        if comment:
            post_id = comment.post_key.key().id()
        else:
            self.redirect('/')

        # If user is the comment user, Delete comment
        if self.user.key().id() == comment.user_key.key().id():
            comment.delete()
            return self.redirect('/post/%s' % str(post_id))
        else:
            self.redirect('/post/%s' % str(post_id))


class NewPostHandler(BlogHandler):
    def get(self):
        # If not logged in redirect to login page
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        # If not logged in redirect to login page
        if not self.user:
            self.redirect('/login')

        # Get post information from form
        subject = self.request.get('subject')
        content = self.request.get('content')

        # If input exists create post else show error
        if subject and content:
            post = Post(parent = blog_key(), subject = subject,
                     content = content, user_key = self.user.key())
            post.put()
            self.redirect('/post/%s' % str(post.key().id()))
        else:
            error = "Please complete all fields"
            self.render("newpost.html", subject=subject, content=content,
                        error=error)


class NewCommentHandler(BlogHandler):
    def get(self, post_id):
        if self.user:
            self.render("/")
        else:
            self.redirect("/login")

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        # If not logged in redirect to login page
        if not self.user:
            self.redirect('/login')

        # If post doesn't exist redirect to home page
        if post:
            post_key = post.key()
        else:
            self.redirect('/')

        # Get comment information from form
        content = self.request.get('content')

        # If input exists create comment else redirect to post
        if content:
            comment = Comment(parent = blog_key(), content = content,
                              post_key = post_key, user_key = self.user.key())
            comment.put()
            self.redirect('/post/%s' % str(post.key().id()))
        else:
            self.redirect('/post/%s' % str(post.key().id()))


class LikeHandler(BlogHandler):
    def get(self, post_id):
        if self.user:
            self.render("/")
        else:
            self.redirect("/login")

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        # If not logged in redirect to login page
        if not self.user:
            self.redirect('/login')

        # If post doesn't exist redirect to home page
        if not post:
            self.redirect('/')

        # If user key exists create like else redirect to post page
        if post.key():
            like = Like(parent = blog_key(), post_key = post.key(),
                        user_key = self.user.key())
            like.put()
            self.redirect('/post/%s' % str(post.key().id()))
        else:
            self.redirect('/post/%s' % str(post.key().id()))


class RemoveLikeHandler(BlogHandler):
    def get(self, post_id):
        if self.user:
            self.render("/")
        else:
            self.redirect("/login")

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        # If not logged in redirect to login page
        if self.user:
            self.redirect('/login')

        # If post doesn't exist redirect to home page
        if post:
            self.redirect('/')

        # Find users like on the post
        likes = Like.all()
        likes.filter("post_key =", post.key())
        likes.filter("user_key =", self.user.key())

        # Delete all likes by user on the post
        if likes:
            for like in likes:
                like.delete()

            self.redirect('/post/%s' % str(post.key().id()))
        else:
            self.redirect('/post/%s' % str(post.key().id()))


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

class PageNotFoundHandler(BlogHandler):
    def get(self):
        self.render('error.html')


app = webapp2.WSGIApplication([('/?', BlogHandler),
                               ('/post/([0-9]+)', PostHandler),
                               ('/edit/([0-9]+)', EditHandler),
                               ('/delete/([0-9]+)', DeleteHandler),
                               ('/newcomment/([0-9]+)', NewCommentHandler),
                               ('/editcomment/([0-9]+)', EditCommentHandler),
                               ('/deletecomment/([0-9]+)', DeleteCommentHandler),
                               ('/like/([0-9]+)', LikeHandler),
                               ('/unlike/([0-9]+)', RemoveLikeHandler),
                               ('/newpost', NewPostHandler),
                               ('/signup', RegisterHandler),
                               ('/login', LoginHandler),
                               ('/logout', LogoutHandler),
                               ('/.*', PageNotFoundHandler)
                               ],
                              debug=True)
