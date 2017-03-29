import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

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


# User encryption and validation functions
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    creator_id = db.StringProperty(required = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def get_comments(self):
        comments = Comment.all()
        comments.filter("post_id =", str(self.key().id()))
        comments.order('created')
        return comments

    def get_user(self):
        user = User.by_id(int(self.creator_id))
        return user.name

    def comment_count(self):
        comments = Comment.all()
        comments.filter("post_id =", str(self.key().id()))

        count = 0

        # Check for the amount of comments for a post
        for comment in comments:
            count += 1

        # return count of comments
        return count

    def like_count(self, user_id):
        likes = Like.all()
        likes.filter("post_id =", str(self.key().id()))

        count = 0
        liked = False

        # Check if user liked the post and return count
        for like in likes:
            count += 1
            if user_id == like.user_id:
                liked = True

        # return int of like count and bool of user like status
        return [count, liked]


class Comment(db.Model):
    post_id = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    user_id = db.StringProperty(required = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def get_user(self):
        user = User.by_id(int(self.user_id))
        return user.name


class Like(db.Model):
    post_id = db.StringProperty(required = True)
    user_id = db.StringProperty(required = True)


class Blog(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        user_id = ''

        # If logged in pass user's id to homepage
        if self.user:
            user_id = str(self.user.key().id())

        self.render('front.html', posts = posts, user_id = user_id)


class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        user_id = ''

        # If logged in pass user's id to post page
        if self.user:
            user_id = str(self.user.key().id())

        if not post:
            self.error(404)
            return

        self.render("post.html", post = post, user_id = user_id)


class EditPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent = blog_key())
        post = db.get(key)
        user_id = str(self.user.key().id())

        if not post:
            self.error(404)
            return

        self.render("edit.html", post = post, user_id = user_id)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent = blog_key())
        post = db.get(key)
        user_id = str(self.user.key().id())

        # If not logged in redirect to home page
        if not self.user:
            self.redirect('/')

        # Get post information from form
        title = self.request.get('title')
        content = self.request.get('content')

        # If title/content exists and user is current user, Edit Post
        if title and content:
            if user_id == post.creator_id:
                post.subject = title
                post.content = content

                post.put()

                return self.redirect('/post/%s' % str(post.key().id()))
        # Else display error
        else:
            error = "Make sure all fields are complete"
            self.render("edit.html", post = post, title = title,
                        content = content, user_id = user_id, error = error)


        if not post:
            self.error(404)
            return


class EditCommentPage(BlogHandler):
    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id),
                               parent = blog_key())
        comment = db.get(key)
        user_id = str(self.user.key().id())

        if not comment:
            self.error(404)
            return

        self.render("editcomment.html", comment = comment, user_id = user_id)

    def post(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id),
                               parent = blog_key())
        comment = db.get(key)
        user_id = str(self.user.key().id())

        # If not logged in redirect to home page
        if not self.user:
            self.redirect('/')

        # Get comment information from form
        content = self.request.get('content')

        # If comment exists and user is current user, Edit Comment
        if content:
            if user_id == comment.user_id:
                comment.content = content

                comment.put()

                return self.redirect('/post/%s' % str(comment.post_id))

        # Else display error
        else:
            error = "Make sure all fields are complete"
            self.render("editcomment.html", comment = comment,
                        user_id = user_id, error = error)

        if not comment:
            self.error(404)
            return


class DeletePage(BlogHandler):
    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        user_id = str(self.user.key().id())

        # If user is the post user, Delete post
        if user_id == post.creator_id:
            post.delete()
            return self.redirect('/')


class DeleteCommentPage(BlogHandler):
    def post(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
        comment = db.get(key)
        user_id = str(self.user.key().id())
        post_id = comment.post_id

        # If user is the comment user, Delete comment
        if user_id == comment.user_id:
            comment.delete()
            return self.redirect('/post/%s' % str(post_id))
        else:
            self.redirect('/post/%s' % str(post_id))


class NewPost(BlogHandler):
    def get(self):
        # If not logged in redirect to login page
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/')

        # Get post information from form
        subject = self.request.get('subject')
        content = self.request.get('content')
        creator_id = str(self.user.key().id())

        # If input exists create post else show error
        if subject and content:
            p = Post(parent = blog_key(), subject = subject,
                     content = content, creator_id = creator_id)
            p.put()
            self.redirect('/post/%s' % str(p.key().id()))
        else:
            error = "Please complete all fields"
            self.render("newpost.html", subject=subject, content=content,
                        error=error)


class NewCommentPage(BlogHandler):
    def get(self, post_id):
        if self.user:
            self.render("/")
        else:
            self.redirect("/login")

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        user_id = str(self.user.key().id())
        content = self.request.get('content')

        # If not logged in redirect to home page
        if not self.user:
            self.redirect('/')

        # Get comment information from form
        content = self.request.get('content')

        # If input exists create comment else redirect to post
        if content and user_id:
            comment = Comment(parent = blog_key(), content = content,
                              post_id = post_id, user_id = user_id)
            comment.put()
            self.redirect('/post/%s' % str(post.key().id()))
        else:
            self.redirect('/post/%s' % str(post.key().id()))


class LikePage(BlogHandler):
    def get(self, post_id):
        if self.user:
            self.render("/")
        else:
            self.redirect("/login")

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        user_id = str(self.user.key().id())

        # If not logged in redirect to post page
        if not self.user:
            self.redirect('/post/%s' % str(post.key().id()))

        # If user id exists create like else redirect to post page
        if user_id:
            like = Like(parent = blog_key(), post_id = post_id,
                        user_id = user_id)
            like.put()
            self.redirect('/post/%s' % str(post.key().id()))
        else:
            self.redirect('/post/%s' % str(post.key().id()))


class RemoveLikePage(BlogHandler):
    def get(self, post_id):
        if self.user:
            self.render("/")
        else:
            self.redirect("/login")

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        user_id = str(self.user.key().id())

        # Find users like on the post
        likes = Like.all()
        likes.filter("post_id =", post_id)
        likes.filter("user_id =", user_id)

        # If not logged in redirect to post page
        if not self.user:
            self.redirect('/post/%s' % str(post.key().id()))

        # Delete all likes by user on the post
        if user_id:
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


class Signup(BlogHandler):
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


class Register(Signup):
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


class Login(BlogHandler):
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


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/')


app = webapp2.WSGIApplication([('/?', Blog),
                               ('/post/([0-9]+)', PostPage),
                               ('/edit/([0-9]+)', EditPage),
                               ('/delete/([0-9]+)', DeletePage),
                               ('/newcomment/([0-9]+)', NewCommentPage),
                               ('/editcomment/([0-9]+)', EditCommentPage),
                               ('/deletecomment/([0-9]+)', DeleteCommentPage),
                               ('/like/([0-9]+)', LikePage),
                               ('/unlike/([0-9]+)', RemoveLikePage),
                               ('/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ],
                              debug=True)
