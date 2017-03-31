from google.appengine.ext import db
from functools import wraps
from models import User, Post, Comment


def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)


def post_exists(function):
    @wraps(function)
    def wrapper(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent = blog_key())
        post = db.get(key)
        # If post doesn't exist, 404 error
        if post:
            return function(self, post_id, post)
        else:
            self.error(404)
            return

    return wrapper


def comment_exists(function):
    @wraps(function)
    def wrapper(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id),
                               parent = blog_key())
        comment = db.get(key)
        # If comment doesn't exist, 404 error
        if comment:
            return function(self, comment_id, comment)
        else:
            self.error(404)
            return

    return wrapper


def logged_in(function):
    @wraps(function)
    def wrapper(self):
        # If not logged in redirect to login page
        if self.user:
            return function(self)
        else:
            self.redirect('/login')

    return wrapper
