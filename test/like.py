from google.appengine.ext import db

from user import User
from post import Post


class Like(db.Model):
    post_key = db.ReferenceProperty(Post, required = True)
    user_key = db.ReferenceProperty(User, required = True)
