from google.appengine.ext import db

from user import User
from post import Post

class Comment(db.Model):
    post_key = db.ReferenceProperty(Post, required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    user_key = db.ReferenceProperty(User, required = True)

    def get_user(self):
        user = User.by_id(int(self.user_key.key().id()))
        return user.name
