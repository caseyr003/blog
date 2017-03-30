from google.appengine.ext import db

class Comment(db.Model):
    post_id = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    user_id = db.StringProperty(required = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def get_user(self):
        user = User.by_id(int(self.user_id))
        return user.name
