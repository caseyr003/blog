from google.appengine.ext import db

class Like(db.Model):
    post_id = db.StringProperty(required = True)
    user_id = db.StringProperty(required = True)
