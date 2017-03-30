from google.appengine.ext import db
import random
import hashlib
from string import letters


def users_key(group = 'default'):
    return db.Key.from_path('users', group)

# User encryption and validation functions
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


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


class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    user_key = db.ReferenceProperty(User, required = True)

    def get_comments(self):
        comments = Comment.all()
        comments.filter("post_key =", self.key())
        comments.order('created')
        return comments

    def get_user(self):
        return self.user_key.name

    def comment_count(self):
        comments = Comment.all()
        comments.filter("post_key =", self.key())

        count = 0

        # Check for the amount of comments for a post
        for comment in comments:
            count += 1

        # return count of comments
        return count

    def like_count(self, user_id):
        likes = Like.all()
        likes.filter("post_key =", self.key())

        count = 0
        liked = False

        # Check if user liked the post and return count
        for like in likes:
            count += 1
            print(like.user_key.key().id())
            if user_id == like.user_key.key().id():
                liked = True

        # return int of like count and bool of user like status
        return [count, liked]


class Comment(db.Model):
    post_key = db.ReferenceProperty(Post, required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    user_key = db.ReferenceProperty(User, required = True)

    def get_user(self):
        user = User.by_id(int(self.user_key.key().id()))
        return user.name


class Like(db.Model):
    post_key = db.ReferenceProperty(Post, required = True)
    user_key = db.ReferenceProperty(User, required = True)
