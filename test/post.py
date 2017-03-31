from google.appengine.ext import db

from user import User
from comment import Comment


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
            if user_id == like.user_key.key().id():
                liked = True

        # return int of like count and bool of user like status
        return [count, liked]
