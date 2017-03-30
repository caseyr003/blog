from google.appengine.ext import db

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
