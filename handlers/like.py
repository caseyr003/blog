from google.appengine.ext import db
from models import User, Post, Like
from decorators import post_exists, logged_in
from main import BlogHandler


def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)


class LikeHandler(BlogHandler):
    @logged_in
    @post_exists
    def post(self, post_id, post):

        # If user key exists create like else redirect to post page
        if post.key():
            like = Like(parent = blog_key(), post_key = post.key(),
                        user_key = self.user.key())
            like.put()

            self.redirect('/post/%s' % str(post.key().id()))
        else:
            self.redirect('/post/%s' % str(post.key().id()))


class RemoveLikeHandler(BlogHandler):
    @logged_in
    @post_exists
    def post(self, post_id, post):

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
