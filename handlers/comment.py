from google.appengine.ext import db
from models import User, Post, Comment
from decorators import post_exists, comment_exists, logged_in, user_comment
from main import BlogHandler


def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)


class NewCommentHandler(BlogHandler):
    @logged_in
    @post_exists
    def post(self, post_id, post):

        # Get comment information from form
        content = self.request.get('content')

        # If input exists create comment else redirect to post
        if content:
            comment = Comment(parent = blog_key(), content = content,
                              post_key = post.key(), user_key = self.user.key())
            comment.put()

            self.redirect('/post/%s' % str(post.key().id()))
        else:
            self.redirect('/post/%s' % str(post.key().id()))


class EditCommentHandler(BlogHandler):
    @logged_in
    @comment_exists
    @user_comment
    def get(self, comment_id, comment):

        self.render("editcomment.html", comment = comment)

    @logged_in
    @comment_exists
    @user_comment
    def post(self, comment_id, comment):

        # Get comment information from form
        content = self.request.get('content')

        # If content exists edit comment
        if content:
            comment.content = content
            comment.put()

            return self.redirect('/post/%s' % str(comment.post_key.key().id()))
        # Else display error
        else:
            error = "Make sure all fields are complete"
            self.render("editcomment.html", comment = comment, error = error)


class DeleteCommentHandler(BlogHandler):
    @logged_in
    @comment_exists
    @user_comment
    def post(self, comment_id, comment):
        comment.delete()
        return self.redirect('/post/%s' % str(comment.post_key.key().id()))
