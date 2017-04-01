from google.appengine.ext import db
from models import User, Post
from decorators import post_exists, logged_in, user_post
from main import BlogHandler

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class NewPostHandler(BlogHandler):
    @logged_in
    def get(self):
        self.render("newpost.html")

    @logged_in
    def post(self):

        # Get post information from form
        subject = self.request.get('subject')
        content = self.request.get('content')

        # If input exists create post else show error
        if subject and content:
            post = Post(parent = blog_key(), subject = subject,
                     content = content, user_key = self.user.key())
            post.put()

            self.redirect('/post/%s' % str(post.key().id()))
        else:
            error = "Please complete all fields"
            self.render("newpost.html", subject=subject, content=content,
                        error=error)

class PostHandler(BlogHandler):
    @post_exists
    def get(self, post_id, post):

        self.render("post.html", post = post)


class EditHandler(BlogHandler):
    @logged_in
    @post_exists
    @user_post
    def get(self, post_id, post):

        self.render("edit.html", post = post)

    @logged_in
    @post_exists
    @user_post
    def post(self, post_id, post):

        # Get post information from form
        title = self.request.get('title')
        content = self.request.get('content')

        # If title/content exists edit post
        if title and content:
            post.subject = title
            post.content = content
            post.put()

            return self.redirect('/post/%s' % str(post.key().id()))
        # Else display error
        else:
            error = "Make sure all fields are complete"
            self.render("edit.html", post = post, title = title,
                        content = content, error = error)

class DeleteHandler(BlogHandler):
    @logged_in
    @post_exists
    @user_post
    def post(self, post_id, post):

        post.delete()
        return self.redirect('/')
