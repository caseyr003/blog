import webapp2
from handlers import *


app = webapp2.WSGIApplication([('/?', FrontHandler),
                               ('/post/([0-9]+)', PostHandler),
                               ('/edit/([0-9]+)', EditHandler),
                               ('/delete/([0-9]+)', DeleteHandler),
                               ('/newcomment/([0-9]+)', NewCommentHandler),
                               ('/editcomment/([0-9]+)', EditCommentHandler),
                               ('/deletecomment/([0-9]+)', DeleteCommentHandler),
                               ('/like/([0-9]+)', LikeHandler),
                               ('/unlike/([0-9]+)', RemoveLikeHandler),
                               ('/newpost', NewPostHandler),
                               ('/signup', RegisterHandler),
                               ('/login', LoginHandler),
                               ('/logout', LogoutHandler),
                               ('/.*', PageNotFoundHandler)
                               ],
                              debug=True)
