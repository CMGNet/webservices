#!/usr/bin/env python
import os.path
import re
import tornado.auth
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import unicodedata
import sqlite3
import crypt
import random
import string

from tornado.options import define, options
define("port", default=8888, help="run on the given port", type=int)
define("db", default="./ratbox-services.db", help="database to use", type=str)

class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", HomeHandler),
            (r"/users", UsersHandler),
            (r"/user/([^/]+)/password", ChangePasswordHandler),
        ]
        settings = dict(
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            xsrf_cookies=True,
            cookie_secret="",
            autoescape=None,
        )
        tornado.web.Application.__init__(self, handlers, **settings)

        self.db = sqlite3.connect(options.db)

class BaseHandler(tornado.web.RequestHandler):
    def getsalt(self, length):
        chars = string.letters + string.digits
        # generate a random 2-character 'salt'
        salt = []
        for i in xrange(length):
            salt.append(random.choice(chars))
        return "".join(salt)

    @property
    def db(self):
        return self.application.db

    def cursor(self):
        return self.application.db.cursor()

    def get_user(self, username):
        c = self.cursor()
        c.execute("select username, password from users where username = ?", (username,) )
        user_list = list(c)
        c.close()

        if not len(user_list):
            return None

        return dict(username=user_list[0][0], password=user_list[0][1])

class HomeHandler(BaseHandler):
    def get(self):
        self.render("home.html")

class UsersHandler(BaseHandler):
    def get(self):
        c = self.cursor()
        c.execute("select username, password from users");

        self.render("users.html", crypt = crypt, users = c)

        c.close()

class ChangePasswordHandler(BaseHandler):
    def get(self, username):
        user = self.get_user(username)
        if user == None: raise tornado.web.HTTPError(404)
        self.render("changepassword.html", username = user['username'], message = "")

    def post(self, username):
        user = self.get_user(username)
        if user == None: raise tornado.web.HTTPError(404)

        current = self.get_argument("current")
        newpw = self.get_argument("password")
        confirm = self.get_argument("confirm")
        if crypt.crypt(current, user['password']) == user['password'] and newpw == confirm:
            newpw = crypt.crypt(newpw, "$1$%s$" % self.getsalt(8))

            self.db.execute("update users set password = ? where username = ?", (newpw, username,))
            self.db.commit()

            self.render("changepassword.html", username = user['username'], message = "Your password was successfuly updated")
        else:
            self.render("changepassword.html", username = user['username'], message = "Your current password was incorrect")

def main():
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)

    from tornado import autoreload
    autoreload.watch("templates/home.html")
    autoreload.watch("templates/users.html")
    autoreload.watch("templates/changepassword.html")
    autoreload.start()
    tornado.ioloop.IOLoop.instance().start()

def gensecret():
    import base64
    import uuid
    print(base64.b64encode(uuid.uuid4().bytes + uuid.uuid4().bytes))

if __name__ == "__main__":
    gensecret()
    main()
