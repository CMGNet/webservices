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
            (r"/user/register", RegistrationHandler),
            (r"/user/([^/]+)/register", RegistrationHandler),
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

class RegistrationHandler(BaseHandler):
    def get(self, username=None):
        if username == None:
            self.render("register_stepone.html", username = username, message = "")
            return
        user = self.get_user(username)
        if user != None: raise tornado.web.HTTPError(404)
        self.render("register.html", username = username, message = "")

    def post(self, username=None):
        if username == None:
            self.redirect("/user/%s/register" % self.get_argument("username"))
            return
        user = self.get_user(username)
        if user != None: raise tornado.web.HTTPError(404)

        newpw = self.get_argument("password")
        confirm = self.get_argument("confirm")
        newpw = crypt.crypt(newpw, "$1$%s$" % self.getsalt(8))

        self.db.execute("insert into users_sync (hook, data) values (?, ?)", ("REGISTER", " ".join([username, newpw])))
        self.db.commit()

        self.render("register.html", username = username, message = "Your account has been created")

class ChangePasswordHandler(BaseHandler):
    def get(self, username):
        user = self.get_user(username)
        if user == None: raise tornado.web.HTTPError(404)
        self.render("changepassword.html", username = username, message = "")

    def post(self, username):
        user = self.get_user(username)
        if user == None: raise tornado.web.HTTPError(404)

        current = self.get_argument("current")
        newpw = self.get_argument("password")
        confirm = self.get_argument("confirm")
        if crypt.crypt(current, user['password']) == user['password'] and newpw == confirm:
            newpw = crypt.crypt(newpw, "$1$%s$" % self.getsalt(8))

            self.db.execute("insert into users_sync (hook, data) values (?, ?)", ("SETPASS", " ".join([username, newpw])))
            self.db.commit()

            self.render("changepassword.html", username = username, message = "Your password was successfuly updated")
        else:
            self.render("changepassword.html", username = username, message = "Your current password was incorrect")

def main():
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)

    from tornado import autoreload
    autoreload.watch("templates/home.html")
    autoreload.watch("templates/users.html")
    autoreload.watch("templates/changepassword.html")
    autoreload.watch("templates/register.html")
    autoreload.watch("templates/register_stepone.html")
    autoreload.start()
    tornado.ioloop.IOLoop.instance().start()

def gensecret():
    import base64
    import uuid
    print(base64.b64encode(uuid.uuid4().bytes + uuid.uuid4().bytes))

if __name__ == "__main__":
    gensecret()
    main()
