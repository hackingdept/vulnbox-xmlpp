# coding: utf-8
import flask_bcrypt as bcrypt

class UserDoesntExist(Exception):
    pass

class User(object):
    is_authenticated = True
    is_active = True
    is_anonymous = False

    def __init__(self, user_id, username, password):
        self.user_id = user_id
        self.username = username
        self.password = bcrypt.generate_password_hash(password)

    def get_id(self):
        return self.user_id

    @staticmethod
    def load(user_id):
        from secret import Database
        try:
            return Database[user_id]
        except KeyError:
            return None

    @staticmethod
    def login(username, password):
        from secret import Database
        for user in Database.values():
            if user.username == username:
                if password and bcrypt.check_password_hash(user.password, password):
                    return user
                else:
                    break
        raise UserDoesntExist()