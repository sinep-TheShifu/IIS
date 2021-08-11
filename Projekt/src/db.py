#!/usr/bin/python3

from src.error import eprint
from sqlalchemy import func
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from configparser import ConfigParser
from sqlalchemy.ext.automap import automap_base
import hashlib
import json
import os.path
import secrets

mysql = SQLAlchemy()
Base = automap_base(mysql.Model)


class User(Base, UserMixin):
    __tablename__ = 'users'

    def get_id(self):
        from flask._compat import text_type
        return text_type(self.ID)


class Group(Base):
    __tablename__ = 'group'


class Thread(Base):
    __tablename__ = 'thread'


class Messages(Base):
    __tablename__ = 'messages'


class Moderate(Base):
    __tablename__ = 'moderate'


class Is_member(Base):
    __tablename__ = 'is_member'


class Applications(Base):
    __tablename__ = 'applications'


class Ranking(Base):
    __tablename__ = 'ranking'


def load_db_config(fname='db.ini', sect='mysql'):
    """Load config file with information to connect to DB
       :returns dictionary of parameters loaded from file fname section sect
    """
    if not os.path.isfile(fname):
        raise Exception(f'File: {fname} doesn\'t exist.')
    config = ConfigParser()
    config.read(fname)

    db = {}
    if config.has_section(sect):
        params = config.items(sect)
        for par in params:
            db[par[0]] = par[1]
    else:
        raise Exception(f'Cannot find {sect} section in file: {fname}')
    return db


def get_blob_size(blob: bytes) -> float:
    """
    Return estimation size of blob given by blob parameter.
    :param blob: Blob which size need to by known
    :type blob: bytes
    :return: size in MB
    :rtype: float
    """
    import sys
    return sys.getsizeof(blob) / 1024 / 1024


class DB:
    def __init__(self, db):
        self.db = db

    def check_password(self, password: str, login: str) -> bool:
        user = self.db.session.query(User).filter_by(Login=login).first()
        if user is None:
            return False
        p_s = user.Password.split('$')
        hash_alg = hashlib.sha256((p_s[1] + password).encode())
        return p_s[0] == hash_alg.hexdigest()

    def change_password(self, id: int, new_psw: str) -> None:
        user = self.db.session.query(User).filter_by(ID=id).first()
        if user is None:
            return
        new_hash = self.create_password(new_psw)
        user.Password = new_hash
        self.db.session.commit()

    @staticmethod
    def create_password(password: str):
        salt = secrets.token_hex(16)
        hash_alg = hashlib.sha256((salt + password).encode())
        return hash_alg.hexdigest() + "$" + salt

    def check_username(self, username: str):
        user = self.db.session.query(User).filter_by(Login=username).first()
        return user is None

    def check_groupname(self, groupname: str):
        group = self.db.session.query(Group).filter_by(Name=groupname).first()
        return group is None

    def check_threadname(self, group: Group, threadname: str):
        thread = self.db.session.query(Thread).filter_by(Group_ID=group.ID, Name=threadname).first()
        return thread is None

    def get_user(self, username: str = None, id: int = None):
        if username is None and id is None:
            return None
        if username:
            instance = self.db.session.query(User).filter_by(Login=username).first()
        else:
            instance = self.db.session.query(User).filter_by(ID=id).first()
        return instance

    def get_membership(self, user: User) -> dict:
        if user.is_anonymous:
            return {'gowner': None, 'gmoderator': None, 'gmember': None}
        Ownership = self.db.session.query(Group).filter_by(User_ID=user.ID).all()
        Moderator = self.db.session.query(Moderate).filter_by(User=user.ID).all()
        Member = self.db.session.query(Is_member).filter_by(User=user.ID).all()

        for mem in Member:
            moderator = [x for x in Moderator if x.Group == mem.Group]
            if moderator:
                Member.delete(mem)

        moderators = list()
        for mod in Moderator:
            group = self.db.session.query(Group).filter_by(ID=mod.Group).first()
            if group:
                moderators.append(group)

        members = list()
        for mem in Member:
            group = self.db.session.query(Group).filter_by(ID=mem.Group).first()
            if group:
                members.append(group)


        gowner = list()
        gmoderator = list()
        gmember = list()
        for own in Ownership:
            path = f'/group_picture/{own.ID}/' if own.Image else '/static/pictures/defaults/default_group_picture.png'
            gowner.append((own, path))
        for mod in moderators:
            path = f'/group_picture/{mod.ID}/' if mod.Image else '/static/pictures/defaults/default_group_picture.png'
            gmoderator.append((mod, path))
        for mem in members:
            path = f'/group_picture/{mem.ID}/' if mem.Image else '/static/pictures/defaults/default_group_picture.png'
            gmember.append((mem, path))
        return {'gowner': gowner, 'gmoderator': gmoderator, 'gmember': gmember}

    def search_user_group(self, search_word: str) -> dict:
        retval = {
            'users': list(),
            'groups': list()
        }
        users = self.db.session.query(User).filter(func.lower(User.Login).contains(search_word.lower(), autoescape=True)).all()
        groups = self.db.session.query(Group).filter(func.lower(Group.Name).contains(search_word.lower(), autoescape=True)).all()
        if users:
            for user in users:
                path = f'/profile_picture/{user.ID}/' if user.Image else '/static/pictures/defaults/default_profile_picture.png'
                retval['users'].append((user, path))
        if groups:
            for group in groups:
                path = f'/group_picture/{group.ID}/' if group.Image else '/static/pictures/defaults/default_group_picture.png'
                retval['groups'].append((group, path))
        return retval

    def get_threads(self, group: Group) -> list:
        return self.db.session.query(Thread).filter_by(Group_ID=group.ID).all()

    def get_members(self, group: Group) -> list:
        members = self.db.session.query(Is_member).filter_by(Group=group.ID).all()
        users = list()
        for mem in members:
            user = self.db.session.query(User).filter_by(ID=mem.User).first()
            if user:
                path = f'/profile_picture/{user.ID}/' if user.Image else '/static/pictures/defaults/default_profile_picture.png'
                users.append((user, path))
            else:
                eprint(f'[Error] Database inconsistency error. User in is_member table with id: {mem.User} doesn\'t exist.')
        return users

    def get_moderators(self, group: Group) -> list:
        moderators = self.db.session.query(Moderate).filter_by(Group=group.ID).all()
        users = list()
        for mod in moderators:
            user = self.db.session.query(User).filter_by(ID=mod.User).first()
            if user:
                path = f'/profile_picture/{user.ID}/' if user.Image else '/static/pictures/defaults/default_profile_picture.png'
                users.append((user, path))
            else:
                eprint(f'[Error] Database inconsistency error. User in moderate table with id: {mod.User} doesn\'t exist.')
        return users

    def get_applicants(self, group: Group) -> list:
        applicants = self.db.session.query(Applications).filter_by(Group=group.ID).all()
        users = list()
        for applicant in applicants:
            user = self.db.session.query(User).filter_by(ID=applicant.User).first()
            if user:
                users.append((user, applicant.Membership, applicant.ID))
            else:
                eprint(f'[Error] Database inconsistency error. User in Applications table with id: {applicant.User} doesn\'t exist.')
        return users

    def insert_to_group(self, id: int = None, name: str = None, mode: int = None, description: str = None,
                        image: tuple = None, user_id: int = None):
        """
        Creates or update group defined by id.
        :param id: id of group or None
        :type id: int
        :param name: New name for group (must not be None when creating group)
        :type name: str
        :param mode: New mode for group
        :type mode: int
        :param description: New description for group
        :type description: str
        :param image: Tuple that contains new image blob (0. index) and mimetype (1.index)
        :type image: tuple
        :param user_id: New owner of the group (must not be None when creating group)
        :type user_id: int
        :return: True or False whether update/insertion succeed or fail
        :rtype: bool
        :raise ValueError on bad parameters
        """
        group = None
        add = False
        if id is None:  # Creating new group
            if name is None or user_id is None:
                return None
                #raise ValueError('Missing argument name or user_id when creating new group')
            group = Group(Name=name, User_ID=user_id)
            add = True
        else:
            group = self.db.session.query(Group).filter_by(ID=id).first()
            if group is None:
                return None
                #raise ValueError(f'Invalid group id: {id}')
        if name and id is not None:
            group.Name = name
        if mode:
            group.Mode = mode
        if description:
            group.Description = description
        if image:
            group.Image = image[0]
            group.Mimetype = image[1]
        if user_id and id is not None:
            group.User_ID = user_id
        if add:
            self.db.session.add(group)
        try:
            self.db.session.commit()
        except Exception as e:
            eprint(str(e))
            self.db.session.rollback()
            self.db.session.flush()
            return False
        else:
            return group.ID

    def insert_to_thread(self, group_id: int, thread_id: int = None, thread_name: str = None, description: str = None) -> bool:
        """
        Creates or update thread defined by group_id and thread_name
        :param group_id: Group to which thread belongs
        :type group_id: int
        :param thread_name: New thread name or name of new thread (if thread name doesn't exist)
        :type thread_name: str
        :param description: New description for thread
        :type description: str
        :return: True or False whether update/insertion succeed or fail
        :rtype: bool
        :raise ValueError on bad parameters
        """
        group = self.db.session.query(Group).filter_by(ID=group_id).first()
        if group is None:
            return False
            #raise ValueError(f'Unknown parameter group_id: {group_id}')

        add = False
        if thread_id is None:
            if thread_name is None:
                return False
                #raise ValueError("Unknown thread name when inserting")
            thread = Thread(Group_ID=group_id, Name=thread_name)
            add = True
        else:
            thread = self.db.session.query(Thread).filter_by(Group_ID=group_id, ID=thread_id).first()
            if thread is None:
                return False
                #raise ValueError(f"Unknown thread with id {thread_id} and Group_ID {group_id}")

        if description:
            thread.Description = description
        if add:
            self.db.session.add(thread)
        try:
            self.db.session.commit()
        except Exception as e:
            eprint(str(e))
            self.db.session.rollback()
            self.db.session.flush()
            return False
        else:
            return thread.ID

    def insert_to_users(self, id: int = None, login: str = None, name: str = None, surname: str = None,
                        description: str = None, mode: int = None, image: tuple = None, password: str = None,
                        last_group_id: int = None):
        """
        Creates or update user defined by id. If id is None new user is created. When creating new user login and password cannot be None.
        Parameters:
            id (int): Users id that will be changed.
            login (str): New login for user
            name (str): New name for user
            surname (str): New surname for user
            description (str): New description for user
            mode (int): New mode for user
            image (tuple): Tuple of image data (0. index) and mimetype (1. index)
            password (str): New password for user (not hashed) for hashing will be used create_password method
            last_group_id (int): New last group visited id for user
            :returns True or False whether update/insertion succeed or fail
            :rtype: bool
            :raise ValueError on bad parameter input
        """
        user = None
        add = False
        if id is None:  # user doesn't exist create new
            if login is not None and password is not None:
                user = User(Login=login, Password=self.create_password(password), Last_group=1)
            else:
                return False
                #raise ValueError("When id is None login and password must be provided.")
            add = True
        else:  # user should exist just update him
            user = self.db.session.query(User).filter_by(ID=id).first()
            if user is None:
                return False
                #raise ValueError(f'Invalid user id: {id}')
        if login and id is not None:
            user.Login = login
        if name:
            user.Name = name
        if surname:
            user.Surname = surname
        if description:
            user.Description = description
        if mode:
            user.Mode = mode
        if image:
            user.Image = image[0]
            user.Mimetype = image[1]
        if password and id is not None:
            user.Password = self.create_password(password)
        if last_group_id:
            user.Last_group = last_group_id
        if add:
            self.db.session.add(user)
        try:
            self.db.session.commit()
        except Exception as e:
            eprint(str(e))
            self.db.session.rollback()
            self.db.session.flush()
            return False
        else:
            return user.ID

    def insert_to_applications(self, user_id: int, group_id: int, membership: bool = True) -> bool:
        if user_id is None or group_id is None:
            return False
            #raise ValueError(f'User_id or group_id are not defined')
        add = False
        application = self.db.session.query(Applications).filter_by(User=user_id, Group=group_id).first()
        if application is None:
            add = True
            application = Applications(User=user_id, Group=group_id)
        application.Membership = membership
        if add:
            self.db.session.add(application)
        try:
            self.db.session.commit()
        except Exception as e:
            eprint(str(e))
            self.db.session.rollback()
            self.db.session.flush()
            return False
        else:
            return application.ID

    def insert_to_membership(self, user_id: int, group_id: int):
        if user_id is None or group_id is None:
            return False
            #raise ValueError('Parameters not passed')
        is_member = Is_member(User=user_id, Group=group_id)
        self.db.session.add(is_member)
        try:
            self.db.session.commit()
        except Exception as e:
            eprint(str(e))
            self.db.session.rollback()
            self.db.session.flush()

    def insert_to_moderate(self, user_id: int, group_id: int):
        if user_id is None or group_id is None:
            return False
            #raise ValueError('Parameters not passed')
        moderate = Moderate(User=user_id, Group=group_id)
        self.db.session.add(moderate)
        try:
            self.db.session.commit()
        except Exception as e:
            eprint(str(e))
            self.db.session.rollback()
            self.db.session.flush()

    def insert_to_messages(self, author: User, thread: Thread, message: str = None, ranking: int = None, id: int = None):
        add = False
        if id:
            new_message = self.db.session.query(Messages).filter_by(ID=id).first()
            if new_message is None:
                return False
                #raise ValueError(f'Unknown message id {id}')
        else:
            add = True
            new_message = Messages(User_ID=author.ID, Thread_name=thread.Name, ID_group=thread.Group_ID, Content=message)
        if ranking:
            new_message.Rank = ranking
        if message:
            new_message.Content = message
        if add:
            self.db.session.add(new_message)
        try:
            self.db.session.commit()
        except Exception as e:
            eprint(str(e))
            self.db.session.rollback()
            self.db.session.flush()

    def insert_to_ranking(self, message: Messages, user: User, inc: bool):
        ranking = self.db.session.query(Ranking).filter_by(User=user.ID, Message=message.ID,Message_author=message.User_ID,Thread_name=message.Thread_name,ID_group=message.ID_group).first()
        add = False
        if ranking is None:
            add = True
            ranking = Ranking(User=user.ID, Message=message.ID,Message_author=message.User_ID,Thread_name=message.Thread_name,ID_group=message.ID_group)
        if inc is not None:
            ranking.Inc = inc
        if add:
            self.db.session.add(ranking)
        try:
            self.db.session.commit()
        except Exception as e:
            eprint(str(e))
            self.db.session.rollback()
            self.db.session.flush()

    def delete_from_db(self, obj):
        self.db.session.delete(obj)
        try:
            self.db.session.commit()
        except Exception as e:
            eprint(str(e))
            self.db.session.rollback()
            self.db.session.flush()

    def get_messages(self, thread: Thread, limit: int = 200, after: int = None, before: int = None) -> list:
        if after and before:
            if after < before:
                ValueError(f'After ({after}) must be grater than before ({before})')
        if after is None and before is None:
            retval = self.db.session.query(Messages).filter(Messages.Thread_name == thread.Name, Messages.ID_group == thread.Group_ID).order_by(Messages.ID.desc()).limit(limit).all()
        elif after and before is None:
            retval = self.db.session.query(Messages).filter(Messages.ID >= after, Thread_name=thread.Name, ID_group=thread.Group_ID).order_by(Messages.ID.desc()).limit(limit).all()
        elif before and after is None:
            retval = self.db.session.query(Messages).filter(Messages.ID <= before, Messages.Thread_name == thread.Name, Messages.ID_group == thread.Group_ID).order_by(Messages.ID.desc()).limit(limit).all()
        else:
            retval = self.db.session.query(Messages).filter(Messages.ID >= after, Messages.ID <= before, Messages.Thread_name == thread.Name, Messages.ID_group == thread.Group_ID).order_by(Messages.ID.desc()).limit(limit).all()
        if not retval:
            retval = list()
        else:
            retval = retval[::-1]
        return retval

    @staticmethod
    def messages_to_json(messages: list) -> str:
        result = list()
        for message in messages:
            result.append({
                'ID': message.ID,
                'Content': message.Content,
                'Rank': message.Rank,
                'Date_time': str(message.Date_time),
                'User_ID': message.User_ID,
                'User_login': User.query.filter_by(ID=message.User_ID).first().Login,
                'Thread_name': message.Thread_name,
                'ID_group': message.ID_group
            })
        return json.dumps(result)

    def getuserrights(self, user, group) -> dict:
        result = {
            'admin': None,
            'owner': None,
            'moderator': None,
            'member': None,
            'user': None,
            'visitor': None
        }
        if not user.is_authenticated:
            result['visitor'] = True
            return result
        if user.Mode & 2:
            result['admin'] = True
        elif user.ID == group.User_ID:
            result['owner'] = True
        elif self.db.session.query(Moderate).filter_by(User=user.ID, Group=group.ID).first():
            result['moderator'] = True
        elif self.db.session.query(Is_member).filter_by(User=user.ID, Group=group.ID).first():
            result['member'] = True
        else:
            result['user'] = True
        return result


# Note this function must be called before others functions that works with database!!!
def init_db(app, fname='db.ini', sect='mysql'):
    db_config = load_db_config(fname, sect)
    host = db_config['mysql_database_host']
    psw = db_config['mysql_database_password']
    db = db_config['mysql_database_db']
    port = db_config['mysql_database_port']
    user = db_config['mysql_database_user']
    # Alternativní verze bez ssl připojení k databázy
    #app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{user}:{psw}@{host}:{port}/{db}'  # Dano proof version
    app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+mysqldb://{user}:{psw}@{host}:{port}/{db}?ssl=true'  # change driver to mysqldb and add ?ssl=true for better performance and security      Original co funguje vsetkym okrem Danovho Linuxu
    #app.config['SQLALCHEMY_ECHO'] = True  # TODO debugging info delete me for production
    #app.config['SQLALCHEMY_POOL_TIMEOUT'] = 600
    #app.config['SQLALCHEMY_POOL_RECYCLE'] = 30
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    global mysql
    mysql.init_app(app)
    global Base
    Base.prepare(mysql.engine, reflect=True)
    # global User, Group, Thread, Messages, Moderate, Is_member, Applications, Ranking
    # User = Base.classes.users
    # Group = Base.classes.group
    # Thread = Base.classes.thread
    # Message = Base.classes.messages
    # Moderate = Base.classes.moderate
    # Is_member = Base.classes.is_member
    # Application = Base.classes.applications
    # Ranking = Base.classes.ranking
    return mysql
