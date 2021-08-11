#!/usr/bin/env python3
# -*- coding: utf-8 -*-

################################################################################
# @project Free Chat - IIS2020(Sociální síť: diskuse v diskusních skupinách)
#
# @file freechat.py
# @brief Online message forum
#
# @author Roman Fulla <xfulla00>
# @author Vojtech Ulej <xulejv00>
################################################################################

from src.db import DB, init_db  # Database
from src.db import Applications, Group, Is_member, Messages, Moderate, Ranking, Thread, User  # Database objects
from src.error import eprint
from datetime import timedelta
from flask import flash, Flask, jsonify, redirect, render_template, request, Response, send_file, send_from_directory, session, url_for
from flask_login import current_user, login_required, login_user, logout_user, LoginManager, UserMixin
import io
import json
import re
import sys
import threading

# App initialization #
app = Flask(__name__)
app.config["SECRET_KEY"] = "c7d6ee3e38c6ce4c50aedeedcf622b9f"
app.app_context().push()  # Nutno udělat, abych mohl pracovat s databází mimo view funkce
database = init_db(app)
db = DB(database)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "welcome"
login_manager.login_message = "You will need to log in to gain access to this page."
rank_mutex = threading.Lock()

# Default values #
default_group_ID        = 1
default_pictures_path   = "/static/pictures/defaults/"
default_profile_picture = "default_profile_picture.png"
default_group_picture   = "default_group_picture.png"


################################################################################
# Visitors
################################################################################
@app.route("/")
@app.route("/index/")
@app.route("/main/")
@app.route("/welcome/")
def welcome():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    return render_template("main_page.html")


@app.route("/registration/", methods=["GET", "POST"])
@app.route("/signup/", methods=["GET", "POST"])
@app.route("/sign_up/", methods=["GET", "POST"])
@app.route("/register/", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("lost"))
    if request.method == "GET":
        return render_template("registration_page.html", form=request.form)

    # Required values
    login    = request.form.get("login", None)
    password = request.form.get("psw", None)
    repeat   = request.form.get("psw-repeat", None)

    # Required values check
    if len(login) > 30 or not re.search(r"^\w+$", login):
        flash("Invalid username. Please use only English letters & numbers. Maximum is 30 characters.")
        return render_template("registration_page.html", form=request.form)
    if not db.check_username(login):
        flash("Username is already taken.")
        return render_template("registration_page.html", form=request.form)
    if password != repeat:
        flash("Passwords do not match.")
        return render_template("registration_page.html", form=request.form)

    db.insert_to_users(login=login, password=password)
    flash("Your registration was succesful. You can now login.")
    return redirect(url_for("welcome"))

    '''
    # Optional values
    name        = request.form.get("name", None)
    surname     = request.form.get("surname", None)
    description = request.form.get("description", None)
    image       = request.files["profile_image"]
    visibility  = request.form.get("visibility", 0)

    # Optional values check
    if name and len(name) > 20:
        flash("Your name is too long. Maximum is 20 characters.")
        return render_template("registration_page.html", form=request.form)
    if surname and len(surname) > 20:
        flash("Your surname is too long. Maximum is 20 characters.")
        return render_template("registration_page.html", form=request.form)
    if description and len(description) > 2000:
        flash("Your description is too long. Maximum is 2000 characters.")
        return render_template("registration_page.html", form=request.form)
    if image:
        blob = image.read()
        if sys.getsizeof(blob) > (2 * 1024 * 1024):
            flash("Your image is too big. Maximum allowed size is 2MB.")
            return render_template("registration_page.html", form=request.form)
        mimetype = image.mimetype
        image    = (blob, mimetype)
    if visibility:
        visibility = int(visibility)

    db.insert_to_users(login=login, password=password, name=name, surname=surname, description=description, image=image, mode=visibility)
    flash("Your registration was succesful. You can now login.")
    return redirect(url_for("welcome"))
    '''


@app.route("/login/", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("lost"))
    if request.method == "GET":
        return redirect(url_for("welcome"))

    login    = request.form.get("uname", None)
    password = request.form.get("psw", None)

    if not db.check_password(password, login):
        flash("Your credentials were incorrect. Please try again.")
        return render_template("main_page.html", form=request.form)

    user = User.query.filter_by(Login=login).first()
    if not user:
        flash("Something went wrong. Please try again.")
        return render_template("main_page.html", form=request.form)

    login_user(user)
    return redirect(url_for("home"))


@app.route("/guest/")
@app.route("/visitor/")
@app.route("/visit/")
@app.route("/browse/")
def guest():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    return redirect(url_for("group", group_id=default_group_ID))


################################################################################
# Users
################################################################################
@app.route("/home/")
@login_required
def home():
    return redirect(url_for("group", group_id=current_user.Last_group))


@app.route("/profile/<user_id>/")
@app.route("/user/<user_id>/")
@app.route("/users/<user_id>/")
@app.route("/profiles/<user_id>/")
def profile(user_id):
    user = User.query.filter_by(ID=user_id).first()
    if user is None:
        return redirect(url_for("lost"))
    private = user.Mode & 1
    if private and current_user.is_anonymous:
        flash("You will need to log in to gain access to this page.")
        return redirect(url_for("welcome"))

    if user.Image is not None:
        image = "/profile_picture/" + str(user.ID)
    else:
        image = default_pictures_path + default_profile_picture

    admin = False
    owner = False
    if current_user.is_authenticated:
        admin = current_user.Mode & 2
        if not admin:
            owner = current_user.ID == user.ID

    member = db.get_membership(user)

    form = request.args.get('form')
    if form:
        form = json.loads(form)
    return render_template("profile_page.html", user_id=user.ID, username=user.Login, name=user.Name, surname=user.Surname, description=user.Description,
                           img_src=image, visibility=private, admin=admin, owner=owner, **member, form=form)


@app.route("/profile_picture/")
@login_required
def profile_img():
    return redirect(url_for("user_img", user_id=current_user.ID))


@app.route("/profile_picture/<user_id>/")
def user_img(user_id):
    user = User.query.filter_by(ID=user_id).first()
    if user is None:
        return redirect(url_for("lost"))
    private = user.Mode & 1
    if private and current_user.is_anonymous:
        flash("You will need to log in to gain access to this page.")
        return redirect(url_for("welcome"))

    if user.Image is None:
        return redirect(url_for("lost"))
    return send_file(io.BytesIO(user.Image), mimetype=user.Mimetype)  # Creates file in memory, then sends file to path


@app.route("/profile_settings/<user_id>/", methods=["POST"])
@login_required
def user_settings(user_id):
    user = User.query.filter_by(ID=user_id).first()
    if user is None:
        return redirect(url_for("lost"))

    admin = current_user.Mode & 2
    owner = current_user.ID == user.ID
    if not admin and not owner:
        return redirect(url_for("tresspass"))

    # Current password
    current_password = request.form.get("current_password", None)
    if not admin and not db.check_password(current_password, user.Login):
        flash("Your password was incorrect. Changes were not applied.")
        return redirect(url_for("profile", user_id=user.ID, form=json.dumps(request.form)))

    # Changed values
    login       = request.form.get("login", None)
    password    = request.form.get("password1", None)
    repeat      = request.form.get("password2", None)
    name        = request.form.get("fname", None)
    surname     = request.form.get("lname", None)
    description = request.form.get("description", None)
    image       = request.files["profile_image"]
    visibility  = request.form.get("visibility", None)

    # Values check
    if login and (len(login) > 30 or not re.search(r"^\w+$", login)):
        flash("Invalid username. Please use only English letters & numbers. Maximum is 30 characters.")
        return redirect(url_for("profile", user_id=user.ID, form=json.dumps(request.form)))
    if login and not db.check_username(login):
        flash("Username is already taken.")
        return redirect(url_for("profile", user_id=user.ID, form=json.dumps(request.form)))
    if password and password != repeat:
        flash("Passwords do not match.")
        return redirect(url_for("profile", user_id=user.ID, form=json.dumps(request.form)))
    if name and len(name) > 20:
        flash("Your name is too long. Maximum is 20 characters.")
        return redirect(url_for("profile", user_id=user.ID, form=json.dumps(request.form)))
    if surname and len(surname) > 20:
        flash("Your surname is too long. Maximum is 20 characters.")
        return redirect(url_for("profile", user_id=user.ID, form=json.dumps(request.form)))
    if description and len(description) > 2000:
        flash("Your description is too long. Maximum is 2000 characters.")
        return redirect(url_for("profile", user_id=user.ID, form=json.dumps(request.form)))
    if image:
        blob = image.read()
        if sys.getsizeof(blob) > (2 * 1024 * 1024):
            flash("Your image is too big. Maximum allowed size is 2MB.")
            return redirect(url_for("profile", user_id=user.ID, form=json.dumps(request.form)))
        mimetype = image.mimetype
        image    = (blob, mimetype)
    if visibility:
        visibility = int(visibility)

    db.insert_to_users(id=user.ID, login=login, password=password, name=name, surname=surname, description=description, image=image, mode=visibility)
    flash("Your changes were applied.")
    return redirect(url_for("profile", user_id=user.ID))


@app.route("/logout/")
@login_required
def logout():
    logout_user()
    return redirect(url_for("welcome"))


@app.route("/delete/profile/<user_id>/")
@app.route("/delete/user/<user_id>/")
@app.route("/delete/users/<user_id>/")
@app.route("/delete/profiles/<user_id>/")
@login_required
def delete_account(user_id):
    user = User.query.filter_by(ID=user_id).first()
    if user is None:
        return redirect(url_for("lost"))

    admin = current_user.Mode & 2
    owner = current_user.ID == user.ID
    if not admin and not owner:
        return redirect(url_for("tresspass"))

    if admin:
        flash("Account " + user.Login + " has been deleted.")
        db.delete_from_db(user)
        return redirect(url_for("home"))
    else:
        logout_user()
        flash("Your account has been deleted.")
        db.delete_from_db(user)
        return redirect(url_for("welcome"))


################################################################################
# Groups
################################################################################
@app.route("/create/group/", methods=["POST"])
@login_required
def create_group():
    name        = request.form.get("group_name", None)
    description = request.form.get("description", None)
    image       = request.files["group_image"]
    visibility  = request.form.get("visibility", None)
    owner       = current_user.ID

    # Values check
    if len(name) > 30:
        flash("Group name is too long. Maximum is 30 characters.")
        return redirect(url_for("group", group_id=current_user.Last_group, form=json.dumps(request.form)))
    if not db.check_groupname(name):
        flash("Group name is already taken. Please use different name.")
        return redirect(url_for("group", group_id=current_user.Last_group, form=json.dumps(request.form)))
    if description and len(description) > 2000:
        flash("Group description is too long. Maximum is 2000 characters.")
        return redirect(url_for("group", group_id=current_user.Last_group, form=json.dumps(request.form)))
    if image:
        blob = image.read()
        if sys.getsizeof(blob) > (2 * 1024 * 1024):
            flash("Group image is too big. Maximum allowed size is 2MB.")
            return redirect(url_for("group", group_id=current_user.Last_group, form=json.dumps(request.form)))
        mimetype = image.mimetype
        image    = (blob, mimetype)
    if visibility:
        visibility = int(visibility)

    id = db.insert_to_group(name=name, description=description, image=image, mode=visibility, user_id=owner)
    return redirect(url_for("group", group_id=id))


@app.route("/group/<group_id>/")
@app.route("/groups/<group_id>/")
def group(group_id):
    group = Group.query.filter_by(ID=group_id).first()
    if group is None:
        return redirect(url_for("group", group_id=default_group_ID))
    private = group.Mode & 1
    if private and current_user.is_anonymous:
        flash("You will need to log in to gain access to this page.")
        return redirect(url_for("welcome"))

    if group.Image is not None:
        image = "/group_picture/" + str(group.ID)
    else:
        image = default_pictures_path + default_group_picture

    group_owner = User.query.filter_by(ID=group.User_ID).first()
    if group_owner is None:
        return redirect(url_for("lost"))

    if current_user.is_anonymous:
        user_id     = None
        username    = "Visitor"
        profile_pic = default_pictures_path + default_profile_picture
    else:
        user_id  = current_user.ID
        username = current_user.Login
        if current_user.Image is not None:
            profile_pic = "/profile_picture/" + str(current_user.ID)
        else:
            profile_pic = default_pictures_path + default_profile_picture
        db.insert_to_users(id=current_user.ID, last_group_id=group.ID)  # Updates last group for homepage

    member = db.get_membership(current_user)
    rights = db.getuserrights(current_user, group)

    closed = group.Mode & 2
    if closed and (rights["user"] or rights["visitor"]):
        threads = None
    else:
        threads = db.get_threads(group)

    form = request.args.get('form')
    if form:
        form = json.loads(form)
    return render_template("group_page.html", group_id=group.ID, groupname=group.Name, groupdescription=group.Description,
                           group_src=image, groupowner_id=group_owner.ID, group_owner=group_owner.Login, private=private,
                           closed=closed, threads=threads, user_id=user_id, username=username, img_src=profile_pic,
                           **member, **rights, form=form)


@app.route("/group_picture/<group_id>/")
def group_img(group_id):
    group = Group.query.filter_by(ID=group_id).first()
    if group is None:
        return redirect(url_for("lost"))
    private = group.Mode & 1
    if private and current_user.is_anonymous:
        flash("You will need to log in to gain access to this page.")
        return redirect(url_for("welcome"))

    if group.Image is None:
        return redirect(url_for("lost"))
    return send_file(io.BytesIO(group.Image), mimetype=group.Mimetype)  # Creates file in memory, then sends file to path


@app.route("/group_settings/<group_id>/", methods=["GET", "POST"])
@login_required
def group_settings(group_id):
    group = Group.query.filter_by(ID=group_id).first()
    if group is None:
        return redirect(url_for("lost"))

    admin = current_user.Mode & 2
    owner = False
    if not admin:
        owner = current_user.ID == group.User_ID
    if not admin and not owner:
        return redirect(url_for("tresspass"))

    if current_user.Image is not None:
        profile_pic = "/profile_picture/" + str(current_user.ID)
    else:
        profile_pic = default_pictures_path + default_profile_picture

    member = db.get_membership(current_user)

    if request.method == "GET":
        return render_template("group_settings.html", group_id=group.ID, user_id=current_user.ID, username=current_user.Login,
                               img_src=profile_pic, **member, admin=admin, owner=owner, form=request.form)

    name        = request.form.get("group_name", None)
    description = request.form.get("description", None)
    image       = request.files["group_image"]
    visibility  = request.form.get("visibility", None)

    # Values check
    if len(name) > 30:
        flash("Group name is too long. Maximum is 30 characters.")
        return render_template("group_settings.html", group_id=group.ID, user_id=current_user.ID, username=current_user.Login,
                               img_src=profile_pic, **member, admin=admin, owner=owner, form=request.form)
    if not db.check_groupname(name):
        flash("Group name is already taken. Please use different name.")
        return render_template("group_settings.html", group_id=group.ID, user_id=current_user.ID, username=current_user.Login,
                               img_src=profile_pic, **member, admin=admin, owner=owner, form=request.form)
    if description and len(description) > 2000:
        flash("Group description is too long. Maximum is 2000 characters.")
        return render_template("group_settings.html", group_id=group.ID, user_id=current_user.ID, username=current_user.Login,
                               img_src=profile_pic, **member, admin=admin, owner=owner, form=request.form)
    if image:
        blob = image.read()
        if sys.getsizeof(blob) > (2 * 1024 * 1024):
            flash("Group image is too big. Maximum allowed size is 2MB.")
            return render_template("group_settings.html", group_id=group.ID, user_id=current_user.ID, username=current_user.Login,
                                   img_src=profile_pic, **member, admin=admin, owner=owner, form=request.form)
        mimetype = image.mimetype
        image    = (blob, mimetype)
    if visibility:
        visibility = int(visibility)

    id = db.insert_to_group(id=group.ID, name=name, description=description, image=image, mode=visibility)
    flash("Your changes have been applied.")
    return redirect(url_for("group", group_id=id))


@app.route("/group_notifications/<group_id>/")
@login_required
def group_notifications(group_id):
    group = Group.query.filter_by(ID=group_id).first()
    if group is None:
        return redirect(url_for("lost"))

    admin = current_user.Mode & 2
    owner = False
    if not admin:
        owner = current_user.ID == group.User_ID
    moderator = Moderate.query.filter_by(User=current_user.ID, Group=group.ID).first()
    if not admin and not owner and not moderator:
        return redirect(url_for("tresspass"))

    if current_user.Image is not None:
        profile_pic = "/profile_picture/" + str(current_user.ID)
    else:
        profile_pic = default_pictures_path + default_profile_picture

    member = db.get_membership(current_user)

    notifications = db.get_applicants(group)
    return render_template("notifications.html", group_id=group.ID, notifications=notifications, user_id=current_user.ID, username=current_user.Login,
                           img_src=profile_pic, **member, admin=admin, owner=owner, moderator=moderator, form=request.form)


@app.route("/group_members/<group_id>/")
def members(group_id):
    group = Group.query.filter_by(ID=group_id).first()
    if group is None:
        return redirect(url_for("lost"))
    private = group.Mode & 1
    if private and current_user.is_anonymous:
        flash("You will need to log in to gain access to this page.")
        return redirect(url_for("welcome"))

    rights = db.getuserrights(current_user, group)
    closed = group.Mode & 2
    if closed and (rights["user"] or rights["visitor"]):
        return redirect(url_for("tresspass"))

    group_owner = User.query.filter_by(ID=group.User_ID).first()
    if group_owner is None:
        return redirect(url_for("lost"))
    if group_owner.Image is not None:
        owner_src = "/profile_picture/" + str(group_owner.ID)
    else:
        owner_src = default_pictures_path + default_profile_picture

    moderators = db.get_moderators(group)
    members = db.get_members(group)

    if current_user.is_anonymous:
        user_id     = None
        username    = "Visitor"
        profile_pic = default_pictures_path + default_profile_picture
    else:
        user_id  = current_user.ID
        username = current_user.Login
        if current_user.Image is not None:
            profile_pic = "/profile_picture/" + str(current_user.ID)
        else:
            profile_pic = default_pictures_path + default_profile_picture

    member = db.get_membership(current_user)
    return render_template("group_members.html", group_id=group.ID, group_owner=group_owner, owner_src=owner_src,
                           moderators=moderators, members=members, user_id=user_id, username=username,
                           img_src=profile_pic, **member, **rights)


@app.route("/apply/member/<group_id>/")
@login_required
def ask_mem(group_id):
    group = Group.query.filter_by(ID=group_id).first()
    if group is None:
        return redirect(url_for("lost"))

    owner     = current_user.ID == group.User_ID
    moderator = Moderate.query.filter_by(User=current_user.ID, Group=group.ID).first()
    member    = Is_member.query.filter_by(User=current_user.ID, Group=group.ID).first()
    if owner or moderator or member:
        return redirect(url_for("lost"))

    db.insert_to_applications(current_user.ID, group.ID, True)
    flash("Your request has been sent for a review.")
    return redirect(url_for("home"))


@app.route("/apply/moderator/<group_id>/")
@login_required
def ask_mod(group_id):
    group = Group.query.filter_by(ID=group_id).first()
    if group is None:
        return redirect(url_for("lost"))

    member = Is_member.query.filter_by(User=current_user.ID, Group=group.ID).first()
    if not member:
        return redirect(url_for("lost"))

    db.insert_to_applications(current_user.ID, group.ID, False)
    flash("Your request has been sent for a review.")
    return redirect(url_for("home"))


@app.route("/accept/<application_id>")
@login_required
def accept_application(application_id):
    application = Applications.query.filter_by(ID=application_id).first()
    if application is None:
        return redirect(url_for("lost"))
    group = Group.query.filter_by(ID=application.Group).first()
    if group is None:
        db.delete_from_db(application)
        return redirect(url_for("home"))

    # User rights
    admin     = current_user.Mode & 2
    owner     = current_user.ID == group.User_ID or admin
    moderator = Moderate.query.filter_by(User=current_user.ID, Group=group.ID).first()

    # Moderator request
    if not application.Membership and not owner:
        return redirect(url_for("tresspass"))
    # Membership request
    if not owner and not moderator:
        return redirect(url_for("tresspass"))

    user = User.query.filter_by(ID=application.User).first()
    if user is None:
        db.delete_from_db(application)
        return redirect(url_for("group_notifications", group_id=group.ID))

    membership    = Is_member.query.filter_by(User=user.ID, Group=group.ID).first()
    moderatorship = Moderate.query.filter_by(User=user.ID, Group=group.ID).first()
    if application.Membership and not membership and not moderatorship:
        db.insert_to_membership(user.ID, group.ID)
    elif not application.Membership and membership and not moderatorship:
        db.insert_to_moderate(user.ID, group.ID)
        db.delete_from_db(membership)

    db.delete_from_db(application)
    return redirect(url_for("group_notifications", group_id=group.ID))


@app.route("/reject/<application_id>")
@login_required
def reject_application(application_id):
    application = Applications.query.filter_by(ID=application_id).first()
    if application is None:
        return redirect(url_for("lost"))
    group = Group.query.filter_by(ID=application.Group).first()
    if group is None:
        db.delete_from_db(application)
        return redirect(url_for("home"))

    # User rights
    admin     = current_user.Mode & 2
    owner     = current_user.ID == group.User_ID or admin
    moderator = Moderate.query.filter_by(User=current_user.ID, Group=group.ID).first()

    # Moderator request
    if not application.Membership and not owner:
        return redirect(url_for("tresspass"))
    # Membership request
    if not owner and not moderator:
        return redirect(url_for("tresspass"))

    db.delete_from_db(application)
    return redirect(url_for("group_notifications", group_id=group.ID))


@app.route("/leave/<group_id>/")
@login_required
def leave_group(group_id):
    return redirect(url_for("kick", group_id=group_id, user_id=current_user.ID))


@app.route("/kick/group/<group_id>/<user_id>/")
@app.route("/kick/groups/<group_id>/<user_id>/")
@login_required
def kick(group_id, user_id):
    group = Group.query.filter_by(ID=group_id).first()
    if group is None:
        return redirect(url_for("lost"))
    user = User.query.filter_by(ID=user_id).first()
    if user is None:
        return redirect(url_for("lost"))

    # Kicked user rights
    is_member    = Is_member.query.filter_by(User=user.ID, Group=group.ID).first()
    is_moderator = Moderate.query.filter_by(User=user.ID, Group=group.ID).first()
    if not is_member and not is_moderator:
        return redirect(url_for("lost"))

    # Kicking user rights
    himself   = current_user.ID == user.ID
    admin     = current_user.Mode & 2
    owner     = current_user.ID == group.User_ID or admin or himself
    moderator = Moderate.query.filter_by(User=current_user.ID, Group=group.ID).first()

    if not owner and not moderator:
        return redirect(url_for("tresspass"))
    if is_moderator and not owner:
        return redirect(url_for("tresspass"))

    if is_member:
        db.delete_from_db(is_member)
    if is_moderator:
        db.delete_from_db(is_moderator)

    if himself:
        flash("You have left the group " + group.Name + ".")
    else:
        flash("User " + user.Login + " was kicked from the group " + group.Name + ".")
    return redirect(url_for("group", group_id=group.ID))


@app.route("/delete/group/<group_id>/")
@app.route("/delete/groups/<group_id>/")
@login_required
def delete_group(group_id):
    group = Group.query.filter_by(ID=group_id).first()
    if group is None:
        return redirect(url_for("lost"))

    admin = current_user.Mode & 2
    owner = current_user.ID == group.User_ID
    if not admin and not owner:
        return redirect(url_for("tresspass"))

    flash("You have deleted the group " + group.Name + ".")
    db.delete_from_db(group)
    return redirect(url_for("group", group_id=default_group_ID))


################################################################################
# Threads
################################################################################
@app.route("/create/thread/<group_id>/", methods=["POST"])
@login_required
def create_thread(group_id):
    group = Group.query.filter_by(ID=group_id).first()
    if group is None:
        return redirect(url_for("lost"))

    admin     = current_user.Mode & 2
    owner     = current_user.ID == group.User_ID
    moderator = Moderate.query.filter_by(User=current_user.ID, Group=group.ID).first()
    member    = Is_member.query.filter_by(User=current_user.ID, Group=group.ID).first()
    if not admin and not owner and not moderator and not member:
        return redirect(url_for("tresspass"))

    name        = request.form.get("thread_subject", None)
    description = request.form.get("description", None)

    # Values check
    if len(name) > 30:
        flash("Subject is too long. Maximum is 30 characters.")
        return redirect(url_for("group", group_id=group.ID, form=json.dumps(request.form)))
    if not db.check_threadname(group, name):
        flash("Subject is already taken.")
        return redirect(url_for("group", group_id=group.ID, form=json.dumps(request.form)))
    if description and len(description) > 2000:
        flash("Description is too long. Maximum is 2000 characters.")
        return redirect(url_for("group", group_id=group.ID, form=json.dumps(request.form)))

    id = db.insert_to_thread(group_id=group.ID, thread_name=name, description=description)
    return redirect(url_for("thread", group_id=group.ID, thread_id=id))


@app.route("/group/<group_id>/<thread_id>/")
@app.route("/groups/<group_id>/<thread_id>/")
def thread(group_id, thread_id):
    group = Group.query.filter_by(ID=group_id).first()
    if group is None:
        return redirect(url_for("group", group_id=default_group_ID))
    thread = Thread.query.filter_by(Group_ID=group.ID, ID=thread_id).first()
    if thread is None:
        return redirect(url_for("group", group_id=group.ID))
    closed  = group.Mode & 2
    private = group.Mode & 1
    if private and current_user.is_anonymous:
        flash("You will need to log in to gain access to this page.")
        return redirect(url_for("welcome"))

    rights = db.getuserrights(current_user, group)
    if closed and (rights["user"] or rights["visitor"]):
        return redirect(url_for("tresspass"))

    if current_user.is_anonymous:
        user_id     = None
        username    = "Visitor"
        profile_pic = default_pictures_path + default_profile_picture
    else:
        user_id  = current_user.ID
        username = current_user.Login
        if current_user.Image is not None:
            profile_pic = "/profile_picture/" + str(current_user.ID)
        else:
            profile_pic = default_pictures_path + default_profile_picture

    member = db.get_membership(current_user)
    return render_template("thread_page.html", group_id=group.ID, thread_id=thread.ID, groupname=group.Name, threadname=thread.Name,
                           description=thread.Description, posts=db.get_messages(thread, 50), user_id=user_id, username=username,
                           img_src=profile_pic, db=db, **member, **rights)


@app.route("/delete/thread/<group_id>/<thread_id>/")
@login_required
def delete_thread(group_id, thread_id):
    group = Group.query.filter_by(ID=group_id).first()
    if group is None:
        return redirect(url_for("lost"))
    thread = Thread.query.filter_by(Group_ID=group.ID, ID=thread_id).first()
    if thread is None:
        return redirect(url_for("lost"))

    # User rights
    admin     = current_user.Mode & 2
    owner     = current_user.ID == group.User_ID
    moderator = Moderate.query.filter_by(User=current_user.ID, Group=group.ID).first()
    if not admin and not owner and not moderator:
        return redirect(url_for("tresspass"))

    flash("Thread " + thread.Name + " was succesfully deleted.")
    db.delete_from_db(thread)
    return redirect(url_for("group", group_id=group.ID))


################################################################################
# Messages
################################################################################
@app.route("/create_message/<group_id>/<thread_id>/", methods=["POST"])
@login_required
def create_message(group_id, thread_id):
    group = Group.query.filter_by(ID=group_id).first()
    if group is None:
        return redirect(url_for("lost"))
    thread = Thread.query.filter_by(Group_ID=group.ID, ID=thread_id).first()
    if thread is None:
        return redirect(url_for("lost"))

    db.insert_to_messages(current_user, thread, message=request.form.get("content", None))
    return redirect(url_for('thread', group_id=group.ID, thread_id=thread.ID))

    ''' TODO previous version
    thread = Thread.query.filter_by(ID=thread_id).first()
    eprint(request.form.keys())
    db.insert_to_messages(current_user, thread, message=request.form['content'])
    return redirect(url_for('thread', group_id=group_id, thread_id=thread_id))
    '''


@app.route("/get_messages/<group_id>/<thread_id>/", methods=["GET"])
def get_messages(group_id, thread_id):
    return db.messages_to_json(db.get_messages(Thread.query.filter_by(ID=thread_id).first(), 200))


@app.route("/group/<group_id>/<thread_id>/<message_id>/delete/")
@app.route("/groups/<group_id>/<thread_id>/<message_id>/delete/")
@login_required
def delete_message(group_id, thread_id, message_id):
    group = Group.query.filter_by(ID=group_id).first()
    if group is None:
        return redirect(url_for("lost"))
    thread = Thread.query.filter_by(Group_ID=group.ID, ID=thread_id).first()
    if thread is None:
        return redirect(url_for("lost"))
    message = Messages.query.filter_by(ID_group=group.ID, Thread_name=thread.Name, ID=message_id).first()
    if message is None:
        return redirect(url_for("lost"))

    admin     = current_user.Mode & 2
    author    = current_user.ID == message.User_ID
    owner     = current_user.ID == group.User_ID
    moderator = Moderate.query.filter_by(User=current_user.ID, Group=group.ID).first()
    if not admin and not author and not owner and not moderator:
        return redirect(url_for("tresspass"))

    db.delete_from_db(message)
    return redirect(url_for('thread', group_id=group.ID, thread_id=thread.ID))


@app.route("/group/<group_id>/<thread_id>/<message_id>/inc/")
@app.route("/groups/<group_id>/<thread_id>/<message_id>/inc/")
@login_required
def increment(group_id, thread_id, message_id):
    rank_mutex.acquire()
    group = Group.query.filter_by(ID=group_id).first()
    if group is None:
        rank_mutex.release()
        return redirect(url_for("lost"))
    thread = Thread.query.filter_by(Group_ID=group.ID, ID=thread_id).first()
    if thread is None:
        rank_mutex.release()
        return redirect(url_for("lost"))
    message = Messages.query.filter_by(ID_group=group.ID, Thread_name=thread.Name, ID=message_id).first()
    if message is None:
        rank_mutex.release()
        return redirect(url_for("lost"))

    rank    = 0
    ranking = Ranking.query.filter_by(User=current_user.ID, Message=message.ID, Thread_name=thread.Name, ID_group=group.ID).first()
    if not ranking:
        rank = rank + 1
        db.insert_to_ranking(message=message, user=current_user, inc=True)
    elif ranking.Inc:
        rank = rank - 1
        db.delete_from_db(ranking)
    else:
        rank = rank + 1
        db.delete_from_db(ranking)

    db.insert_to_messages(id=message.ID, ranking=message.Rank + rank, author=message.User_ID, thread=thread)
    rank_mutex.release()
    return redirect(url_for('thread', group_id=group.ID, thread_id=thread.ID))


@app.route("/group/<group_id>/<thread_id>/<message_id>/dec/")
@app.route("/groups/<group_id>/<thread_id>/<message_id>/dec/")
@login_required
def decrement(group_id, thread_id, message_id):
    rank_mutex.acquire()
    group = Group.query.filter_by(ID=group_id).first()
    if group is None:
        rank_mutex.release()
        return redirect(url_for("lost"))
    thread = Thread.query.filter_by(Group_ID=group.ID, ID=thread_id).first()
    if thread is None:
        rank_mutex.release()
        return redirect(url_for("lost"))
    message = Messages.query.filter_by(ID_group=group.ID, Thread_name=thread.Name, ID=message_id).first()
    if message is None:
        rank_mutex.release()
        return redirect(url_for("lost"))

    rank    = 0
    ranking = Ranking.query.filter_by(User=current_user.ID, Message=message.ID, Thread_name=thread.Name, ID_group=group.ID).first()
    if not ranking:
        rank = rank - 1
        db.insert_to_ranking(message=message, user=current_user, inc=False)
    elif ranking.Inc:
        rank = rank - 1
        db.delete_from_db(ranking)
    else:
        rank = rank + 1
        db.delete_from_db(ranking)

    db.insert_to_messages(id=message.ID, ranking=message.Rank + rank, author=message.User_ID, thread=thread)
    rank_mutex.release()
    return redirect(url_for('thread', group_id=group.ID, thread_id=thread.ID))


################################################################################
# Other
################################################################################
@app.route("/search/", methods=["POST"])
def search():
    if current_user.is_anonymous:
        user_id     = None
        username    = "Visitor"
        profile_pic = default_pictures_path + default_profile_picture
        visitor = True
        group_id = default_group_ID
    else:
        user_id  = current_user.ID
        username = current_user.Login
        if current_user.Image is not None:
            profile_pic = "/profile_picture/" + str(current_user.ID)
        else:
            profile_pic = default_pictures_path + default_profile_picture
        visitor = False
        group_id = current_user.Last_group

    eprint(request.form.get("search", None))
    results = db.search_user_group(request.form.get("search", None))
    return render_template("search.html", **results, user_id=user_id, username=username, img_src=profile_pic, visitor=visitor, group_id=group_id)


@app.route("/egg/")
@app.route("/easter/")
@app.route("/easteregg/")
@app.route("/easter_egg/")
def egg():
    return render_template("egg_page.html")


@app.route("/tresspass/")
def tresspass():
    return render_template("tresspassing_page.html")


@app.route("/lost/")
def lost():
    return render_template("lost_page.html")


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def default_lost(path):
    return render_template("lost_page.html")


################################################################################
# Supporting functions
################################################################################
@app.before_request
def enforce_https():
    if request.headers.get("X-Forwarded-Proto") == "http":
        url = request.url.replace("http://", "https://", 1)
        code = 301
        return redirect(url, code=code)


@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(hours=1)
    session.modified = True


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


if __name__ == "__main__":
    app.run(debug=True)
