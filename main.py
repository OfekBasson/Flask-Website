from os import abort
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from hashlib import md5



app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

#Initiallizing flask-login
login_manager = LoginManager()
login_manager.init_app(app)

#Initiallizing the base and the relationship between tables
Base = declarative_base()

#Initiallizing Gravater (pictures)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONFIGURE TABLES
#User table
class User(UserMixin, db.Model, Base):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    #URL of the Gravatar image
    gravatar_url = db.Column(db.String(250))
    # List of all blog posts for the particular user. Connected to BlogPost table
    posts = relationship('BlogPost', back_populates='author')
    #List of all comments for the particular user. Connected to Comment table
    comments = relationship('Comment', back_populates='comment_author')

#Posts table
class BlogPost(db.Model, Base):
    __tablename__ = 'blog_posts'
    id = db.Column(db.Integer, primary_key=True)
    #Initiallizing One-To-Many relationship between posts to author (one author, many posts)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = relationship('User', back_populates='posts')
    #More attributes
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    #List of the comments for the particular post, connected to Comment table
    comments = relationship('Comment', back_populates='post')

#Commrnts table
class Comment(db.Model, Base):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(250), nullable=False)
    #Initiallizing One-To-Many relationship between comments to author (one author, many comments)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    comment_author = relationship('User', back_populates='comments')
    # Initiallizing One-To-Many relationship between comments to post (one post, many comments)
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    post = relationship('BlogPost', back_populates='comments')



db.create_all()



#שAdmin only decorator
def admin_only(func):
    @wraps(func)
    def wrapper_function(*args, **kwargs):
        # Checks if a user (not admin) is authenticated.
        if current_user.is_authenticated:
            if current_user.id != 1:
                return abort(403)
        # Checks if there is no authenticated user right now
        if not current_user.is_authenticated:
            return abort(403)
        # If the admin is authenticated - execute "func"
        return func(*args, **kwargs)
    return wrapper_function

#Loading user function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#Website pages and functions

#Homepage that shows all the posts
@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    is_admin = False
    if current_user.is_authenticated:
        if current_user.id == 1:
            is_admin = True
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, is_admin=is_admin)

#Registering page
@app.route('/register', methods=["GET", "POST"])
def register():
    #Creating the register form
    form = RegisterForm()

    if form.validate_on_submit():
        # Test if the email address is already in the db.
        exist_user = db.session.query(User).filter(User.email == request.form["email"]).first()
        if exist_user:
            return redirect(url_for("login", exist=True, logged_in=current_user.is_authenticated))
        #If the user isn't exist - register it.
        hashed_and_salted_password = generate_password_hash(form.password.data, method="pbkdf2:sha256", salt_length=8)
        #Defining gravatar image
        lower_email = form.email.data.lower()
        encoded_lower_email = lower_email.encode()
        hashed_lower_encoded_email = md5(encoded_lower_email).hexdigest()
        img_request_URL = f"https://www.gravatar.com/avatar/{hashed_lower_encoded_email}"
        #Creating user and adding it to the db
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hashed_and_salted_password,
            gravatar_url=img_request_URL
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)


        return redirect(url_for("get_all_posts", logged_in=current_user.is_authenticated))
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        #Looking for the specific user
        user = db.session.query(User).filter(User.email == form.email.data).first()

        #If the specific user doesn't exist - flash it
        if not user:
            flash("This email does not exist. Please try another email address.")
            return redirect(url_for("login", logged_in=current_user.is_authenticated))

        #If the specific user exist and the password is correct - log in
        else:
            if check_password_hash(user.password, request.form["password"]):
                login_user(user)
                return redirect(url_for("get_all_posts", logged_in=current_user.is_authenticated))
            # If the specific user exist and the password is **incorrect** - flash it
            else:
                flash("Wrong password, try again!")

    #If the user already exist (and we were sent from the register page) - announce it
    if request.args.get("exist"):
        flash("You are already signed up with this email address. Log in instead.")

    if request.args.get("did_comment_without_logging_in"):
        flash("You have to log in or register to comment.")

    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    # Checks if the user is an admin (to decide if to show the "edit post" button)
    is_admin = False
    if current_user.is_authenticated:
        if current_user.id == 1:
            is_admin = True
    #Posting comment
    if form.validate_on_submit():
        #If not logged in - redirect to login and flash it.
        if not current_user.is_authenticated:
            return redirect(url_for("login", logged_in=current_user.is_authenticated, did_comment_without_logging_in=True))
        #Creating the new post and adding it to the db
        new_comment = Comment(
            text=form.comment.data,
            author_id=current_user.id,
            comment_author=current_user,
            post_id=post_id,
            post=db.session.query(BlogPost).filter(BlogPost.id == post_id).first()
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))
    #Choosing all the related-comments
    comments = BlogPost.query.get(post_id).comments

    return render_template("post.html",
                           post=requested_post,
                           logged_in=current_user.is_authenticated,
                           is_admin=is_admin,
                           form=form,
                           comments=comments,
                           )


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)

@app.route("/new-post", methods=["POST", "GET"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        #Creating and adding new post
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            author=current_user,
            date=date.today().strftime("%B %d, %Y"),
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))

    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=["POST", "GET"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts', logged_in=current_user.is_authenticated))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
