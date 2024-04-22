from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash,request,session
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm,RegisterNewUser,LoginForm,CommentForm
from sqlalchemy.sql import exists


'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)




# TODO: Configure Flask-Login
login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view='login'



# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    # ForeignKey should reference 'users.id'
    comments=db.relationship('Comment',backref='post',lazy=True)

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)  # Removed unique=True from password
    posts = db.relationship('BlogPost', backref='author', lazy=True)  # Changed lazy='True' to lazy=True
    comments=db.relationship('Comment',backref='commentor',lazy=True)

#defining the comments table
class Comment(db.Model):
    __tablename__ ='comments'
    id=db.Column(db.Integer,primary_key=True)
    comment=db.Column(db.Text)
    user_id=db.Column(db.Integer,db.ForeignKey('users.id'),nullable=False)
    post_id=db.Column(db.Integer,db.ForeignKey('blog_posts.id'),nullable=False)


#define a user loader callback function
def load_user(user_id):
    return User.query.get(int(user_id))

# TODO: Create a User table for all your registered users. 


with app.app_context():
    db.create_all()

login_manager.user_loader(load_user)

#creating a decorator function to check if the user is an admin or not
def admin_only(func):
    @wraps(func)
    def wrapper(*args,**kwargs):
        #code to check if the user is admin or not
        if not current_user.is_authenticated or current_user.id!=1:
            return abort(403)
        elif current_user.id!=1:
            return abort(403)
        return func(*args,**kwargs)
    return wrapper

# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register',methods=['GET','POST'])
def register():
    if request.method=='POST':
        new_user=User(name=request.form.get('name'),email=request.form.get('email'),password=generate_password_hash(request.form.get('password'),method='pbkdf2:sha256'))
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        session['isLogged']=True
        return redirect(url_for('get_all_posts'))
    user_form=RegisterNewUser()
    return render_template("register.html",form=user_form)



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        # Check if user exists and password is correct
        chk_pass=check_password_hash(user.password, password)
        if user and chk_pass:
            login_user(user)
            session['isLogged'] = True
            return redirect(url_for('get_all_posts'))
        else:
            # Flash message for incorrect email or password
            flash('Invalid email or password', 'error')

    login_form = LoginForm()
    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    session['isLogged']=False
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    isLogged=request.args.get('isLogged')
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    isLogged=session.get('isLogged',False)
    if current_user.is_authenticated:
        isLogged = True
        isAdmin = True if current_user.id == 1 else False  # Corrected syntax
    else:
        isLogged = False
        isAdmin = False  # You must also set isAdmin in the else block

    return render_template("index.html", all_posts=posts,isLogged=isLogged,isAdmin=isAdmin)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>",methods=['GET','POST'])
def show_post(post_id):
    if request.method=='POST':
        if current_user.is_authenticated:
            comment=request.form.get('comment')
            post_id=request.form.get('post_id')
            user_id=current_user.id
            new_comment=Comment(comment=comment,post_id=post_id,user_id=user_id)
            db.session.add(new_comment)
            db.session.commit()
            return redirect('/')
        else:
            flash('login to comment on the post')
            return redirect('/login')
    requested_post = db.get_or_404(BlogPost, post_id)
    comment_form=CommentForm()
    comments_for_post=Comment.query.filter_by(post_id=post_id).all()
    return render_template("post.html", post=requested_post,form=comment_form,isLogged=current_user.is_authenticated,comments=comments_for_post)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
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
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True, port=5002)
