from flask import Flask, render_template, url_for, flash, redirect, request, abort, Blueprint
#from hello import ShortenName
from webapp import db
from webapp.posts.forms import PostForm
from webapp.models import User, Role, Post, Permission
from flask_login import current_user, login_required
from webapp.utils import save_pic
from webapp.decorators import permission_required

posts = Blueprint('posts', __name__)


@posts.app_context_processor
def inject_permissions():
    return dict(Permission=Permission)


##################################POSTS#################################
@posts.route('/post/new', methods=['POST','GET'])
@login_required
@permission_required(Permission.WRITE)
def newPost():
    form = PostForm()
    if form.validate_on_submit():
        if form.img_file.data:
            pic_file = save_pic(form.img_file.data,480,480)
            post = Post(title=form.title.data, content=form.content.data, img_file=pic_file, author=current_user)
        else:
            post = Post(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash(f'Your post has been created successfully!', 'success')
        return redirect(url_for('main.home'))
    return render_template('posts/new_post.html', title="New Post", form=form, active_post='active', legend="Create a New Post")

@posts.route('/post/<int:post_id>')
def VPost(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('posts/post.html', title=post.title, post=post)


@posts.route('/post/<int:post_id>/update', methods=['POST','GET'])
@login_required
def updatePost(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        if form.img_file.data:
            pic_file = save_pic(form.img_file.data,480,480)
            post.img_file=pic_file
        post.title=form.title.data
        post.content=form.content.data
        db.session.commit()
        flash('Your post has been updated!', 'success')
        return redirect(url_for('posts.VPost', post_id=post.id))
    elif request.method == 'GET':
        form.title.data=post.title
        form.content.data=post.content
    return render_template('posts/new_post.html', title=post.title, post=post, form=form, legend='Update Post')

@posts.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def deletePost(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Your post has been deleted', 'success')
    return redirect(url_for('main.home'))

@posts.route('/user/<string:username>')
def user_posts(username):
    page = request.args.get('page', 1, type=int)
    user = User.query.filter_by(username=username).first_or_404()
    #deletes notify message
    if current_user.is_authenticated:
        u = current_user.association.filter_by(association_id=user.id).first()
        if u and u.notify:
            u.notify=''
            db.session.commit()
        u = user.followed.filter_by(followed_id=current_user.id).first()
        if u and u.notify:
            u.notify=''
            db.session.commit()
    posts=Post.query.filter_by(author=user)\
        .order_by(Post.date_posted.desc())\
        .paginate(per_page=5, page=page)
    return render_template('posts/user_posts.html', posts=posts, user=user)
