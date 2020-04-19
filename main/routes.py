from flask import Flask, render_template, url_for, flash, redirect, request, abort, Blueprint, make_response
from flask_login import current_user, login_required
#from hello import ShortenName
from webapp import db
from webapp.models import User, Role, Post, Permission
import datetime
from webapp.decorators import admin_required, permission_required, role_required

main = Blueprint('main', __name__)


@main.app_context_processor
def inject_permissions():
    return dict(Permission=Permission)

@main.route('/')
@main.route('/home')
def home():
    page = request.args.get('page', 1, type=int)
    show_followed = False
    if current_user.is_authenticated:
        show_followed = bool(request.cookies.get('show_followed', ''))
    if show_followed:
        query = current_user.followed_posts
    else:
        query = Post.query
    posts=query.order_by(Post.date_posted.desc()).paginate(page, per_page=4, error_out=False)
    return render_template('main/index.html', active_home='active', datetime=datetime, current_time=datetime.datetime.utcnow(), posts=posts, show_followed=show_followed)

@main.route('/about')
def about():
    return render_template('main/about.html', title='About', active_about='active')

@main.route('/follow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.', 'danger')
        return redirect(url_for('main.home'))
    if current_user.is_following(user):
        flash('You already following this user.', 'info')
        return redirect(url_for("posts.userPosts", username=username))
    if user.has_role('Individual'):
        flash('One cannot follow this type of user.', 'danger')
        return redirect(url_for('main.home'))
    current_user.follow(user)
    db.session.commit()
    flash('You are now following %s.' %username, 'success')
    return redirect(url_for("posts.userPosts", username=username))

@main.route('/unfollow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.', 'danger')
        return redirect(url_for('main.home'))
    if not current_user.is_following(user):
        flash('You cannot unfollow a user which you have not followed.', 'danger')
        return redirect(url_for('main.home'))
    current_user.unfollow(user)
    db.session.commit()
    flash('You have now unfollowed %s.' %username, 'success')
    return redirect(url_for("posts.userPosts", username=username))

@main.route('/followers/<username>')
def followers(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.', 'danger')
        return redirect(url_for('main.home'))
    page = request.args.get('page', 1, type=int)
    pagination = user.followers.paginate(
        page, per_page=20, error_out=False
    )
    follows = [{'user': item.follower, 'timestamp': item.timestamp}
                for item in pagination.items]
    return render_template('account/follows.html', user=user, title='Followers of',
                            endpoint='main.followers', pagination=pagination, follows=follows)

@main.route('/followed/<username>')
def followed(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.', 'danger')
        return redirect(url_for('main.home'))
    page = request.args.get('page', 1, type=int)
    pagination = user.followed.paginate(
        page, per_page=20, error_out=False
    )
    follows = [{'user': item.followed, 'timestamp': item.timestamp}
                for item in pagination.items]
    return render_template('account/follows.html', user=user, title='Following',
                            endpoint='main.followed', pagination=pagination, follows=follows)

@main.route('/all_posts')
@login_required
def show_all():
    resp = make_response(redirect(url_for('main.home')))
    resp.set_cookie('show_followed', '', max_age= - 130*24*60*60)#30days
    return resp
@main.route('/followed_posts')
@login_required
def show_followed():
    resp = make_response(redirect(url_for('main.home')))
    resp.set_cookie('show_followed', '1', max_age=30*24*60*60)#30days
    return resp