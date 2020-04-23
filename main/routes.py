from flask import Flask, render_template, url_for, flash, redirect, request, abort, Blueprint, make_response
from flask_login import current_user, login_required
#from hello import ShortenName
from webapp import db
from webapp.utils import send_email
from webapp.models import User, Role, Post, Permission
import datetime
from webapp.decorators import admin_required, permission_required, role_required, able_to_join

main = Blueprint('main', __name__)


@main.app_context_processor
def inject_permissions():
    return dict(Permission=Permission)

@main.app_context_processor
def inject_users():
    return dict(User=User)


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
        return redirect(url_for("posts.user_posts", username=username))
    if user.has_role('Individual'):
        flash('One cannot follow this type of user.', 'danger')
        return redirect(url_for('main.home'))
    current_user.follow(user)
    db.session.commit()
    send_email(user.email, 'A new Follower', 'email/notify', user=user, follower=current_user, following=True)
    flash('You are now following %s.' %username, 'success')
    return redirect(url_for("posts.user_posts", username=username))

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
    return redirect(url_for("posts.user_posts", username=username))

@main.route('/followers/<username>')
@login_required
def followers(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.', 'danger')
        return redirect(url_for('main.home'))
    if user.has_role('Individual'):
        flash('An Individual(user) account does not have followers', 'info')
        return redirect(url_for('main.followed', username=user.username))
    page = request.args.get('page', 1, type=int)
    pagination = user.followers.paginate(
        page, per_page=20, error_out=False
    )
    follows = [{'user': item.follower, 'timestamp': item.timestamp}
                for item in pagination.items]
    return render_template('account/follows.html', user=user, title='Followers of',
                            endpoint='main.followers', pagination=pagination, follows=follows)

@main.route('/followed/<username>')
@login_required
def followed(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.', 'danger')
        return redirect(url_for('main.home'))
    u = user.followed.filter_by(followed_id=current_user.id).first()
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

@main.route('/join_request/<shorten>')
@login_required
@able_to_join
def join_request(shorten):
    user = User.query.filter_by(shorten=shorten).first()
    if user is None:
        flash('Association does not exist.', 'danger')
        return redirect(url_for('main.home'))
    if current_user.is_a_member(user):
        flash('You already apart of this Association.', 'info')
        return redirect(url_for("posts.user_posts", shorten=shorten))
    if not user.has_role('Association'):
        flash('This user is not an association.', 'danger')
        return redirect(url_for('main.home'))
    current_user.temp_join(user)
    db.session.commit()
    send_email(user.email, 'Join Request', 'email/notify', user=user, member=current_user, join=True)
    flash('Your join request has been sent to %s.' %shorten, 'success')
    return redirect(url_for("posts.user_posts", username=user.username))

@main.route('/cancel/join_request/<shorten>')
@login_required
@able_to_join
def cancel_join_request(shorten):
    user = User.query.filter_by(shorten=shorten).first()
    if user is None:
        flash('Association does not exist.', 'danger')
        return redirect(url_for('main.home'))
    if current_user.is_a_member(user):
        flash('You already apart of this Association. leave instead', 'info')
        return redirect(url_for("posts.user_posts", username=user.username))
    if not user.has_role('Association'):
        flash('This user is not an association.', 'danger')
        return redirect(url_for('main.home'))
    current_user.temp_leave(user)
    db.session.commit()
    flash('Your join request to %s has been cancelled' %shorten, 'success')
    return redirect(url_for("posts.user_posts", username=user.username))

@main.route('/temporal/members')
@login_required
@role_required('Association')
def temp_members():
    user = User.query.filter_by(shorten=current_user.shorten).first()
    page = request.args.get('page', 1, type=int)
    pagination = user.temp_members.paginate(
        page, per_page=20, error_out=False
    )
    temp_joins = [{'user': item.temp_member, 'timestamp': item.timestamp}
                for item in pagination.items]
    return render_template('account/temp_members.html', user=user, title='Temporal Members of',
                            endpoint='main.temp_members', pagination=pagination, temp_joins=temp_joins)

@main.route('/accept/<username>')
@login_required
@role_required("Association")
def accept(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('User does not exist.', 'danger')
        return redirect(url_for('main.home'))
    if current_user.is_association_for(user):
        flash('user is already apart of this Association.', 'info')
        return redirect(url_for("posts.user_posts", username=username))
    if user.has_role('Association'):
        flash('This user is an association. Therefore cannot Join', 'danger')
        return redirect(url_for('main.home'))
    if not current_user.temp_is_association_for(user):
        flash('This user has not made any join request to your association. Therefore you cannot accept a join request', 'danger')
        return redirect(url_for('main.home'))
    user.join(current_user)
    user.temp_leave(current_user)
    db.session.commit()
    send_email(user.email, 'You are accepted', 'email/notify', user=user, org=current_user, accept=True)
    flash('%s is now a member.' %username, 'success')
    return redirect(url_for("posts.user_posts", username=user.username))
#todo > confirm leave >later
@main.route('/make_leave/<username>')
@login_required
@role_required("Association")
def make_leave(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('User does not exist.', 'danger')
        return redirect(url_for('main.home'))
    if not current_user.is_association_for(user):
        flash('user cannot leave an association which user have not joined.', 'danger')
        return redirect(url_for('main.home'))
    user.leave(current_user)
    db.session.commit()
    flash('Now %s is not a member.' %username, 'success')
    return redirect(url_for("posts.user_posts", username=user.username))

@main.route('/leave/<shorten>')
@login_required
@able_to_join
def leave(shorten):
    user = User.query.filter_by(shorten=shorten).first()
    if user is None:
        flash('Association does not exist.', 'danger')
        return redirect(url_for('main.home'))
    if not current_user.is_a_member(user):
        flash('You cannot leave an association which you have not joined.', 'danger')
        return redirect(url_for('main.home'))
    current_user.leave(user)
    db.session.commit()
    flash('Now you are not a member of %s.' %shorten, 'success')
    return redirect(url_for("posts.user_posts", username=user.username))


@main.route('/members/<shorten>')
@login_required
def members(shorten):
    user = User.query.filter_by(shorten=shorten).first()
    if user is None:
        flash('Invalid user.', 'danger')
        return redirect(url_for('main.home'))
    if not user.has_role('Association'):
        flash('User is not an association account', 'danger')
        return redirect(url_for('main.home'))
    page = request.args.get('page', 1, type=int)
    pagination = user.members.paginate(
        page, per_page=20, error_out=False
    )
    joins = [{'user': item.member, 'timestamp': item.timestamp}
                for item in pagination.items]
    return render_template('account/joins.html', user=user, title='Members of',
                            endpoint='main.members', pagination=pagination, joins=joins)
@main.route('/associations/<username>')
@login_required
def associations(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.', 'danger')
        return redirect(url_for('main.home'))
    if user.has_role('Association'):
        flash('User is an association account. It does not join other associations', 'danger')
        return redirect(url_for('main.home'))
    page = request.args.get('page', 1, type=int)
    pagination = user.association.paginate(
        page, per_page=20, error_out=False
    )
    joins = [{'user': item.association, 'timestamp': item.timestamp}
                for item in pagination.items]
    return render_template('account/joins.html', user=user, title='Associations of',
                            endpoint='main.associations', pagination=pagination, joins=joins)

@main.route('/unnotify/<username>')
@login_required
def unnotify(username):
    user = User.query.filter_by(username=username).first()
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
    return redirect(url_for('posts.user_posts', username=username))