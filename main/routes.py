from flask import Flask, render_template, url_for, flash, redirect, request, abort, Blueprint
#from hello import ShortenName
from webapp.models import User, Role, Post, Permission
import datetime

main = Blueprint('main', __name__)


@main.app_context_processor
def inject_permissions():
    return dict(Permission=Permission)

@main.route('/')
@main.route('/home')
def home():
    page = request.args.get('page', 1, type=int)
    posts=Post.query.order_by(Post.date_posted.desc()).paginate(per_page=4, page=page)
    return render_template('main/index.html', active_home='active', datetime=datetime, current_time=datetime.datetime.utcnow(), posts=posts)

@main.route('/about')
def about():
    return render_template('main/about.html', title='About', active_about='active')

