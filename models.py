from datetime import datetime
from flask import current_app, url_for, redirect, request, g, render_template, abort
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from webapp import db, login_manager, admin#, create_app
from flask_login import UserMixin, current_user, AnonymousUserMixin
from flask_admin import BaseView, expose
from flask_admin.contrib.sqla import ModelView
from flask_admin.model.form import InlineFormAdmin
from flask_admin.menu import MenuCategory, MenuView, MenuLink, SubMenuCategory  # noqa: F401

#from webapp.forms import LoginForm
@current_app.shell_context_processor
def make_shell_context():
    return dict(db=db, User=User, Role=Role, Post=Post, Temp_user=Temp_user, Permission=Permission, Follow=Follow, Join=Join, Temp_Join=Temp_Join)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


########################################################
class Permission:
    FOLLOW = 1
    JOIN = 2
    WRITE = 4
    COMMENT = 8
    MODERATE = 16
    ADMIN = 32

##########TEMP SECTION#################

class Temp_user(db.Model):
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer(), primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    temail = db.Column(db.String(50), unique=True, nullable=False)
    trole = db.Column(db.String(50), nullable=False)
    used = db.Column(db.Integer())
    date = db.Column(db.DateTime(), default=datetime.utcnow)

    def __init__(self, **kwargs):
        super(Temp_user, self).__init__(**kwargs)
        if self.used is None:
            self.used = 0
    
    def add_used(self, u=1):
        self.used += u
        db.session.commit()

    def delete(self):
        if self.used > 5:
            db.session.delete(self)
            db.session.commit()

    @staticmethod
    def makedate():
        users = Temp_user.query.all()
        for user in users:    
            if user.date is None:
                user.date = datetime.utcnow()
                #db.session.commit()

    def ping(self):
        now = datetime.utcnow()
        if self.date:
            delta = now - self.date
            weeks = delta.days/7
            if weeks >= 1:
                db.session.delete(self)
                db.session.commit()
##############TEMP SECTION#############

# Define the Role data-model
class Role(db.Model):
    __tablename__ = 'roles'
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __repr__(self):
        return f"{self.name}"

    def __init__(self, **kwargs):
        super(Role, self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions = 0


    def add_permission(self, perm):
        if not self.has_permission(perm):
            self.permissions += perm

    def remove_permission(self, perm):
        if self.has_permission(perm):
            self.permissions -= perm

    def reset_permissions(self):
        self.permissions = 0

    def has_permission(self, perm):
        return self.permissions & perm == perm
    
    @staticmethod
    def insert_roles():
        roles={
            'Individual' : [Permission.FOLLOW, Permission.JOIN, Permission.COMMENT],
            'Association' : [Permission.COMMENT, Permission.WRITE],
            'Scholar' : [Permission.FOLLOW, Permission.JOIN, Permission.COMMENT, Permission.WRITE],
            'Moderator' : [Permission.FOLLOW, Permission.JOIN, Permission.COMMENT, Permission.WRITE, Permission.MODERATE],
            'admin' : [Permission.FOLLOW, Permission.JOIN, Permission.COMMENT, Permission.WRITE, Permission.MODERATE, Permission.ADMIN]
        }
        default_role = 'Individual'
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.reset_permissions()
            for perm in roles[r]:
                role.add_permission(perm)
            role.default = (role.name == default_role)
            db.session.add(role)
        db.session.commit()

#the follows association table as a model
class Follow(db.Model):
    __tablename__ = 'follows'
    __table_args__ = {'extend_existing': True}
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    notify = db.Column(db.String)

    def __init__(self, **kwargs):
        super(Follow, self).__init__(**kwargs)
        self.notify = "has started following you."
        
    @staticmethod
    def show():
        f=Follow.query.all()
        for i in f:
            print(i.notify)

    @staticmethod
    def reset():
        f=Follow.query.all()
        for i in f:
                db.session.delete(i)
        db.session.commit()
        User.add_self_follows()
        User.unnotify()
#the join association table as a model
class Temp_Join(db.Model):
    temp_member_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    temp_association_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    notify = db.Column(db.String)

    #?further questions
    why_join = db.Column(db.Text)
    want_to_achieve = db.Column(db.Text)
    willing_to_offer = db.Column(db.Text)

    def __init__(self, **kwargs):
        super(Temp_Join, self).__init__(**kwargs)
        self.notify = "has sent you a join request."
    @staticmethod
    def reset():
        j=Temp_Join.query.all()
        for i in j:
                db.session.delete(i)
        db.session.commit()
class Join(db.Model):
    __tablename__ = 'joins'
    member_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    association_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    notify = db.Column(db.String)

    #?further questions
    why_join = db.Column(db.Text)
    want_to_achieve = db.Column(db.Text)
    willing_to_offer = db.Column(db.Text)

    def __init__(self, **kwargs):
        super(Join, self).__init__(**kwargs)
        self.notify = "has accepted your join request"
    @staticmethod
    def reset():
        j=Join.query.all()
        for i in j:
                db.session.delete(i)
        db.session.commit()

# Define User data-model
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)

    # User Authentication fields
    #code = db.Column(db.String(20))
    phone = db.Column(db.String(), unique=True)
    email = db.Column(db.String(255), nullable=False, unique=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    image_file = db.Column(db.String(60), nullable=False, default='default.jpg')

    #tracking
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)
    confirmed_at = db.Column(db.DateTime())
    confirmed = db.Column(db.Boolean(), default=False)
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow)
    #location = db.Column(db.String())

    # User fields
    active = db.Column(db.Boolean(), default=True)
    #! shorten => username
    or_name = db.Column(db.String(50), unique=True)
    shorten = db.Column(db.String(50))
    
    f_name = db.Column(db.String())
    l_name = db.Column(db.String())
    address = db.Column(db.String())
    # futher details
    #?dob = db.Column(db.Date)
    #?gender = db.Column(db.String)

    # Relationships:
    ##posts
    posts = db.relationship('Post', backref='author', lazy=True)
    ##roles
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    ##follows
    followed = db.relationship('Follow', foreign_keys=[Follow.follower_id], backref=db.backref('follower', lazy='joined'),
                            lazy='dynamic', cascade='all, delete-orphan')
    followers = db.relationship('Follow', foreign_keys=[Follow.followed_id], backref=db.backref('followed', lazy='joined'),
                            lazy='dynamic', cascade='all, delete-orphan')
    ##joining association
    members = db.relationship('Join', foreign_keys=[Join.association_id], backref=db.backref('association', lazy='joined'),
                            lazy='dynamic', cascade='all, delete-orphan')
    association = db.relationship('Join', foreign_keys=[Join.member_id], backref=db.backref('member', lazy='joined'),
                            lazy='dynamic', cascade='all, delete-orphan')
    ##request joining association
    temp_members = db.relationship('Temp_Join', foreign_keys=[Temp_Join.temp_association_id], backref=db.backref('temp_association', lazy='joined'),
                            lazy='dynamic', cascade='all, delete-orphan')
    temp_association = db.relationship('Temp_Join', foreign_keys=[Temp_Join.temp_member_id], backref=db.backref('temp_member', lazy='joined'),
                            lazy='dynamic', cascade='all, delete-orphan')

    # TODO role.id
    def has_role(self, urole):
        # db is your database session.
        _role = Role.query.filter_by(name=urole).first()
        #query = db.query(Role).filter(Role.name == role).first()
        if _role:
            if _role.id == self.role_id:
                return True
        return False

    def delete(self, urole):
        if self.has_role(urole):
            if self.posts != None:
                _posts=Post.query.filter_by(author=self).all()
                for p in _posts:
                    db.session.delete(p)
            db.session.delete(self)
            db.session.commit()
  
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role_id is None:
            if 'website.an@gmail.com' == self.email:#! current_app.config['username']
                self.role = Role.query.filter_by(name='admin').first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()
        if not self.has_role('Individual'):
            self.follow(self)

    def can(self, perm):
        return self.role is not None and self.role.has_permission(perm)

    def is_administrator(self):
        return self.can(Permission.ADMIN)

    #def group(self):
    #    if self.role
    #todo > association should not follow anyone
    def follow(self, user):
        if not user.has_role('Individual'):    
            if not self.is_following(user):
                f = Follow(follower=self, followed=user)
                db.session.add(f)
    def unfollow(self, user):
        if self.is_following(user):
            f = self.followed.filter_by(followed_id=user.id).first()
            if f:
                db.session.delete(f)
    def is_following(self, user):
        if user.id is None:
            return False
        if user.has_role('Individual'):
            return False
        return self.followed.filter_by(followed_id=user.id).first() is not None
    def is_followed_by(self, user):
        if user.id is None:
            return False
        return self.followers.filter_by(follower_id=user.id).first() is not None
    @property
    def followed_posts(self):
        return Post.query.join(Follow, Follow.followed_id == Post.user_id)\
            .filter(Follow.follower_id == self.id)
    
    @staticmethod
    def unnotify():
        for user in User.query.all():
            if user.is_following(user):
                f = user.followed.filter_by(followed_id=user.id).first()
                if f:
                    f.notify=None
                    db.session.commit()

    #todo > temp_join
    def join(self, user, **kwargs):
        if user.has_role('Association'):
            if not self.is_a_member(user):
                j = Join(member=self, association=user, **kwargs)
                db.session.add(j)
                self.follow(user)
    def leave(self, user):
        j = self.association.filter_by(association_id=user.id).first()
        if j:
            db.session.delete(j)
    def is_a_member(self, user):
        if user.id is None:
            return False
        if not user.has_role('Association'):
            return False
        return self.association.filter_by(association_id=user.id).first() is not None
    def is_association_for(self, user):
        if user.id is None:
            return False
        if user.has_role('Association'):
            return False
        return self.members.filter_by(member_id=user.id).first() is not None

    def temp_join(self, user, **kwargs):
        if user.has_role('Association'):
            if not self.temp_is_a_member(user):
                j = Temp_Join(temp_member=self, temp_association=user, **kwargs)
                print(j)
                db.session.add(j)
                self.follow(user)
    def temp_leave(self, user):
        j = self.temp_association.filter_by(temp_association_id=user.id).first()
        if j:
            db.session.delete(j)
    def temp_is_a_member(self, user):
        if user.id is None:
            return False
        if not user.has_role('Association'):
            return False
        return self.temp_association.filter_by(temp_association_id=user.id).first() is not None
    def temp_is_association_for(self, user):
        if user.id is None:
            return False
        if user.has_role('Association'):
            return False
        return self.temp_members.filter_by(temp_member_id=user.id).first() is not None

    def notify(self, parameter_list):
        pass

    @staticmethod
    def add_self_follows():
        for user in User.query.all():
            if not user.is_following(user):
                user.follow(user)
                db.session.add(user)
                db.session.commit()

    def generate_token(self, expires_in=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expires_in)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def verify_token(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        if data.get('user_id') != self.id:
            return False
        return True

    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        if data.get('user_id') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True

    def ping(self):
        self.last_seen = datetime.utcnow()
        db.session.add(self)
        db.session.commit()
        
    def __repr__(self):
        return f"('{self.id}', '{self.role}', '{self.username}')"

class AnonymousUser(AnonymousUserMixin):
    def has_role(self, urole):#TODO has_role and is authenticated
        return False
    def can(self, permissions):
        return False
    def is_administrator(self):
        return False
    def is_following(self, user):
        return False
    def is_followed_by(self, user):
        return False
    def is_a_member(self, user):
        return False
    def is_association_for(self, user):
        return False
    
login_manager.anonymous_user = AnonymousUser
login_manager.session_protection = "strong"


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    img_file = db.Column(db.String(60))
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)



class Association(User):
    pass
class Scholar(User):
    pass
class Individual(User):
    pass

class Ass_Post(Association):
    pass
class Sch_Post(Scholar):
    pass

class MyView(BaseView):
    @expose('/')
    def index(self):
        return render_template('')

class UserView(ModelView):
    @expose('/admin/', methods=('GET', 'POST'))
    def create_view(self):
        return self.render('admin.register_login.html')

class MyModelView(ModelView):
    def is_accessible(self):
        if current_user.has_role('admin'):
            return True

    def inaccessible_callback(self, name, **kwargs):
        # redirect to login page if user doesn't have access
        abort(403)

class users_View(MyModelView):
    column_exclude_list = ['password', 'image_file', 'code', 'f_name', 'l_name', 'address', 'phone','or_name', 'shorten']
    form_excluded_columns = []

class follow_view(MyModelView):
    pass

class Ass_View(MyModelView):
    column_exclude_list = ['password', 'image_file', 'code', 'f_name', 'l_name', 'address', 'phone']
    form_excluded_columns = ['password', 'image_file', 'code', 'f_name', 'l_name', 'address', 'phone']

class Sch_View(MyModelView):
    column_exclude_list = ['password', 'image_file', 'code', 'or_name', 'shorten']
    form_excluded_columns = ['password', 'image_file', 'code', 'or_name', 'shorten']

class Ind_View(MyModelView):
    column_exclude_list = ['password', 'image_file', 'code', 'f_name', 'l_name', 'address', 'phone', '']
    form_excluded_columns = ['password', 'image_file', 'code', 'f_name', 'l_name', 'address', 'phone']

class PostView(MyModelView):
    column_exclude_list = ['img_file', 'content']

class RoleView(MyModelView):
    column_exclude_list = None
class TempView(MyModelView):
    column_exclude_list = None
    
    # column_select_related_list = (Role.users)
    #form_columns = ['name', 'users']
    #inline_models =(MyInlineModelForm(MyInlineModel),)




admin.add_view(users_View(User, db.session))
#admin.add_view(Ass_View(Association, db.session, category="Users"))
#admin.add_view(Sch_View(Scholar, db.session, category="Users"))
admin.add_view(follow_view(Follow, db.session))
admin.add_view(RoleView(Role, db.session))
admin.add_view(PostView(Post, db.session))

admin.add_view(TempView(Temp_user, db.session))

#admin.add_sub_category(name="Links", parent_name="Users")
admin.add_link(MenuLink(name='Home Page', url='/', category='Links'))

#admin.add_view(RoleModelView(Role, db.session))
#admin.add_view(ModelView(User, db.session))
#admin.add_view(ModelView(Post, db.session))

#db.drop_all()
#db.drop_all()

#db.create_all(app=current_app)
#Temp_user.drop()



#myusers = [Scholar, Association, Individual]
