from functools import wraps
from flask import abort
from flask_login import current_user
from .models import Permission

def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_funtion(*args, **kwargs):
            if not current_user.can(permission):
                abort(403)
            return f(*args, **kwargs)
        return decorated_funtion
    return decorator

def admin_required(f):
    return permission_required(Permission.ADMIN)(f)
    
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_funtion(*args, **kwargs):
            if not current_user.has_role(role):
                abort(403)
            return f(*args, **kwargs)
        return decorated_funtion
    return decorator