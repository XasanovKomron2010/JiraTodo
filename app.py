import os
from flask import Flask
from models.user import User
from models.todo import Todo
from models.role import Role
from datetime import timedelta
from models.project import Project
from models.permission import Permission
from models.project_column import ProjectColumn
from models.user_permission import UserPermission
from models.role_permission import RolePermission
from models import db, migrate, login_manager

root = Flask(__name__)
root.config["DEBUG"] = True
# root.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=3)
root.config["UPLOADS_FOLDER"] = os.path.join(os.getcwd(), "static", "uploads")
root.config["SECRET_KEY"] = "Komronbek_2010"
root.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://postgres:Komronbek_2010@localhost:5432/test"
root.config['WTF_CSRF_ENABLED'] = False
root.config['WTF_CSRF_SECRET_KEY'] = "12342354j34j"

db.init_app(root)
migrate.init_app(root,db)
login_manager.init_app(root)

if __name__ == '__main__':
    from routes.error_route import page_not_found, permission_denied, unauthorized

    root.register_error_handler(404, page_not_found)
    root.register_error_handler(401, unauthorized)
    root.register_error_handler(403, permission_denied)

    from routes.auth_route import *
    from routes.main_route import *
    from routes.admin_route import *
    from routes.team_lead_route import *    

    root.run(debug=True, port=8080, host='0.0.0.0')