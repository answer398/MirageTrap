from app.extensions import db
from app.models.admin_user import AdminUser


class AdminRepository:
    def get_by_id(self, user_id: int) -> AdminUser | None:
        return db.session.get(AdminUser, user_id)

    def get_by_username(self, username: str) -> AdminUser | None:
        return AdminUser.query.filter_by(username=username).first()

    def create(self, username: str, raw_password: str) -> AdminUser:
        user = AdminUser(username=username)
        user.set_password(raw_password)
        db.session.add(user)
        db.session.commit()
        return user

    def save(self, user: AdminUser) -> AdminUser:
        db.session.add(user)
        db.session.commit()
        return user
