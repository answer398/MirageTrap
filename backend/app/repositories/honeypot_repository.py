from app.extensions import db
from app.models.honeypot_instance import HoneypotInstance


class HoneypotRepository:
    def create(self, **kwargs) -> HoneypotInstance:
        item = HoneypotInstance(**kwargs)
        db.session.add(item)
        db.session.commit()
        return item

    def save(self, instance: HoneypotInstance) -> HoneypotInstance:
        db.session.add(instance)
        db.session.commit()
        return instance

    def delete(self, instance: HoneypotInstance) -> None:
        db.session.delete(instance)
        db.session.commit()

    def get_by_id(self, instance_id: int) -> HoneypotInstance | None:
        return db.session.get(HoneypotInstance, instance_id)

    def get_by_honeypot_id(self, honeypot_id: str) -> HoneypotInstance | None:
        return HoneypotInstance.query.filter(HoneypotInstance.honeypot_id == honeypot_id).first()

    def get_by_container_name(self, container_name: str) -> HoneypotInstance | None:
        return HoneypotInstance.query.filter(HoneypotInstance.container_name == container_name).first()

    def get_by_exposed_port(self, exposed_port: int) -> HoneypotInstance | None:
        return HoneypotInstance.query.filter(HoneypotInstance.exposed_port == exposed_port).first()

    def list_all(self) -> list[HoneypotInstance]:
        return HoneypotInstance.query.order_by(HoneypotInstance.id.asc()).all()

    def list_paginated(self, *, page: int = 1, page_size: int = 20) -> dict:
        pagination = HoneypotInstance.query.order_by(
            HoneypotInstance.updated_at.desc(),
            HoneypotInstance.id.desc(),
        ).paginate(page=page, per_page=page_size, error_out=False)

        return {
            "items": pagination.items,
            "page": pagination.page,
            "page_size": pagination.per_page,
            "total": pagination.total,
            "pages": pagination.pages,
        }
