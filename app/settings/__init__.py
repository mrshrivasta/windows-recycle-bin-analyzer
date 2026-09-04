"""
Settings module — Windows Recycle Bin Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta
"""
from app.database import db, UserSettings


def get_or_create_settings(user):
    settings = UserSettings.query.filter_by(user_id=user.id).first()
    if not settings:
        settings = UserSettings(user_id=user.id)
        db.session.add(settings)
        db.session.commit()
    return settings


def update_settings(user, **kwargs):
    settings = get_or_create_settings(user)
    for key, value in kwargs.items():
        if hasattr(settings, key) and value is not None:
            setattr(settings, key, value)
    db.session.commit()
    return settings
