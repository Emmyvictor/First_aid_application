# normalize_guides.py
from app import app, db, EmergencyGuide
import json


def force_list(value):
    """
    Converts any value (string, list, None) into a proper Python list.
    """
    if value is None or value == "":
        return []

    # Already Python list
    if isinstance(value, list):
        return value

    # Try JSON decode
    try:
        decoded = json.loads(value)
        if isinstance(decoded, list):
            return decoded
    except:
        pass

    # Fallback → wrap in list
    return [value]


with app.app_context():
    guides = EmergencyGuide.query.all()

    # SAFE: Disable autoflush using session.no_autoflush context manager (always available)
    with db.session.no_autoflush:
        for g in guides:
            g.steps = json.dumps(force_list(g.steps), ensure_ascii=False)
            g.symptoms = json.dumps(force_list(g.symptoms), ensure_ascii=False)
            g.warnings = json.dumps(force_list(g.warnings), ensure_ascii=False)
            g.tips = json.dumps(force_list(g.tips), ensure_ascii=False)
            db.session.add(g)

        db.session.commit()

    print("✔ All guide fields normalized to clean JSON arrays.")
