"""
Original Code:

@app.route('/account/<user_id>')
def get_account(user_id):
    user = db.query(User).filter_by(id=user_id).first()
    return jsonify(user.to_dict())

Vulnerability:

Broken Access Control
No authentication/authorization and no null check.
Returns all user data including possible secrets.

Fix:

Enforcing authentication, authorization, validates
input type, and returns only explicit safe fields.
"""
from flask import abort, jsonify, request
from flask_login import current_user, login_required

@app.route('/account/<int:user_id>')
@login_required
def get_account(user_id):
    # Only allow the owner or admins
    if current_user.id != user_id and not current_user.has_role('admin'):
        abort(403)

    user = db.session.query(User).filter_by(id=user_id).first()
    if not user:
        abort(404)

    # Explicity return safe fields
    return jsonify({
        "id": user.id,
        "display_name": user.display_name,
        "email": user.email if current_user.id == user_id else None
    })
