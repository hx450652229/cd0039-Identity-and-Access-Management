from functools import wraps
import os
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS

from .database.models import db_drop_and_create_all, setup_db, Drink, db
from .auth.auth import AuthError, requires_auth
from werkzeug.exceptions import HTTPException

app = Flask(__name__)
setup_db(app)
CORS(app)

with app.app_context():
    db_drop_and_create_all()


def handle_exceptions(f):
    """Try-except decorator

    Args:
        f (function): Endpoint function

    Returns:
        function: Decorated function
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except HTTPException as e:
            # forward known http exception
            raise e
        except AuthError as e:
            # auth error
            abort(e.status_code)
        except Exception as e:
            # abort with 500 for unknown exception
            print(e)
            abort(500)
        finally:
            db.session.rollback()
            db.session.close()

    return decorated_function


@app.route('/drinks')
@handle_exceptions
def get_drinks():
    """Endpoint to get all drinks"""
    drinks = Drink.query.all()
    return jsonify({
        "success": True,
        "drinks": [e.short() for e in drinks]
    })


@app.route('/drinks-detail')
@handle_exceptions
@requires_auth('get:drinks-detail')
def get_drinks_detail():
    """Endpoint to get drinks detail. Requires 'get:drinks-detail' permission."""
    drinks = Drink.query.all()
    return jsonify({
        "success": True,
        "drinks": [e.long() for e in drinks]
    })


@app.route('/drinks', methods=['POST'])
@handle_exceptions
@requires_auth('post:drinks')
def create_drink():
    """Endpoint to create drink. Requires post:drinks permission."""
    drink_json = request.get_json()
    if (drink_json['title'] == "" or drink_json['recipe'] == ""):
        abort(422)
    drink = Drink(title=drink_json['title'],
                  recipe=json.dumps(drink_json['recipe']))
    drink.insert()
    return jsonify({
        "success": True,
        "drinks": [drink.long()]
    })


@app.route('/drinks/<drink_id>', methods=['PATCH'])
@handle_exceptions
@requires_auth('patch:drinks')
def modify_drink(drink_id):
    """Endpoint to modify drink. Requires patch:drinks permission."""
    drink = Drink.query.get(drink_id)
    if drink is None:
        abort(404)
    drink_json = request.get_json()
    if (drink_json['title'] == "" or drink_json['recipe'] == ""):
        abort(422)
    drink.title = drink_json['title']
    drink.recipe = json.dumps(drink_json['recipe'])
    drink.update()
    return jsonify({
        "success": True,
        "drinks": [drink.long()]
    })


@app.route('/drinks/<drink_id>', methods=['DELETE'])
@handle_exceptions
@requires_auth('delete:drinks')
def delete_drink(drink_id):
    """Endpoint to delete drink. Requires delete:drinks permission."""
    drink = Drink.query.get(drink_id)
    if drink is None:
        abort(404)
    drink.delete()
    return jsonify({
        "success": True,
        "delete": drink_id
    })


@app.errorhandler(404)
def not_found(err):
    """Error handler for 404 not found"""
    return jsonify({
        'success': False,
        'error': 404,
        'message': 'Resource Not Found'
    }), 404


@app.errorhandler(400)
def bad_request(err):
    """Error handler for 400 bad request"""
    return jsonify({
        'success': False,
        'error': 400,
        'message': 'Bad Request'
    }), 400


@app.errorhandler(422)
def unprocessable(err):
    """Error handler for 422 unprocessable"""
    return jsonify({
        'success': False,
        'error': 422,
        'message': 'Unprocessable'
    }), 422


@app.errorhandler(500)
def internal_server_error(err):
    """Error handler for internal server error"""
    return jsonify({
        'success': False,
        'error': 500,
        'message': 'Internal Server Error'
    }), 500


@app.errorhandler(401)
def unauthorized(err):
    """Error handler for unauthorized error"""
    return jsonify({
        'success': False,
        'error': 401,
        'message': 'Unauthorized'
    }), 401


@app.errorhandler(403)
def forbidden(err):
    """Error handler for forbidden error"""
    return jsonify({
        'success': False,
        'error': 403,
        'message': 'Forbidden'
    }), 403
