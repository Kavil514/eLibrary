import json
from flask import jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
from app import app, mongo, spec
from marshmallow import Schema, fields
import uuid
import jwt
from functools import wraps

class SignupRequestSchema(Schema):
    name = fields.Str()
    email = fields.Email()
    password = fields.Str()

class SignupResponseSchema(Schema):
    message: fields.Str()

@app.route('/signup', method=['POST'])
def signup():
    """Signup user
        ---
        post:
            description: Signup a user
            request-body:
                required: true
                content:
                    application/json:
                        schema: SignupRequestSchema
            response: 
                200:
                    description: Return success message
                    content:
                        application/json:
                            schema: SignupResponseSchema
                401:
                    description: Duplicate email
                    content:
                        application/json:
                            schema: SignupResponseSchema
                500:
                    description: Server Error
                    content:
                        application/json:
                            schema: SignupResponseSchema                        
    """
    _json = request.json
    _name = _json['name']
    _email = _json['email']
    _password = _json['password']

    try:
        data = request.get_json()
        check = mongo.db.users.find({"email": data['email']})
        if check.count() >= 1:
            resp = jsonify("user with that email exists")
            resp.status_code = 401
            return resp

        elif _name and _email and _password and request.method == 'POST':
            _hased_password  = generate_password_hash(_password)
            id = mongo.db.users.insert_one({'name':_name, 'email':_email, 'password':_hased_password})
            resp = jsonify("User added successfully")
            resp.status_code = 200
            return resp
        else:
            return not_found()

    except Exception as ex:
        message = {
            'status': 500,
            'message': 'Server Error' + request.url
        }
        return jsonify(message), 200

with app.test_request_context():
    spec.path(view=signup)


@app.errorhandler(404)
def not_found(err = None):
    message = {
        'status': 404,
        'message': 'Not Found' + request.url
    }
    resp = jsonify(message)
    resp.status_code = 404
    return resp