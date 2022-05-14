from crypt import methods
from functools import wraps
from urllib import response
from flask import Flask, jsonify, render_template, send_from_directory, request
from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from apispec_webframeworks.flask import FlaskPlugin
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from marshmallow import Schema, fields
import jwt

app = Flask(__name__, template_folder="swagger/templates")

app.secret_key = "secretkey"

# MongoDB
try:
    app.config['MONGO_URI'] = "mongodb://localhost:27017/eLibrary"
    mongo = PyMongo(app)
except:
    print("Error: Cannot connect to MongoDb")

# Swagger

spec = APISpec(
    title="eLibrary",
    version='1.0.0',
    openapi_version='3.0.2',
    plugins=[FlaskPlugin(), MarshmallowPlugin()],
)


@app.route('/api/swagger.json')
def create_swagger_spec():
    return jsonify(spec.to_dict())


@app.route('/docs')
@app.route('/docs/<path:path>')
def swagger_docs(path=None):
    if not path or path == 'index.html':
        return render_template('index.html', base_url='/docs')
    else:
        return send_from_directory("./swagger/static", path)

# WelcomePage


@app.route('/')
def index():
    return """ <h1> Welcome to E-Library </h1> """

# Authentication


def tokenReq(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "Authorization" in request.headers:
            token = request.headers["Authorization"]
            try:
                jwt.decode(token, app.secret_key)
            except:
                return jsonify({"status": "fail", "message": "unauthorized"}), 401
            return f(*args, **kwargs)
        else:
            return jsonify({"status": "fail", "message": "unauthorized"}), 401
    return decorated

# Schema


class SignupRequestSchema(Schema):
    name = fields.Str()
    email = fields.Email()
    password = fields.Str()


class SignupResponseSchema(Schema):
    message = fields.Str()


class SigninRequestSchema(Schema):
    email = fields.Email()
    password = fields.Str()


class SigninResponseSchema(Schema):
    message = fields.Str()

# Routes

@app.route('/signup', methods=['POST'])
def signup():
    """Signup user
        ---
        post:
            description: Signup a user
            requestBody:
                required: true
                content:
                    application/json:
                        schema: SignupRequestSchema
            responses: 
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
        check = mongo.db.users.find_one({"email": data['email']})

        if check:
            resp = jsonify("user with that email exists")
            resp.status_code = 401
            return resp

        elif _name and _email and _password and request.method == 'POST':
            _hased_password = generate_password_hash(_password)
            id = mongo.db.users.insert_one(
                {'name': _name, 'email': _email, 'password': _hased_password})
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


@app.route('/sigin', methods=['POST'])
def sigin():
    """Signin user
        ---
        post:
            description: Signin a user
            requestBody:
                required: true
                content:
                    application/json:
                        schema: SigninRequestSchema
            responses: 
                200:
                    description: Return success message
                    content:     
                        application/json:
                            schema: SigninResponseSchema
                401:
                    description: Invalid Credentials
                    content:
                        application/json:
                            schema: SigninResponseSchema
                500:
                    description: Server Error
                    content:
                        application/json:
                            schema: SigninResponseSchema             

    """
    try:
        data = request.get_json()
        user = mongo.db.users.find_one({"email": data["email"]})

        if user:
            user['_id'] = str(user['_id'])
            if user and check_password_hash(user['password'], data['password']):
                token = jwt.encode({
                    "user": {
                        "email": f"{user['email']}",
                        "id": f"{user['_id']}",
                    }
                }, app.secret_key)

                del user['password']

                resp = jsonify("User authenticated")
                resp.status_code = 200
                resp.status = "success"
                resp_data = {"token": token}

            else:
                resp = jsonify("wrong password")
                resp.status_code = 401
                resp.status = "fail"
                resp_data = None
        else:
            resp = jsonify("invalid login details")
            resp.status_code = 401
            resp.status = "fail"
            resp_data = None

    except Exception as ex:
        resp = jsonify(ex)
        resp.status_code = 500
        resp.status = "fail"
        resp_data = None
    return resp, resp_data


with app.test_request_context():
    spec.path(view=signup)
    spec.path(view=sigin)


@app.errorhandler(404)
def not_found(err=None):
    message = {
        'status': 404,
        'message': 'Not Found' + request.url
    }
    resp = jsonify(message)
    resp.status_code = 404
    return resp


if __name__ == '__main__':
    app.run(debug=True, host="127.0.0.1", port=5000)
