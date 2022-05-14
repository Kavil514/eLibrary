from flask import Flask, jsonify, render_template, send_from_directory, request
from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from apispec_webframeworks.flask import FlaskPlugin
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from marshmallow import Schema, fields

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

# Routes


class SignupRequestSchema(Schema):
    name = fields.Str()
    email = fields.Email()
    password = fields.Str()


class SignupResponseSchema(Schema):
    message = fields.Str()


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
        # .find({"email": data['email']})

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


with app.test_request_context():
    spec.path(view=signup)


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
