from crypt import methods
from functools import wraps
import bson
from bson import ObjectId
from flask import Flask, jsonify, render_template, send_from_directory, request
from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from apispec_webframeworks.flask import FlaskPlugin
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from marshmallow import Schema, ValidationError, fields, missing
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


# JWT AUTH
jwt_scheme = {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
spec.components.security_scheme("Authorization", jwt_scheme)

# Schema


class SignupRequestSchema(Schema):
    name = fields.Str()
    email = fields.Email()
    password = fields.Str()


class MessageSchema(Schema):
    message = fields.Str()


class SigninRequestSchema(Schema):
    email = fields.Email()
    password = fields.Str()


class BookSchema(Schema):
    bookName = fields.Str()
    author = fields.Str()


class DeleteABookSchema(Schema):
    book_id = fields.Str()


class BookAvailabilitySchema(Schema):
    book_id = fields.Str()

# Routes
# USERS


@app.route('/user/signup', methods=['POST'])
def signupUser():
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
                201:
                    description: Return success message
                    content:     
                        application/json:
                            schema: MessageSchema
                401:
                    description: Duplicate email
                    content:
                        application/json:
                            schema: MessageSchema
                500:
                    description: Server Error
                    content:
                        application/json:
                            schema: MessageSchema             

    """
    message = ""
    code = 500
    status = "fail"
    _json = request.json
    _name = _json['name']
    _email = _json['email']
    _password = _json['password']

    try:
        data = request.get_json()
        check = mongo.db.users.find_one({"email": data['email']})

        if check:
            message = "user with that email exists"
            code = 401
            status = "fail"

        else:
            _hased_password = generate_password_hash(_password)
            id = mongo.db.users.insert_one(
                {'name': _name, 'email': _email, 'password': _hased_password})
            if id.acknowledged:
                status = "successful"
                message = "user created successfully"
                code = 201

    except Exception as ex:
        message = f"{ex}"
        status = "fail"
        code = 500

    return jsonify({'status': status, "message": message}), code


@app.route('/user/signin', methods=['POST'])
def signinUser():
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
                            schema: MessageSchema
                401:
                    description: Invalid Credentials
                    content:
                        application/json:
                            schema: MessageSchema
                500:
                    description: Server Error
                    content:
                        application/json:
                            schema: MessageSchema             

    """
    message = ""
    res_data = {}
    code = 500
    status = "fail"
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

                message = f"user authenticated"
                code = 200
                status = "successful"
                res_data['token'] = token
                res_data['user'] = user

            else:
                message = "wrong password"
                code = 401
                status = "fail"
        else:
            message = "invalid login details"
            code = 401
            status = "fail"

    except Exception as ex:
        message = f"{ex}"
        code = 500
        status = "fail"
    return jsonify({'status': status, "data": res_data, "message": message}), code


@app.route('/user/update', methods=['PUT'])
def updateUser():
    """Update User Details
        ---
        put:
            description: Update a user
            security:
                - Authorization: []
            requestBody:
                required: true
                content:
                    application/json:
                        schema: SignupRequestSchema
            responses: 
                201:
                    description: Return success message
                    content:     
                        application/json:
                            schema: MessageSchema
                404:
                    description: Failed
                    content:
                        application/json:
                            schema: MessageSchema
                500:
                    description: Server Error
                    content:
                        application/json:
                            schema: MessageSchema             

    """
    _json = request.json
    _name = _json['name']
    _email = _json['email']
    _password = _json['password']
    data = {}
    loggedInUser = {}
    code = 500
    message = ""
    status = "fail"
    if "Authorization" in request.headers:
        token = request.headers["Authorization"][7:]
        try:
            loggedInUser = jwt.decode(
                token, app.secret_key, algorithms=["HS256"])
        except:
            return jsonify({"status": "fail", "message": "unauthorized"}), 401
    else:
        return jsonify({"status": "fail", "message": "unauthorized"}), 401

    try:
        if (request.method == 'PUT'):
            user_id = loggedInUser['user']['id']
            filter = {"_id": ObjectId(user_id)}
            _hased_password = generate_password_hash(_password)
            data = {"name": _name, "email": _email,
                    "password": _hased_password}
            updatedData = {"$set": data}
            check = mongo.db.users.find_one({"email": _email})
            if not check:
                res = mongo.db.users.update_one(filter, updatedData)
                if res:
                    message = "updated successfully"
                    status = "successful"
                    code = 201
                else:
                    message = "update failed"
                    status = "fail"
                    code = 404
            else:
                return jsonify({"status": "fail", "message": "duplicateEmail"}), 401
        else:
            not_found()

    except Exception as ee:
        message = str(ee)
        status = "Error"

    return jsonify({"status": status, "message": message, 'data': data}), code


@app.route('/user/delete', methods=['DELETE'])
def deleteUser():
    """Delete User 
        ---
        delete:
            description: Remove User
            security:
                - Authorization: []
            responses: 
                201:
                    description: Return success message
                    content:     
                        application/json:
                            schema: MessageSchema
                404:
                    description: Failed
                    content:
                        application/json:
                            schema: MessageSchema
                500:
                    description: Server Error
                    content:
                        application/json:
                            schema: MessageSchema             

    """
    loggedInUser = {}
    code = 500
    message = ""
    status = "fail"
    if "Authorization" in request.headers:
        token = request.headers["Authorization"][7:]
        try:
            loggedInUser = jwt.decode(
                token, app.secret_key, algorithms=["HS256"])
        except:
            return jsonify({"status": "fail", "message": "unauthorized"}), 401
    else:
        return jsonify({"status": "fail", "message": "unauthorized"}), 401

    try:
        if (request.method == 'DELETE'):
            user_id = loggedInUser['user']['id']
            res = mongo.db.users.delete_one({"_id": ObjectId(user_id)})
            if res:
                message = "deleted successfully"
                status = "successful"
                code = 201
            else:
                message = "delete failed"
                status = "fail"
                code = 404
        else:
            not_found()

    except Exception as ee:
        message = str(ee)
        status = "Error"

    return jsonify({"status": status, "message": message}), code

# BOOKS


@app.route('/add-book', methods=['POST'])
def addBook():
    """Add a Book
        ---
        post:
            description: Add a Book
            security:
                - Authorization: []
            requestBody:
                required: true
                content:
                    application/json:
                        schema: BookSchema
            responses: 
                201:
                    description: Return success message
                    content:     
                        application/json:
                            schema: MessageSchema
                401:
                    description: Adding a Book Failed
                    content:
                        application/json:
                            schema: MessageSchema
                500:
                    description: Server Error
                    content:
                        application/json:
                            schema: MessageSchema             

    """
    _json = request.json
    _bookName = _json['bookName']
    _author = _json['author']
    code = 500
    message = ""
    status = "fail"
    if "Authorization" in request.headers:
        token = request.headers["Authorization"][7:]
        try:
            loggedInUser = jwt.decode(
                token, app.secret_key, algorithms=["HS256"])
        except:
            return jsonify({"status": "fail", "message": "unauthorized"}), 401
    else:
        return jsonify({"status": "fail", "message": "unauthorized"}), 401

    try:
        if (request.method == 'POST'):
            user_id = loggedInUser['user']['id']
            print(user_id)
            res = mongo.db.books.insert_one(
                {"bookName": _bookName, "author": _author, "user_id": user_id, "availability": "available"})
            if res.acknowledged:
                message = "Book added successfully"
                status = "successful"
                code = 201
            else:
                message = "Adding book failed"
                status = "fail"
                code = 404
        else:
            not_found()

    except Exception as ee:
        message = str(ee)
        status = "Error"

    return jsonify({"status": status, "message": message}), code


@app.route('/delete-book/<book_id>', methods=['DELETE'])
def removeBook(book_id):
    """Remove a Book
        ---
        delete:
            description: Remove a Book
            security:
                - Authorization: []
            requestBody:
                required: true
                content:
                    application/json:
                        schema: DeleteABookSchema
            responses: 
                201:
                    description: Return success message
                    content:     
                        application/json:
                            schema: MessageSchema
                404:
                    description: Adding a Book Failed
                    content:
                        application/json:
                            schema: MessageSchema
                500:
                    description: Server Error
                    content:
                        application/json:
                            schema: MessageSchema             

    """
    data = {}
    code = 500
    message = ""
    status = "fail"
    try:
        if (request.method == 'DELETE'):
            print(ObjectId(book_id))
            # data = mongo.db.books.find_one({"_id": ObjectId(book_id)})
            res = mongo.db.books.delete_one({"_id": ObjectId(book_id)})
            if res:
                message = "Delete successfully"
                status = "successful"
                code = 201
            else:
                message = "Delete failed"
                status = "fail"
                code = 404
        else:
            message = "Delete Method failed"
            status = "fail"
            code = 404

    except Exception as ee:
        message = str(ee)
        status = "Error"

    return jsonify({"status": status, "message": message, 'data': data}), code


@app.route('/temporary-remove-book/<book_id>', methods=['PUT'])
def removeBookTemp(book_id):
    """Remove a Book Temporarily
        ---
        put:
            description: Make book Unavailable
            security:
                - Authorization: []
            requestBody:
                required: true
                content:
                    application/json:
                        schema: BookAvailabilitySchema
            responses: 
                201:
                    description: Return success message
                    content:     
                        application/json:
                            schema: MessageSchema
                404:
                    description: Adding a Book Failed
                    content:
                        application/json:
                            schema: MessageSchema
                500:
                    description: Server Error
                    content:
                        application/json:
                            schema: MessageSchema             
    """
    code = 500
    message = ""
    status = "fail"
    try:
        if (request.method == 'PUT'):
            filter = {"_id": ObjectId(book_id)}
            markUnavialable = {"$set": {"availability": "not available"}}
            res = mongo.db.books.update_one(filter, markUnavialable)
            if res:
                message = "Book is made temporarily unavialble"
                status = "successful"
                code = 201
            else:
                message = "Marking unavailable failed"
                status = "fail"
                code = 404
        else:
            message = "Updation Method failed"
            status = "fail"
            code = 404

    except Exception as ee:
        message = str(ee)
        status = "Error"

    return jsonify({"status": status, "message": message}), code


with app.test_request_context():
    spec.path(view=signupUser)
    spec.path(view=signinUser)
    spec.path(view=updateUser)
    spec.path(view=deleteUser)
    spec.path(view=addBook)
    spec.path(view=removeBook)
    spec.path(view=removeBookTemp)


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
