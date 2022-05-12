from flask import Flask, jsonify, render_template, send_from_directory
from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from apispec_webframeworks.flask import FlaskPlugin
from marshmallow import Schema, fields

app = Flask(__name__, template_folder="swagger/templates")

@app.route('/')
def index():
    return """ <h1> Welcome to E-Library </h1> """

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
        return render_template('index.html',base_url = '/docs')
    else:
        return send_from_directory("./swagger/static", path)  

# class SignupUserSchema(Schema):
#     userId = fields.Int()
#     name = fields.Str()
#     email = fields.Email()
#     password = fields.Str()

# class SignInSchema(Schema):
#     email = fields.Email()
#     password = fields.Str()

# class UpdateUserSchema(Schema):
#     name = fields.Str()
#     email = fields.Email()
#     password = fields.Str()

# class AllUsersSchema():
#     users = fields.List(fields.Nested(SignupUserSchema))

# class AddBooksSchema():
#     bookId = fields.Int()
#     title = fields.Str()
#     author = fields.Str()

# class ListingBooksSchema():
#     books = fields.List(fields.Nested(AddBooksSchema))

if __name__ == '__main__' :
    app.run(debug=True, host="127.0.0.1", port=5000)
