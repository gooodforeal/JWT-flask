from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask import request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)


with app.app_context():
    db.create_all()


app.config['JWT_SECRET_KEY'] = '29567d2b5ba20a2c9e8dfab9c2a5cfe84d31f983ea3d90b6165d7bce85c9f667e8997cee6e879399163fbca62faa559a77a69e0cc4da21c903cd82440970f6132e3ee16e56ce818175749688a47e2f26b0e5c453ff8dee04d3814fbbbacdc69fae41aeea46c5493810b386d1bfc567ae511b03f70029c4ff54472a0c7357a4f6ea1c3ee3e1ee637cddd77e0c2565d73cd6a715e17b5d0de20b581f9c705ae368794c671feb21cec7150d471ad74983babb9d448e61fe6feb7300ba699eaf0e40307a61160e7edefaaaed53f3f93633df55661c2819c1c4eeec26114e918e039879ea23501290ed5b20197bf8e33d6fd3348c78c0bbcd66d97b8065f9cc1897cd'
jwt = JWTManager(app)


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    new_user = User(username=data['username'], password=data['password'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully!"}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username'],
                                password=data['password']).first()

    if user:
        access_token = create_access_token(identity=user.username)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"msg": "Bad username or password"}), 401


@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    return jsonify({"msg": "This is a protected route."}), 200


if __name__ == '__main__':
    app.run(debug=True)
