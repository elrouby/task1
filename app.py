from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/task1'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# ba3mel db user
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def hash_password(self):
        self.password = bcrypt.generate_password_hash(self.password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

#  ba3mel db product
class Product(db.Model):
    pid = db.Column(db.Integer, primary_key=True)
    pname = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())

# Route to register a new user
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Invalid input'}), 400

    user = User(name=data['name'], username=data['username'], password=data['password'])
    user.hash_password()
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201

# Route to log in and get JWT token
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    
    if user and user.check_password(data['password']):
        access_token = create_access_token(identity=user.id, expires_delta=False)
        return jsonify({'token': access_token}), 200
    
    return jsonify({'error': 'Invalid credentials'}), 401

# Route to update user details
@app.route('/users/<int:id>', methods=['PUT'])
@jwt_required()
def update_user(id):
    user = User.query.get(id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()
    if 'name' in data:
        user.name = data['name']
    db.session.commit()
    return jsonify({'message': 'User updated successfully'})

# Route to create a new product
@app.route('/products', methods=['POST'])
@jwt_required()
def create_product():
    data = request.get_json()
    product = Product(**data)
    db.session.add(product)
    db.session.commit()
    return jsonify({'message': 'Product created successfully'}), 201

# Route to get all products
@app.route('/products', methods=['GET'])
def get_products():
    products = Product.query.all()
    return jsonify([{'pid': p.pid, 'pname': p.pname, 'price': p.price, 'stock': p.stock} for p in products])

# Route to get a specific product by ID
@app.route('/products/<int:pid>', methods=['GET'])
def get_product(pid):
    product = Product.query.get(pid)
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    return jsonify({'pid': product.pid, 'pname': product.pname, 'price': product.price, 'stock': product.stock})

# Route to update a product
@app.route('/products/<int:pid>', methods=['PUT'])
@jwt_required()
def update_product(pid):
    product = Product.query.get(pid)
    if not product:
        return jsonify({'error': 'Product not found'}), 404

    data = request.get_json()
    for key, value in data.items():
        setattr(product, key, value)
    db.session.commit()
    return jsonify({'message': 'Product updated successfully'})

# Route to delete a product
@app.route('/products/<int:pid>', methods=['DELETE'])
@jwt_required()
def delete_product(pid):
    product = Product.query.get(pid)
    if not product:
        return jsonify({'error': 'Product not found'}), 404

    db.session.delete(product)
    db.session.commit()
    return jsonify({'message': 'Product deleted successfully'})

# Run the application
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
