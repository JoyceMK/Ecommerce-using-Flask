from datetime import datetime
import pytz
from . import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model,UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password= db.Column(db.String(200),nullable=False)
    is_admin=db.Column(db.Boolean,default=False)
    is_active=db.Column(db.Boolean,default=True)

    

    def __repr__(self):
        return f'User{self.name}'
    
    def set_password(self,password):
        self.password=generate_password_hash(password)

    def check_password(self,password):
        return check_password_hash(self.password,password)
    

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(300), nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_url = db.Column(db.String(500), nullable=True)

    def __repr__(self):
        return f"<Product {self.name}>"
    
class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    status=db.Column(db.String(50),nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(pytz.timezone('Asia/Kolkata')))   


    def __repr__(self):
        return f"<Order {self.status}>"



class Cart(db.Model):
    __tablename__ = 'cart'  

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)

    # Relationships
    user = db.relationship('User', backref=db.backref('cart', lazy=True, cascade="all, delete-orphan"))
    product = db.relationship('Product', backref=db.backref('cart', lazy=True, cascade="all, delete-orphan"))

    def __repr__(self):
        return f"<Cart User: {self.user_id}, Product: {self.product_id}, Quantity: {self.quantity}>"


