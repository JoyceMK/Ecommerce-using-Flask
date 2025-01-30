import os
import razorpay
from flask import Blueprint, request, render_template, redirect, url_for, flash, session,jsonify
from werkzeug.security import check_password_hash,generate_password_hash
from werkzeug.utils import secure_filename
from flask_login import login_required, current_user,logout_user
from .models import User,Product,Order,Cart
from pytz import timezone
from flask_login import LoginManager,  login_user, login_required, logout_user, current_user
from . import db
from sqlalchemy import desc

main = Blueprint('main', __name__)


client = razorpay.Client(auth=("rzp_test_FuqIwgrQeAAtNt", "givvUW1Irf4fQqXnFd3UITXr"))

@main.route('/')
def home():
    products = Product.query.all() 
    return render_template('ecommerce.html', products=products)

login_manager = LoginManager(main)
login_manager.init_app(main)
login_manager.login_view = 'login'


@main.route('/blog')
def blog():
    return render_template('blog.html')



@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        password_hash = generate_password_hash(password)
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists!', 'danger')
            return redirect(url_for('main.register'))
        
        new_user = User(name=name, email=email, password=password_hash)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('main.login'))

    return render_template('register.html')





@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:  
        flash('You are already logged in.', 'info')
        return redirect(url_for('main.user_dashboard')) if not current_user.is_admin else redirect(url_for('main.admin_dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):  
            login_user(user) 
            
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin

            flash('Login successful!', 'success')

            return redirect(url_for('main.admin_dashboard' if user.is_admin else 'main.user_dashboard'))
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('login.html')





@main.route('/admin/dashboard', methods=['GET'])
@login_required

def admin_dashboard():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('main.home'))
    products = Product.query.all()  

    return render_template('admin_home.html', products=products)





UPLOAD_FOLDER = 'static/images/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}



def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@main.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('main.home'))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = request.form['price']

        image = request.files['image']
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image_path = os.path.join(UPLOAD_FOLDER, filename)
            image.save(os.path.join('app', image_path))  

        else:
            flash('Invalid image format. Only PNG, JPG, JPEG, GIF are allowed.', 'danger')
            return redirect(request.url)

        new_product = Product(
            name=name,
            description=description,
            price=price,
            image_url=image_path 
        )

        db.session.add(new_product)
        db.session.commit()

        flash(f'Product "{name}" added successfully!', 'success')
        return redirect(url_for('main.admin_dashboard')) 

    return render_template('add_product.html')



@main.route('/view_orders')
@login_required

def view_orders():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('main.home'))

    orders = db.session.query(Order, Product, User).join(Product, Order.product_id == Product.id).join(User, Order.user_id == User.id).order_by(Order.id).all()
    return render_template('admin_ordtl.html', orders=orders)





@main.route('/view_users')
@login_required

def view_users():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('main.home'))
    users = User.query.all()  
    return render_template('admin_users.html', users=users)


@main.route('/update_order_status', methods=['POST'])
@login_required

def update_order_status():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('main.home'))

    order_id = request.form.get('order_id')
    new_status = request.form.get('status')
    
    order = Order.query.get(order_id)
    order.status = new_status
    db.session.commit()

    return redirect(url_for('main.view_orders'))



@main.route('/admin/delete_product/<int:product_id>', methods=['POST'])
@login_required

def delete_product(product_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('main.home'))
    

    product = Product.query.get(product_id)
    if product:
        db.session.delete(product)
        db.session.commit()
    return redirect(url_for('main.admin_dashboard'))



#USERS!!!!!

@main.route('/user_dashboard')
@login_required
def user_dashboard():
    products = Product.query.all() 
    return render_template('user_home.html', products=products, user=current_user)



@main.route('/buy_now/<int:product_id>', methods=['POST'])
def buy_now(product_id):
    product = Product.query.get_or_404(product_id)
    new_link = f"http://127.0.0.1:5000/{product.image_url}"
    
    return render_template('buy_now.html', product=product, new_link=new_link)




@main.route('/confirm_order/<int:product_id>', methods=['POST'])
def confirm_order(product_id):
    product = Product.query.get_or_404(product_id)
    
    quantity = request.form.get('quantity', 1, type=int)

    order = Order(
        user_id=current_user.id,
        product_id=product.id,
        status="Order Placed",
        quantity=quantity
    )
    db.session.add(order)
    db.session.commit()

    flash('Product purchase successfully initiated!', 'success')
    return redirect(url_for('main.user_dashboard'))





@main.route('/order_details')
@login_required
def order_details():
    orders = db.session.query(Order, Product).join(Product, Order.product_id == Product.id) \
        .filter(Order.user_id == current_user.id) \
        .order_by(desc(Order.created_at))  

    local_tz = timezone('Asia/Kolkata')  
    orders_list = orders.all()

    for order, product in orders_list:
        order.created_at = order.created_at.astimezone(local_tz)
    
    return render_template('order_details.html', orders=orders_list)



from flask import request, redirect, url_for, flash

@main.route('/cancel_order/<int:order_id>', methods=['POST'])
def cancel_order(order_id):
    order = Order.query.get(order_id)
    
    if order:
        try:
            db.session.delete(order)
            db.session.commit()
            flash('Your order has been successfully canceled.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'danger')
    else:
        flash('Order not found!', 'danger')
    
    return redirect(url_for('main.order_details'))




@main.route('/add_to_cart/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)

    cart_item = Cart.query.filter_by(user_id=current_user.id, product_id=product.id).first()
    if cart_item:
        cart_item.quantity += 1  
    else:
        cart_item = Cart(user_id=current_user.id, product_id=product.id, quantity=1)
        db.session.add(cart_item)

    db.session.commit()
    flash(f'Added {product.name} to cart!', 'success')
    return redirect(url_for('main.user_dashboard'))


@main.route('/cart')
@login_required
def cart():
    # Fetch cart items and calculate total price
    cart_items = db.session.query(Cart, Product).join(Product, Cart.product_id == Product.id).filter(Cart.user_id == current_user.id).all()
    total_price = sum(cart.quantity * product.price for cart, product in cart_items)

    # Razorpay order creation for testing
    order_data = {
        "amount": int(total_price * 100),  # Convert total price to paise
        "currency": "INR",
        "payment_capture": 1  # Auto-capture payment
    }
    order = client.order.create(order_data)
    order_id = order['id']  # Get generated order ID

    return render_template('add_to_cart.html',
                           cart_items=cart_items,
                           total_price=total_price,
                           order_id=order_id,
                           user_name=current_user.name,
                           user_email=current_user.email)




@main.route('/remove_from_cart/<int:cart_id>', methods=['POST'])
@login_required
def remove_from_cart(cart_id):
    cart_item = Cart.query.get_or_404(cart_id)
    
    if cart_item.user_id != current_user.id:
        flash("Unauthorized action!", "danger")
        return redirect(url_for('main.cart'))

    db.session.delete(cart_item)
    db.session.commit()
    
    flash("Item removed from cart successfully!", "success")
    return redirect(url_for('main.cart'))



@main.route('/verify_payment', methods=['POST'])
def verify_payment():
    payment_id = request.form['razorpay_payment_id']
    order_id = request.form['razorpay_order_id']
    signature = request.form['razorpay_signature']

    # Create a dictionary for verification
    data = {
        'razorpay_order_id': order_id,
        'razorpay_payment_id': payment_id,
        'razorpay_signature': signature
    }

    # Verify the signature
    try:
        client.utility.verify_payment_signature(data)
        return "Payment Verified"
    except razorpay.errors.SignatureVerificationError:
        return "Payment Failed"



@main.route('/create_order', methods=['POST'])
def create_order():
    # Get the total amount to be paid
    amount = request.form['amount']  # You can calculate the total amount here

    # Razorpay API to create an order
    order_data = {
        "amount": amount * 100,  # Razorpay requires the amount in paise (1 INR = 100 paise)
        "currency": "INR",
        "payment_capture": 1
    }

    order = client.order.create(data=order_data)
    return jsonify(order)




@main.route('/logout')
def logout():
    logout_user()  # This logs out the user from Flask-Login session
    flash('Logged out successfully!', 'info')
    return redirect(url_for('main.login'))



