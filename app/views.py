import os
from flask import Blueprint, request, render_template, redirect, url_for, flash, session
from werkzeug.security import check_password_hash,generate_password_hash
from werkzeug.utils import secure_filename
from flask_login import login_required, current_user,logout_user
from .models import User,Product,Order
from pytz import timezone
from flask_login import LoginManager,  login_user, login_required, logout_user, current_user
from . import db
from sqlalchemy import desc

main = Blueprint('main', __name__)

@main.route('/')
def home():
    return render_template('login.html')

login_manager = LoginManager(main)
login_manager.init_app(main)
login_manager.login_view = 'login'



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
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('main.login'))

    return render_template('register.html')




@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:  # Prevent logged-in users from accessing login
        flash('You are already logged in.', 'info')
        return redirect(url_for('main.user_dashboard')) if not current_user.is_admin else redirect(url_for('main.admin_dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):  # Validate credentials
            login_user(user)  # Login user with Flask-Login
            
            # Set custom session attributes
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin

            flash('Login successful!', 'success')

            # Redirect based on user role
            return redirect(url_for('main.admin_dashboard' if user.is_admin else 'main.user_dashboard'))
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('login.html')





@main.route('/admin/dashboard', methods=['GET'])
def admin_dashboard():
    products = Product.query.all()  

    return render_template('admin_home.html', products=products)





UPLOAD_FOLDER = 'static/images/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}



def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@main.route('/add_product', methods=['GET', 'POST'])
def add_product():
    # Check if user is logged in and is an admin
    if 'user_id' not in session or not session.get('is_admin'):
        flash('You need to be an admin to add products.', 'danger')
        return redirect(url_for('main.home'))

    if request.method == 'POST':
        # Retrieve form data
        name = request.form['name']
        description = request.form['description']
        price = request.form['price']

        # Handle image upload
        image = request.files['image']
        if image and allowed_file(image.filename):
            # Secure the filename and save it to the static folder
            filename = secure_filename(image.filename)
            image_path = os.path.join(UPLOAD_FOLDER, filename)
            image.save(os.path.join('app', image_path))  # Update with actual app directory path

        else:
            flash('Invalid image format. Only PNG, JPG, JPEG, GIF are allowed.', 'danger')
            return redirect(request.url)

        # Create a new Product object
        new_product = Product(
            name=name,
            description=description,
            price=price,
            image_url=image_path  # Store image path in the database
        )

        # Add product to the database
        db.session.add(new_product)
        db.session.commit()

        flash(f'Product "{name}" added successfully!', 'success')
        return redirect(url_for('main.admin_dashboard')) 

    return render_template('add_product.html')



@main.route('/view_orders')
def view_orders():
    # Fetch all orders, joining with the Product and User tables, sorted by order_id
    orders = db.session.query(Order, Product, User).join(Product, Order.product_id == Product.id).join(User, Order.user_id == User.id).order_by(Order.id).all()
    return render_template('admin_ordtl.html', orders=orders)





@main.route('/view_users')
def view_users():
    # Fetch all users
    users = User.query.all()  # Assuming you have a 'User' model
    return render_template('admin_users.html', users=users)

@main.route('/update_order_status', methods=['POST'])
def update_order_status():
    order_id = request.form.get('order_id')
    new_status = request.form.get('status')
    
    order = Order.query.get(order_id)
    order.status = new_status
    db.session.commit()

    return redirect(url_for('main.view_orders'))



@main.route('/admin/delete_product/<int:product_id>', methods=['POST'])
def delete_product(product_id):
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
    # Fetch orders for the logged-in user, joining with the Product table to get product details
    orders = db.session.query(Order, Product).join(Product, Order.product_id == Product.id) \
        .filter(Order.user_id == current_user.id) \
        .order_by(desc(Order.created_at))  # Sort orders by created_at in descending order

    # Convert created_at to local timezone (Asia/Kolkata in this example)
    local_tz = timezone('Asia/Kolkata')  # Replace with your local timezone if needed
    orders_list = orders.all()

    for order, product in orders_list:
        # Convert created_at from UTC to local timezone
        order.created_at = order.created_at.astimezone(local_tz)
    
    return render_template('order_details.html', orders=orders_list)



from flask import request, redirect, url_for, flash

@main.route('/cancel_order/<int:order_id>', methods=['POST'])
def cancel_order(order_id):
    order = Order.query.get(order_id)
    
    if order:
        try:
            # Delete the order
            db.session.delete(order)
            db.session.commit()
            flash('Your order has been successfully canceled.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'danger')
    else:
        flash('Order not found!', 'danger')
    
    # Redirect back to the orders page with the modal showing
    return redirect(url_for('main.order_details'))






@main.route('/logout')
def logout():
    logout_user()  # This logs out the user from Flask-Login session
    flash('Logged out successfully!', 'info')
    return redirect(url_for('main.login'))



