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
    products = Product.query.all() 
    return render_template('ecommerce.html', products=products)

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






@main.route('/logout')
def logout():
    logout_user()  # This logs out the user from Flask-Login session
    flash('Logged out successfully!', 'info')
    return redirect(url_for('main.login'))



