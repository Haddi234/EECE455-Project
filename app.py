import os
import re
import json
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_babel import Babel, gettext as _
from gf2_m import GF2_m  # Your GF(2^m) arithmetic class

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "supersecretkey")



if os.environ.get("USE_POSTGRES") == "true":
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
        "DATABASE_URL", "postgresql://postgres:postgres@localhost/gf2m_db"
    )
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///gf2m_db.sqlite3"

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure PostgreSQL database locally.
# If DATABASE_URL is not set, the default connection string will be used.
# Make sure to update "postgres", "postgres", and "gf2m_db" to match your local PostgreSQL credentials.

# Language configuration
LANGUAGES = ['en', 'es', 'fr', 'ar']
app.config['BABEL_DEFAULT_LOCALE'] = 'en'
app.config['BABEL_SUPPORTED_LOCALES'] = LANGUAGES

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
babel = Babel(app, locale_selector=lambda: session.get('lang', request.accept_languages.best_match(LANGUAGES)))

# Inject locale into templates
@app.context_processor
def inject_locale():
    return dict(get_locale=lambda: session.get('lang', request.accept_languages.best_match(LANGUAGES)))

# Inject current user into templates
@app.context_processor
def inject_user():
    return dict(current_user=session.get('user', 'guest'))

# -----------------
# Database Models
# -----------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)  # Hashed password
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    history = db.relationship('History', backref='user', lazy=True)

class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    operation = db.Column(db.String(20), nullable=False)
    field_degree = db.Column(db.Integer, nullable=False)
    poly_degree = db.Column(db.Integer, nullable=False)
    coefficient_format = db.Column(db.String(20), nullable=False)
    output_format = db.Column(db.String(20), nullable=False)
    coefficients_A = db.Column(db.String(255), nullable=False)
    coefficients_B = db.Column(db.String(255))  # Optional for unary operations
    result = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# -----------------
# Routes
# -----------------

# Language switching route
@app.route('/set_language/<lang_code>')
def set_language(lang_code):
    if lang_code not in LANGUAGES:
        lang_code = 'en'
    session['lang'] = lang_code
    return redirect(request.referrer or url_for('index'))

# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash(_("Passwords do not match."))
            return render_template('signup.html')

        if User.query.filter_by(username=username).first():
            flash(_("Username already exists. Please choose another."))
            return render_template('signup.html')

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash(_("Signup successful! Please log in."))
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user'] = user.username
            session['user_id'] = user.id
            return redirect(url_for('index'))
        else:
            flash(_("Invalid username or password."))
            return redirect(url_for('login'))
    return render_template('login.html')

# Guest login route
@app.route('/guest')
def guest_login():
    session['user'] = 'guest'
    session.pop('user_id', None)
    return redirect(url_for('index'))

# Logout route
@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('user_id', None)
    return redirect(url_for('login'))

# Main index route
@app.route('/')
def index():
    user_status = session.get('user', 'guest')
    return render_template('index.html', user=user_status)

# Route to perform GF(2^m) arithmetic operations
@app.route('/perform_operation', methods=['POST'])
def perform_operation():
    if 'user' not in session:
        return jsonify(error=_("Unauthorized: Please log in first")), 403

    try:
        data = request.get_json()
        print("Received request:", data)

        field_degree = int(data['fieldDegree'])
        poly_degree = int(data['degree'])
        coefficient_format = data['coefficientFormat']
        output_format = data['outputFormat']
        operation = int(data['operation'])

        coefficientsA = data['coefficientsA']
        coefficientsB = data['coefficientsB'] if operation != 5 else []

        print("Parsed Data:", field_degree, poly_degree, coefficient_format, output_format, operation)
        print("Coefficients A:", coefficientsA)
        print("Coefficients B:", coefficientsB)

        def convert_coefficients(coeffs, format_type):
            processed = []
            for coeff in coeffs:
                coeff = str(coeff).strip() if coeff is not None else "0"
                if format_type == "bin":
                    if not re.fullmatch(r"[01]", coeff):
                        raise ValueError(_("Binary coefficients must be a single digit: 0 or 1."))
                    processed.append(int(coeff, 2))
                elif format_type == "hex":
                    if not re.fullmatch(r"[0-9A-Fa-f]+", coeff):
                        raise ValueError(_("Hexadecimal coefficients must only contain characters 0-9 and A-F."))
                    processed.append(int(coeff, 16) % 2)
                elif format_type == "dec":
                    if not re.fullmatch(r"\d+", coeff):
                        raise ValueError(_("Decimal coefficients must only contain digits 0-9."))
                    processed.append(int(coeff, 10) % 2)
                else:
                    raise ValueError(_("Invalid coefficient format specified."))
            return processed

        if coefficient_format in ["direct_bin", "direct_hex"]:
            processed_A = coefficientsA
            processed_B = coefficientsB if operation != 5 else None
        else:
            processed_A = convert_coefficients(coefficientsA, coefficient_format)
            processed_B = convert_coefficients(coefficientsB, coefficient_format) if operation != 5 else None

        # Reverse the coefficient lists to account for UI order
        processed_A = list(reversed(processed_A))
        if processed_B is not None:
            processed_B = list(reversed(processed_B))

        gf = GF2_m(field_degree)
        poly_A = sum(c << i for i, c in enumerate(processed_A))
        poly_B = sum(c << i for i, c in enumerate(processed_B)) if processed_B else None

        result_poly = None
        if operation == 1:  # Addition
            result_poly = gf.add(poly_A, poly_B)
        elif operation == 2:  # Subtraction
            result_poly = gf.sub(poly_A, poly_B)
        elif operation == 3:  # Multiplication
            result_poly = gf.mul(poly_A, poly_B)
        elif operation == 4:  # Division
            if poly_B == 0:
                return jsonify(error=_("Division by zero is not allowed")), 400
            result_poly = gf.div(poly_A, poly_B)
        elif operation == 5:  # Inversion
            if poly_A == 0:
                return jsonify(error=_("Zero has no multiplicative inverse")), 400
            result_poly = gf.inverse(poly_A)
        else:
            return jsonify(error=_("Invalid operation")), 400

        # Convert result polynomial to coefficients list
        result_coeffs = [(result_poly >> i) & 1 for i in range(gf.m - 1, -1, -1)]

        def to_superscript(num):
            sup_map = {'0': '⁰', '1': '¹', '2': '²', '3': '³', '4': '⁴', '5': '⁵', '6': '⁶', '7': '⁷', '8': '⁸', '9': '⁹'}
            return "".join(sup_map[d] for d in str(num))

        if output_format == "bin":
            result_str = "".join(map(str, result_coeffs))
        elif output_format == "hex":
            result_str = hex(int("".join(map(str, result_coeffs)), 2))[2:].upper()
        else:
            let_terms = []
            for i, c in enumerate(result_coeffs):
                if c:
                    exponent = gf.m - 1 - i
                    if exponent == 0:
                        let_terms.append("1")
                    elif exponent == 1:
                        let_terms.append("x")
                    else:
                        let_terms.append(f"x{to_superscript(exponent)}")
            result_str = " + ".join(let_terms) if let_terms else "0"

        # Record the operation history for registered (non-guest) users
        if session.get('user') != 'guest' and session.get('user_id'):
            history_entry = History(
                user_id=session.get('user_id'),
                operation=str(data.get('operation')),
                field_degree=field_degree,
                poly_degree=int(data['degree']),
                coefficient_format=coefficient_format,
                output_format=output_format,
                coefficients_A=json.dumps(data['coefficientsA']),
                coefficients_B=json.dumps(data['coefficientsB']) if data.get('coefficientsB') else None,
                result=result_str
            )
            db.session.add(history_entry)
            db.session.commit()

        return jsonify(result=result_str)

    except Exception as e:
        print("Error in perform_operation:", str(e))
        return jsonify(error=f"{_('An unexpected error occurred')}: {str(e)}"), 500

# Route to display the user's operation history
@app.route('/history')
def history():
    if 'user' not in session or session.get('user') == 'guest':
        flash(_("Guests cannot access history. Please log in or sign up."))
        return redirect(url_for('login'))
    
    user_id = session.get('user_id')
    user_history = History.query.filter_by(user_id=user_id).order_by(History.timestamp.desc()).all()
    return render_template('history.html', history=user_history)

if __name__ == '__main__':
    app.run(debug=True)
