from flask import Flask, render_template, request, url_for, session, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os
import secrets
import logging
import traceback

app = Flask(__name__)
# Generate a strong secret key for session management.
# In production, this should be loaded from an environment variable.
app.secret_key = os.urandom(24)

# --- CONFIGURATION ---
# Define the database file name. SQLite is used for simplicity.
# For production, consider a more robust database like PostgreSQL or MySQL.
DATABASE = 'user_database.db'

# Configure logging to output informational messages and higher to the console.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_db_connection():
    """Establishes a connection to the SQLite database.
    Sets row_factory to sqlite3.Row to allow accessing columns by name (like a dictionary).
    """
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database by creating the 'users' table if it doesn't already exist.
    This table stores user registration details. Email verification fields are removed.
    """
    with app.app_context():
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    business_name TEXT NOT NULL,
                    owner_name TEXT NOT NULL,
                    phone_number TEXT NOT NULL,
                    business_type TEXT NOT NULL,
                    business_location TEXT NOT NULL,
                    food_specialty TEXT,
                    avg_daily_customers INTEGER,
                    supply_capacity TEXT,
                    delivery_regions TEXT,
                    fssai_license TEXT,
                    receive_updates BOOLEAN NOT NULL,
                    is_verified INTEGER NOT NULL DEFAULT 1  -- Changed default to 1 (True) as no email verification
                    -- verification_token TEXT                 -- Removed this column
                )
            ''')
            conn.commit()
            logging.info("Database initialized successfully.")
        except Exception as e:
            # Log any errors encountered during database initialization
            logging.error(f"Error initializing database: {e}")
            logging.error(traceback.format_exc()) # Print full traceback for debugging
        finally:
            # Ensure the database connection is closed
            if conn:
                conn.close()

# Call init_db() once when the Flask application starts to ensure the database is ready.
init_db()

@app.route('/')
def index():
    """Renders the main homepage (index.html).
    Checks for an active user session and passes relevant user data to the template.
    """
    user_data = None
    if 'email' in session:
        conn = None
        try:
            conn = get_db_connection()
            # Fetch user details from the database based on the email stored in the session.
            # Included business_type in the selection
            user = conn.execute("SELECT business_name, owner_name, email, business_type FROM users WHERE email = ?", (session['email'],)).fetchone()
            if user:
                user_data = dict(user) # Convert Row object to a dictionary
        except Exception as e:
            # Log any errors during user data retrieval from session
            app.logger.error(f"Error fetching user data for session: {e}")
            app.logger.error(traceback.format_exc())
        finally:
            if conn:
                conn.close()
    # Render the index.html template, passing user_data if available.
    return render_template('index.html', user=user_data)

@app.route('/api/signup', methods=['POST'])
def api_signup():
    """Handles user registration requests.
    Collects form data, performs validation, hashes the password,
    stores the user in the database. Email verification is removed.
    """
    # Extract form data from the request.form object.
    business_name = request.form.get('businessName')
    owner_name = request.form.get('ownerName')
    email = request.form.get('email')
    phone_number = request.form.get('phoneNumber')
    password = request.form.get('password')
    confirm_password = request.form.get('confirmPassword')
    business_type = request.form.get('businessType') # Expected to be 'vendor' or 'supplier'
    business_location = request.form.get('businessLocation')
    
    # Extract fields specific to 'vendor' or 'supplier' types.
    food_specialty = request.form.get('foodSpecialty') if business_type == 'vendor' else None
    avg_daily_customers = int(request.form.get('avgDailyCustomers')) if request.form.get('avgDailyCustomers') and business_type == 'vendor' else None
    supply_capacity = request.form.get('supplyCapacity') if business_type == 'supplier' else None
    delivery_regions = request.form.get('deliveryRegions') if business_type == 'supplier' else None
    fssai_license = request.form.get('fssaiLicense') if business_type == 'supplier' else None
    
    # Convert checkbox values ('on' or None) to boolean True/False.
    terms_accepted = request.form.get('termsAccepted') == 'on'
    receive_updates = request.form.get('receiveUpdates') == 'on'
    
    # Basic server-side validation for required fields.
    if not all([business_name, owner_name, email, phone_number, password, confirm_password, business_type, business_location, terms_accepted]):
        logging.warning("Signup failed: Missing required fields or terms not accepted.")
        return jsonify({'status': 'error', 'message': 'All required fields must be filled and Terms accepted!'}), 400
    
    if password != confirm_password:
        logging.warning("Signup failed: Passwords do not match.")
        return jsonify({'status': 'error', 'message': 'Passwords do not match!'}), 400
    
    if len(password) < 8: # Enforce a minimum password length.
        logging.warning("Signup failed: Password too short.")
        return jsonify({'status': 'error', 'message': 'Password must be at least 8 characters long.'}), 400

    # Hash the user's password for secure storage.
    hashed_password = generate_password_hash(password)
    # verification_token is no longer needed as email verification is removed
    # verification_token = secrets.token_urlsafe(32) 

    conn = None
    try:
        conn = get_db_connection()
        # Insert new user data into the 'users' table.
        # 'is_verified' is now always 1 (True) by default, and 'verification_token' is not stored.
        conn.execute(
            """INSERT INTO users 
            (email, password, business_name, owner_name, phone_number, business_type, 
            business_location, food_specialty, avg_daily_customers, supply_capacity, 
            delivery_regions, fssai_license, receive_updates, is_verified) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (email, hashed_password, business_name, owner_name, phone_number, 
             business_type, business_location, food_specialty, avg_daily_customers, 
             supply_capacity, delivery_regions, fssai_license, receive_updates, 1) # is_verified is always 1
        )
        conn.commit() # Commit the transaction to save changes to the database.
        logging.info(f"User {email} registered successfully (email verification skipped).")
        
        # Return success response after successful registration.
        # User will be prompted to sign in manually after this.
        return jsonify({'status': 'success', 'message': 'Account created successfully! You can now sign in.'}), 201

    except sqlite3.IntegrityError:
        # Handle cases where the email already exists (UNIQUE constraint violation).
        logging.warning(f"Signup attempt for existing email: {email}")
        return jsonify({'status': 'error', 'message': 'Email address already registered.'}), 409
    except Exception as e:
        # Catch any other unexpected errors during signup.
        app.logger.error(f"Error during signup for {email}: {e}")
        app.logger.error(f"Signup traceback: {traceback.format_exc()}")
        return jsonify({'status': 'error', 'message': 'An unexpected error occurred during registration.'}), 500
    finally:
        if conn:
            conn.close() # Always close the database connection.

@app.route('/verify/<token>', methods=['GET'])
def verify_email(token):
    """
    This endpoint is now largely vestigial as email verification is removed.
    It will always return a message indicating no verification is needed.
    """
    logging.info(f"Received verification request for token: {token} (Email verification is disabled).")
    return "<h1>Email verification is not required for this application.</h1><p>You can proceed to sign in directly.</p>", 200

@app.route('/api/signin', methods=['POST'])
def api_signin():
    """Handles user login requests.
    Authenticates user credentials. Email verification check is removed.
    """
    email = request.form.get('email')
    password = request.form.get('password')

    if not email or not password:
        return jsonify({'status': 'error', 'message': 'Email and password are required!'}), 400
    
    conn = None
    try:
        conn = get_db_connection()
        # Retrieve user details based on the provided email.
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        
        # Check if a user was found and if the provided password matches the hashed password.
        # The 'is_verified' check is removed here because all users are considered verified upon signup.
        if user and check_password_hash(user['password'], password):
            # If credentials are correct, log the user in.
            session['email'] = user['email'] # Store email in session to mark user as logged in.
            logging.info(f"User {email} logged in successfully.")
            return jsonify({
                'status': 'success', 
                'message': 'Logged in successfully!',
                'email': user['email'],
                'business_name': user['business_name'],
                'owner_name': user['owner_name'],
                'business_type': user['business_type'] # Include business_type
            }), 200
        else:
            # If no user found or password does not match.
            logging.warning(f"Failed login attempt for email: {email} - Invalid credentials.")
            return jsonify({'status': 'error', 'message': 'Invalid email or password.'}), 401
    except Exception as e:
        # Catch any unexpected errors during the sign-in process.
        app.logger.error(f"Error during signin for {email}: {e}")
        app.logger.error(f"Signin traceback: {traceback.format_exc()}")
        return jsonify({'status': 'error', 'message': 'An unexpected error occurred during login.'}), 500
    finally:
        if conn:
            conn.close() # Always close the database connection.

@app.route('/api/logout', methods=['POST'])
def api_logout():
    """Handles user logout by clearing the user's session."""
    session.pop('email', None) # Remove the 'email' from the session.
    logging.info("User logged out.")
    return jsonify({'status': 'success', 'message': 'You have been logged out.'}), 200

@app.route('/api/user_status', methods=['GET'])
def api_user_status():
    """Checks and returns the current user's login status and basic information.
    Used by the frontend to update UI elements based on login state.
    """
    if 'email' in session:
        conn = None
        try:
            conn = get_db_connection()
            # Fetch minimal user data for display if logged in.
            # Included business_type in the selection
            user = conn.execute("SELECT business_name, owner_name, email, business_type FROM users WHERE email = ?", (session['email'],)).fetchone()
            if user:
                return jsonify({'logged_in': True, 'email': user['email'], 'business_name': user['business_name'], 'owner_name': user['owner_name'], 'business_type': user['business_type']}), 200
        except Exception as e:
            # Log errors if fetching user data from session fails.
            app.logger.error(f"Error checking user status: {e}")
            app.logger.error(traceback.format_exc())
        finally:
            if conn:
                conn.close()
    # If no email in session or an error occurred, return not logged in.
    return jsonify({'logged_in': False}), 200

if __name__ == '__main__':
    # This block runs the Flask development server when the script is executed directly.
    # For local development, it typically runs on http://127.0.0.1:5000/.
    # Ensure this matches the FLASK_BASE_URL in your HTML for correct API calls.
    app.run(debug=True) # debug=True enables reloader and debugger; set to False for production.
