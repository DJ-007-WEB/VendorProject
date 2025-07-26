from flask import Flask, render_template, request, url_for, session, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os
import yagmail
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

# Email Configuration for sending verification emails.
# IMPORTANT: For production deployments, these credentials MUST be loaded
# from environment variables (e.g., os.environ.get('SENDER_EMAIL')).
SENDER_EMAIL = 'djjotwani@gmail.com'
SENDER_APP_PASSWORD = 'emfx ngai bryi aoou' # This should be a Gmail App Password

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
    This table stores user registration details, including email verification status and token.
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
                    is_verified INTEGER NOT NULL DEFAULT 0,    -- 0=False, 1=True
                    verification_token TEXT                     -- Stores the unique verification token
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
            user = conn.execute("SELECT business_name, owner_name, email FROM users WHERE email = ?", (session['email'],)).fetchone()
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
    Collects form data, performs validation, hashes the password, generates a unique
    verification token, stores the user in the database, and sends a verification email.
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
    # Generate a secure, URL-safe token for email verification.
    verification_token = secrets.token_urlsafe(32) # 32 bytes for a reasonably long token

    conn = None
    try:
        conn = get_db_connection()
        # Insert new user data into the 'users' table.
        # 'is_verified' is initially 0 (False), and 'verification_token' is stored.
        conn.execute(
            """INSERT INTO users 
            (email, password, business_name, owner_name, phone_number, business_type, 
            business_location, food_specialty, avg_daily_customers, supply_capacity, 
            delivery_regions, fssai_license, receive_updates, is_verified, verification_token) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (email, hashed_password, business_name, owner_name, phone_number, 
             business_type, business_location, food_specialty, avg_daily_customers, 
             supply_capacity, delivery_regions, fssai_license, receive_updates, 0, verification_token)
        )
        conn.commit() # Commit the transaction to save changes to the database.
        logging.info(f"User {email} registered successfully with token: {verification_token}")
        
        # Attempt to send the verification email.
        try:
            yag = yagmail.SMTP(SENDER_EMAIL, SENDER_APP_PASSWORD)
            # Generate a full external URL for the verification link, essential for emails.
            verification_url = url_for('verify_email', token=verification_token, _external=True)
            yag.send(
                to=email,
                subject='✅ Verify Your FreshConnect Account',
                contents=f"""
                    <h2>Hi {owner_name}, welcome to FreshConnect!</h2>
                    <p>Thanks for registering. Please click the link below to activate your account:</p>
                    <p><a href="{verification_url}" style="padding: 10px 20px; color: white; background-color: #007bff; text-decoration: none; border-radius: 5px; display: inline-block;">Verify My Email</a></p>
                    <p>This link will expire after a certain period or once used.</p>
                    <p>If you did not sign up for this account, you can safely ignore this email.</p>
                    <p>Best regards,<br>The FreshConnect Team</p>
                """
            )
            logging.info(f"Verification email sent to {email}. Verification URL: {verification_url}")
        except Exception as e:
            # Log email sending failures but don't prevent user registration.
            # A mechanism for resending verification emails would be needed in a full application.
            app.logger.error(f"Failed to send verification email to {email}: {e}")
            app.logger.error(f"Email sending traceback: {traceback.format_exc()}")

        # Return success response after successful registration and email attempt.
        return jsonify({'status': 'success', 'message': 'Account created! Please check your email to verify your account.'}), 201

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
    """Handles email verification requests when a user clicks the link in their email.
    Updates the user's 'is_verified' status in the database and clears the verification token.
    """
    logging.info(f"Received verification request for token: {token}")
    conn = None
    try:
        conn = get_db_connection()
        # Attempt to find a user with the provided verification token.
        user = conn.execute("SELECT id, email, is_verified FROM users WHERE verification_token = ?", (token,)).fetchone()
        
        if user:
            logging.info(f"Found user {user['email']} for token {token}. Current verification status: {user['is_verified']}")
            if user['is_verified'] == 1:
                # If the user is already verified, inform them.
                logging.info(f"User {user['email']} is already verified.")
                return "<h1>✅ Your email is already verified!</h1><p>You can now close this tab and sign in.</p>", 200

            # Mark the user as verified (is_verified = 1) and remove the token to prevent reuse.
            conn.execute("UPDATE users SET is_verified = 1, verification_token = NULL WHERE id = ?", (user['id'],))
            conn.commit() # Commit the changes to the database.
            logging.info(f"User {user['email']} (ID: {user['id']}) successfully verified.")
            return "<h1>✅ Your email has been verified successfully!</h1><p>You can now close this tab and sign in.</p>", 200
        else:
            # If no user is found with the token, it's invalid or expired.
            logging.warning(f"No user found for verification token: {token} or token already used/invalid.")
            return "<h1>❌ Invalid or expired verification link.</h1><p>Please try signing up again or contact support.</p>", 400
    except Exception as e:
        # Catch any unexpected errors during the verification process.
        app.logger.error(f"Error during email verification for token {token}: {e}")
        app.logger.error(f"Verification traceback: {traceback.format_exc()}")
        return "<h1>An error occurred during verification.</h1><p>Please try again or contact support.</p>", 500
    finally:
        if conn:
            conn.close() # Always close the database connection.

@app.route('/api/signin', methods=['POST'])
def api_signin():
    """Handles user login requests.
    Authenticates user credentials and checks if their account is verified.
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
        if user and check_password_hash(user['password'], password):
            if user['is_verified'] == 1:
                # If credentials are correct and account is verified, log the user in.
                session['email'] = user['email'] # Store email in session to mark user as logged in.
                logging.info(f"User {email} logged in successfully.")
                return jsonify({
                    'status': 'success', 
                    'message': 'Logged in successfully!',
                    'email': user['email'],
                    'business_name': user['business_name'],
                    'owner_name': user['owner_name']
                }), 200
            else:
                # If credentials are correct but the account is not verified.
                logging.warning(f"Login attempt for unverified user: {email}")
                return jsonify({'status': 'error', 'message': 'Account not verified. Please check your email for a verification link.'}), 403
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
            user = conn.execute("SELECT business_name, owner_name, email FROM users WHERE email = ?", (session['email'],)).fetchone()
            if user:
                return jsonify({'logged_in': True, 'email': user['email'], 'business_name': user['business_name'], 'owner_name': user['owner_name']}), 200
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
