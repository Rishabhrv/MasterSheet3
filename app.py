import json
import logging
import os
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler
import gspread
import pytz
from pytz import timezone
from flask import (Flask, jsonify, redirect,
                   render_template, request, session, url_for, flash)
from google.oauth2.service_account import Credentials
from flask_mail import Mail, Message
import random
import string
from werkzeug.exceptions import BadRequest
import jwt
from dotenv import load_dotenv


app = Flask(__name__)
load_dotenv()
app.secret_key = os.getenv('SECRET_KEY', 'default-secret-key') 
SECRET_KEY = app.secret_key

scope = ["https://www.googleapis.com/auth/spreadsheets"]


creds_path = os.getenv('CREDS_PATH', 'token.json')
users_json_path = os.getenv('USERS_JSON_PATH', 'users.json')
sheets_json_path = os.getenv('SHEETS_JSON_PATH', 'sheets.json')


load_dotenv()

app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'False') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

mail = Mail(app)

# Temporary storage for OTPs
otp_store = {}  

credentials = Credentials.from_service_account_file(creds_path, scopes = scope)
gc = gspread.authorize(credentials)

# Custom Formatter for IST Time Zone
class ISTFormatter(logging.Formatter):
    def __init__(self, fmt=None, datefmt=None):
        super().__init__(fmt, datefmt)
        self.ist = timezone('Asia/Kolkata')

    def formatTime(self, record, datefmt=None):
        record_time = datetime.fromtimestamp(record.created, self.ist)
        return record_time.strftime(datefmt or self.default_time_format)

# Configure the log file and handler
LOG_FILENAME = 'app.log'
log_handler = RotatingFileHandler(LOG_FILENAME, maxBytes=5*1024*1024, backupCount=10)
log_handler.setLevel(logging.INFO)

# Set the custom formatter for IST
log_format = '%(asctime)s - %(levelname)s - %(message)s'
log_handler.setFormatter(ISTFormatter(fmt=log_format, datefmt='%d-%m-%Y %H:%M:%S'))

# Get the root logger and set its handler
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)

werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.setLevel(logging.WARNING)

def read_users_from_json():
    if os.path.exists(users_json_path):
        with open(users_json_path, 'r') as file:
            return json.load(file)
    return []

def write_users_to_json(users):
    with open(users_json_path, 'w') as file:
        json.dump(users, file, indent=4)


def read_sheets_from_json():
    if os.path.exists(sheets_json_path):
        with open(sheets_json_path, 'r') as file:
            return json.load(file)
    return {}

def write_sheets_to_json(sheets):
    with open(sheets_json_path, 'w') as file:
        json.dump(sheets, file, indent=4)

sheets = read_sheets_from_json()
users = read_users_from_json()

# Add enumerate to the Jinja2 environment via context processor
@app.context_processor
def utility_processor():
    return dict(enumerate=enumerate)

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=120)


@app.before_request
def manage_session():
    session.permanent = True

    # Bypass the check if we're on the login, logout, or static routes
    if request.endpoint in ('login', 'static', 'logout',
                            'redirect_to_adsearch', 'redirect_to_newcrm',
                            'forgot_password', 'reset_password'):
        return None

    # If user is not logged in, redirect to login
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    # If user is logged in but is not an admin, check time restrictions
    if session.get('logged_in') and session.get('user_role') != 'Admin':
        if not is_access_allowed():
            username = session.get('name', 'Unknown User')
            app.logger.info(f'Logging out user {username} due to time restriction.')
            return redirect(url_for('logout'))
        
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        # Load user data
        users = read_users_from_json()
        user = next((u for u in users if u['email'] == email), None)

        if user:
            
            # Allow password reset only if email belongs to an Admin
            if user.get('role') != 'Admin':  
                flash("Only Admins can reset their password.", "danger")
                logging.warning(f"Unauthorized password reset attempt by non-admin: {email}")
                return redirect(url_for('login'))
            
            # Generate OTP
            otp = ''.join(random.choices(string.digits, k=6))  # 6-digit OTP
            otp_store[email] = otp

            # Send OTP via email
            msg = Message('MasterSheet Password Reset', recipients=[email])
            msg.body = f"""
            Dear User,

            You have requested to reset your password. Please use the One-Time Password (OTP) below to proceed with the reset:

            🔑 OTP: {otp}

            For security reasons, this OTP is valid for a limited time and should not be shared with anyone. If you did not request a password reset, please ignore this email."""
            mail.send(msg)

            logging.info(f"OTP sent to Admin {email} for password reset.")

            flash('An OTP has been sent to your email.', 'info')
            return redirect(url_for('reset_password', email=email))
        else:
            flash('Email not found!', 'danger')
            logging.warning(f"Password reset attempt with non-existent email: {email}")

    return render_template('forgot_password.html')


@app.route('/reset-password/<email>', methods=['GET', 'POST'])
def reset_password(email):
    # Load user data
    users = read_users_from_json()
    user = next((u for u in users if u['email'] == email), None)

    # Ensure email exists and belongs to an Admin
    if not user or user.get('role') != 'Admin':
        flash("Only Admins can reset their password.", "danger")
        logging.warning(f"Unauthorized reset password access attempt by: {email}")
        return redirect(url_for('login'))

    if request.method == 'POST':
        entered_otp = request.form['otp']
        new_password = request.form['new_password']

        # Validate OTP
        if otp_store.get(email) == entered_otp:
            # Update password in the user database
            for user in users:
                if user['email'] == email:
                    user['pass'] = new_password
                    break

            write_users_to_json(users)  # Save changes
            otp_store.pop(email, None)  # Remove OTP after use

            logging.info(f"Admin {email} successfully reset their password.")

            flash('Password reset successfully.', 'success')
            session.modified = True
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')
            logging.warning(f"Invalid OTP entered for {email}.")

    return render_template('reset_password.html', email=email)


@app.route('/redirect_to_content_dashboard')
def redirect_to_content_dashboard():
    import time
    if not session.get('logged_in') or session.get('user_role') != 'Writer':
        app.logger.warning("Unauthorized request to redirect_to_content_dashboard.")
        return redirect(url_for('login'))

    try:
        expiration_time = int(time.time()) + 20 * 60
        
        token = jwt.encode({
            'user': session['name'],
            'role': session['user_role'],
            'exp': expiration_time
        }, SECRET_KEY, algorithm='HS256')

        dashboard_url = f"https://agkit.agvolumes.com/teamdash?token={token}"
        #dashboard_url = f"http://localhost:8501/teamdash?token={token}"
        app.logger.info("Redirect to Content Data Dashboard successfully")
        return redirect(dashboard_url)
    except Exception as e:
        app.logger.error(f"Error generating token or redirect URL: {str(e)}")
        return "Internal Server Error", 500
    

@app.route('/redirect_to_proofread_dashboard')
def redirect_to_proofread_dashboard():
    import time
    if not session.get('logged_in') or session.get('user_role') != 'proofreader':
        app.logger.warning("Unauthorized request to redirect_to_proofread_dashboard.")
        return redirect(url_for('login'))

    try:
        expiration_time = int(time.time()) + 20 * 60
        
        token = jwt.encode({
            'user': session['name'],
            'role': session['user_role'],
            'exp': expiration_time
        }, SECRET_KEY, algorithm='HS256')

        dashboard_url = f"https://agkit.agvolumes.com/teamdash?token={token}"
        #dashboard_url = f"http://localhost:8501/teamdash?token={token}"
        app.logger.info("Redirect to Proofread Data Dashboard successfully")
        return redirect(dashboard_url)
    except Exception as e:
        app.logger.error(f"Error generating token or redirect URL: {str(e)}")
        return "Internal Server Error", 500

        
@app.route('/redirect_to_dashboard')
def redirect_to_dashboard():
    import time
    if not session.get('logged_in') or session.get('user_role') != 'Admin':
        app.logger.warning("Unauthorized request to redirect_to_dashboard.")
        return redirect(url_for('login'))

    try:
        # Get the current time and add 10 minutes in seconds
        expiration_time = int(time.time()) + 20 * 60
        
        token = jwt.encode({
            'user': session['name'],
            'role': session['user_role'],
            'exp': expiration_time
        }, SECRET_KEY, algorithm='HS256')

        dashboard_url = f"https://agkit.agvolumes.com/?token={token}"
        #dashboard_url = f"http://localhost:8501/?token={token}"
        app.logger.info("Redirect to Data Dashboard successfully")
        return redirect(dashboard_url)
    except Exception as e:
        app.logger.error(f"Error generating token or redirect URL: {str(e)}")
        return "Internal Server Error", 500
    

@app.route('/redirect_to_newcrm')
def redirect_to_newcrm():
    import time
    if not session.get('logged_in') or (session.get('user_role') != 'Book Entry' and session.get('user_role') != 'Admin'):
        app.logger.warning("Unauthorized request to redirect_to_newcrm.")
        return redirect(url_for('login'))

    try:
        # Get the current time and add 10 minutes in seconds
        expiration_time = int(time.time()) + 60 * 60
        
        token = jwt.encode({
            'user': session['name'],
            'role': session['user_role'],
            'exp': expiration_time
        }, SECRET_KEY, algorithm='HS256')

        dashboard_url = f"https://newcrm.agvolumes.com/?token={token}"
        #dashboard_url = f"http://localhost:8501/?token={token}"
        app.logger.info("Redirect to New CRM successfully")
        return redirect(dashboard_url)
    except Exception as e:
        app.logger.error(f"Error generating token or redirect URL: {str(e)}")
        return "Internal Server Error", 500


@app.route('/redirect_to_ijisem')
def redirect_to_ijisem():
    import time
    if not session.get('logged_in') or session.get('user_role') != 'Admin':
        app.logger.warning("Unauthorized request to redirect_to_ijisem.")
        return redirect(url_for('login'))

    try:
        # Get the current time and add 10 minutes in seconds
        expiration_time = int(time.time()) + 20 * 60
        
        token = jwt.encode({
            'user': session['name'],
            'role': session['user_role'],
            'exp': expiration_time
        }, SECRET_KEY, algorithm='HS256')

        dashboard_url = f"https://agkit.agvolumes.com/ijisem/?token={token}"
        #dashboard_url = f"http://localhost:8501/ijisem/?token={token}"
        app.logger.info("Redirect to IJISEM successfully")
        return redirect(dashboard_url)
    except Exception as e:
        app.logger.error(f"Error generating token or redirect URL: {str(e)}")
        return "Internal Server Error", 500
    
@app.route('/redirect_to_agsearch')
def redirect_to_agsearch():
    import time
    if not session.get('logged_in') or session.get('user_role') != 'Admin':
        app.logger.warning("Unauthorized request to redirect_to_agsearch.")
        return redirect(url_for('login'))

    try:
        # Get the current time and add 10 minutes in seconds
        expiration_time = int(time.time()) + 20 * 60
        
        token = jwt.encode({
            'user': session['name'],
            'role': session['user_role'],
            'exp': expiration_time
        }, SECRET_KEY, algorithm='HS256')

        dashboard_url = f"https://agsearch.agvolumes.com/?token={token}"
        #dashboard_url = f"http://localhost:8502/?token={token}"
        app.logger.info("Redirect to agsearch successfully")
        return redirect(dashboard_url)
    except Exception as e:
        app.logger.error(f"Error generating token or redirect URL: {str(e)}")
        return "Internal Server Error", 500


@app.route('/redirect_to_adsearch', methods=['POST'])
def redirect_to_adsearch():
    import time
    from flask import request, jsonify

    try:
        # Validate API key
        api_key = request.headers.get('Authorization')
        if not api_key:
            app.logger.warning("Missing Authorization header.")
            return jsonify({"error": "Authorization header is missing"}), 400

        if api_key != SECRET_KEY:
            app.logger.warning("Unauthorized request to redirect_to_adsearch.")
            return jsonify({"error": "Unauthorized"}), 401

        # Validate and parse JSON payload
        data = request.get_json()
        if not data or 'user' not in data or 'role' not in data:
            app.logger.warning("Invalid JSON payload received.")
            return jsonify({"error": "Invalid request data"}), 400

        # Generate token and construct URL
        expiration_time = int(time.time()) + 10 * 60
        token = jwt.encode({
            'user': data['user'],
            'role': data['role'],
            'exp': expiration_time
        }, SECRET_KEY, algorithm='HS256')

        adsearch_url = f"https://agsearch.agvolumes.com/?token={token}"
        #adsearch_url = f"http://localhost:8502/?token={token}"
        return jsonify({"url": adsearch_url}), 200
    except Exception as e:
        app.logger.error(f"Error in /redirect_to_adsearch API: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500


@app.route('/logout')
def logout():
    username = session.get('name', 'Unknown User')
    start_time = session.get('start_time')
    end_time = datetime.now(timezone.utc)

    if start_time:
        if isinstance(start_time, str):
            start_time = datetime.fromisoformat(start_time)
        session_duration = end_time - start_time
        formatted_duration = f"{session_duration.seconds // 60} min {session_duration.seconds % 60} sec"
        app.logger.info(f'User {username} logged out. Session duration: {formatted_duration}')
    else:
        app.logger.info(f'User {username} logged out but session start time not found.')

    session.clear()
    return redirect(url_for('login'))


def is_access_allowed():
    india_tz = pytz.timezone('Asia/Kolkata')
    current_time = datetime.now(india_tz).time()
    start_time = datetime.strptime('09:30', '%H:%M').time()
    end_time = datetime.strptime('18:00', '%H:%M').time()
    return start_time <= current_time <= end_time      

def filter_columns(data, exclude_columns):
    if "view_all" in exclude_columns:
        return data, list(range(len(data[0])))  # Return data and a direct mapping if no columns are excluded
    else:
        cleaned_permissions = {permission.strip() for permission in exclude_columns}
        headers = data[0]
        allowed_indices = [idx for idx, header in enumerate(headers) if header.strip() not in cleaned_permissions]

        # Return both the filtered data and the list of allowed indices (mapping to original data)
        filtered_data = [[cell for idx, cell in enumerate(row) if idx in allowed_indices] for row in data]
        return filtered_data, allowed_indices  # Filtered data and mapping of allowed indices


def filter_editable_columns(filtered_headers, original_headers, editable_columns):
    cleaned_permissions = [perm.split(":")[1].strip() if ":" in perm else perm for perm in editable_columns]

    # Handle the case where the user has "view_all" permission
    if "view_all" in cleaned_permissions:
        return list(range(len(filtered_headers)))

    return [filtered_headers.index(header) for header in original_headers if header in cleaned_permissions]

def set_user_sheet_session(sheet_name, sheet_id=None):
    """Set session variables related to the current sheet and user permissions."""
    
    if session.get('user_role') == 'Admin':
        # Admin has access to all sheets
        session['current_sheet_id'] = sheet_id if sheet_id else sheets.get(sheet_name)
        session['current_sheet_name'] = sheet_name
        session['exclude_columns'] = ['view_all']
        session['editable_columns'] = ['view_all']
    else:
        # Non-admin users
        user_sheets = session.get('user_sheets', {})
        if sheet_name in user_sheets:
            session['current_sheet_id'] = sheet_id if sheet_id else sheets.get(sheet_name)
            session['current_sheet_name'] = sheet_name
            session['exclude_columns'] = user_sheets[sheet_name]['exclude_columns']
            session['editable_columns'] = user_sheets[sheet_name]['editable_columns']
        else:
            app.logger.warning(f"Unauthorized access attempt by user: {session.get('user_role')}")
            raise PermissionError("Unauthorized access")
        
from datetime import datetime, timezone
@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        return redirect(url_for('index'))

    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        app.logger.info(f'Trying to login with username: {username}')
        
        users = read_users_from_json()
        user = next((u for u in users if u['email'] == username and u['pass'] == password), None)

        if user:
            # Check if the user is not an admin and if access is allowed
            if user['role'] != 'Admin' and not is_access_allowed():
                app.logger.warning(f'Login attempt outside permitted hours by user: {username}')
                error = "Access restricted. You can only access the sheet between 09:30 AM and 06:00 PM."
            else:
                session['logged_in'] = True
                session['user_role'] = user['role']
                session['name'] = user['name']
                session['start_time'] = datetime.now(timezone.utc).isoformat()
                # Load sheets and their specific permissions for the user
                if user['role'] == 'Admin':
                    # Admin has access to all sheets
                    session['user_sheets'] = sheets
                    
                    first_available_sheet = next(iter(session['user_sheets']), None)
                    if first_available_sheet:
                        set_user_sheet_session(first_available_sheet)
                    else:
                        session['current_sheet_name'] = None
                        session['current_sheet_id'] = None
                        session['exclude_columns'] = []
                        session['editable_columns'] = []
                else:
                    # Non-admin users
                    session['user_sheets'] = user.get('sheets', {})
                    
                    # Assign default sheet (could be the first in the list)
                    default_sheet = next(iter(session['user_sheets']), None)
                    if default_sheet:
                        set_user_sheet_session(default_sheet)
                    else:
                        session['current_sheet_name'] = None
                        session['current_sheet_id'] = None
                        session['exclude_columns'] = []
                        session['editable_columns'] = []
                
                app.logger.info(f'User {session["name"]} logged in successfully, assigned default sheet: {session["current_sheet_name"]}')
                return redirect(url_for('index'))
        else:
            app.logger.warning(f'Invalid login attempt for username: {username}') 
            error = 'Invalid credentials'
    
    return render_template('login.html', error=error)

checkbox_columns = ['Book Complete', 'Apply ISBN', 'ID Proof','Welcome Mail / Confirmation', 'Check',
                    'Author Detail','Photo','Writing Complete','Proofreading Complete',
                    'Formating Complete', 'Cover Page', 'Back Page Update', 'Send Cover Page and Agreement',
                    'Agreement Received','Digital Prof', 'Plagiarism Report', 'Confirmation', 'Ready to Print',
                    'Print','Final Mail','Deliver','Google Review','Writing Complete','Proofreading Complete',
                    'Formating Complete','Review Process','Acceptance']

@app.route('/')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    current_sheet_name = session.get('current_sheet_name')
    current_sheet_id = session.get('current_sheet_id')

    # If for some reason current_sheet_id is not found, return an error rather than assigning a new sheet
    if not current_sheet_id:
        app.logger.error(f"Sheet ID not found for the current session. Sheet name: {current_sheet_name}")
        session.clear()
        return "Error: No valid sheet assigned to you."

    # Fetch the sheet using the current_sheet_id stored in the session
    try:
        sheet = gc.open_by_key(current_sheet_id).sheet1
    except Exception as e:
        app.logger.error(f"Error opening sheet with ID {current_sheet_id}: {e}")
        session.clear()
        return "Error: Could not access the assigned sheet. Could be API Error"

    # Get all values from the Google Sheet
    values = sheet.get_all_values()

    if not values or not values[0]:
        # If values is empty or the first row is empty, return an error message
        app.logger.warning('No data available or incorrect sheet format.')
        return "No data available in the sheet or the sheet format is incorrect."

    # Get user permissions from session
    exclude_columns = session.get('exclude_columns', [])
    editable_columns = session.get('editable_columns', [])

    # Filter columns
    filtered_values, allowed_indices = filter_columns(values, exclude_columns)
    filtered_headers = filtered_values[0]

    # Determine editable indices based on filtered headers
    editable_indices = filter_editable_columns(filtered_headers, values[0], editable_columns)

    # Get sheets available to the user
    if session['user_role'] == 'Admin':
        # Admin can access all sheets
        user_sheets = sheets
    else:
        # Non-admin users can only access their assigned sheets
        user_sheets = {sheet_name: sheets[sheet_name] for sheet_name in session.get('user_sheets', [])}

    return render_template(
        'index.html', 
        values=filtered_values, 
        allowed_indices=allowed_indices,
        columns=len(filtered_values[0]) if filtered_values else 0,
        sheets=sheets,  # For Admin use
        user_sheets=user_sheets,  # For non-admin users
        current_sheet_name=session.get('current_sheet_name'), 
        editable_indices=editable_indices,
        filtered_headers = filtered_headers,
        checkbox_columns = checkbox_columns
        
    )

@app.route('/update', methods=['POST'])
def update():
    try:
        # Fetch the sheet dynamically using the sheet ID stored in the session
        current_sheet_id = session.get('current_sheet_id')
        if not current_sheet_id:
            raise BadRequest('No sheet selected.')

        sheet = gc.open_by_key(current_sheet_id).sheet1
        
        row = int(request.form['row'])
        col = int(request.form['col'])
        value = request.form['value']
        
        if row <= 0 or col <= 0:
            raise BadRequest('Row and column must be positive integers.')

        # Update the Google Sheet with the value
        sheet.update_cell(row, col, value)
        return 'OK'
    
    except (ValueError, BadRequest) as e:
        app.logger.error(f'Invalid input: {e}')
        return jsonify({'status': 'error', 'message': str(e)}), 400

    except gspread.exceptions.APIError as e:
        app.logger.error(f'Google Sheets API error: {e}')
        return jsonify({'status': 'error', 'message': 'Google Sheets API error'}), 500
    
    except Exception as e:
        app.logger.error(f'Error updating cell: {e}')
        return jsonify({'status': 'error', 'message': str(e)}), 500

        
@app.route('/add', methods=['POST'])
def add_new_data():
    try:
        current_sheet_id = session.get('current_sheet_id')
        if not current_sheet_id:
            raise BadRequest('No sheet selected.')

        sheet = gc.open_by_key(current_sheet_id).sheet1
        
        data = request.form['data']
        new_row = json.loads(data)  # Safely parse JSON data

        if not isinstance(new_row, list) or not all(isinstance(item, str) for item in new_row):
            raise BadRequest('Invalid data format. Expected a list of strings.')

        # Append the new row to the Google Sheet
        sheet.append_row(new_row)
        app.logger.info(f'Added new row: {new_row}')
        return 'OK'
    
    except (ValueError, BadRequest) as e:
        app.logger.error(f'Invalid input: {e}')
        return jsonify({'status': 'error', 'message': str(e)}), 400
    
    except gspread.exceptions.APIError as e:
        app.logger.error(f'Google Sheets API error: {e}')
        return jsonify({'status': 'error', 'message': 'Google Sheets API error'}), 500
    
    except Exception as e:
        app.logger.error(f'Error adding new data: {e}')
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/access_control')
def access_control():
    if session.get('user_role') != 'Admin':
        app.logger.warning('Unauthorized access to accesscontrol by non-admin user.')
        return redirect(url_for('index'))
    for user in users:
        if user['role'] == 'Admin':
            # Admin can access all sheets, so add sheets from sheets.json
            user['sheets'] = sheets
    return render_template('admin.html', users=users)

@app.route('/sheets', methods=['GET','POST'])
def manage_sheets():
    sheet_name = request.form['sheet_name']
    sheet_id = request.form['sheet_id']

    if len(sheet_id) != 44:
        return jsonify({'status': 'error', 'message': 'Invalid Sheet ID length.'}), 400
    try:
        sheets[sheet_name] = sheet_id
        write_sheets_to_json(sheets)
        app.logger.info(f'Sheet Added: {sheet_name}')
        return jsonify({'status': 'success', 'message': 'Sheet added successfully.', 'sheet_name': sheet_name, 'sheet_id': sheet_id}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': 'Failed to add sheet.'}), 500

@app.route('/select_sheet/<sheet_id>', methods=['POST'])
def select_sheet(sheet_id):
    # Fetch the sheet name from the request
    sheet_name = request.form.get('sheet_name', 'Google Sheet')

    # Check if the user is logged in
    if not session.get('logged_in'):
        return jsonify({'status': 'error', 'message': 'User not logged in'}), 403
    try:
        # Set session variables for the selected sheet
        set_user_sheet_session(sheet_name, sheet_id)
        app.logger.info(f'Sheet switched: {session["current_sheet_name"]} by user: {session.get("name")}')
        return '', 204

    except PermissionError:
        return jsonify({'status': 'error', 'message': 'Unauthorized access'}), 403  

@app.route('/delete_user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    global users
    # Find the user to be deleted
    user_to_delete = next((user for user in users if user['id'] == user_id), None)
    
    if user_to_delete is None:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404

    # Log the user's name
    user_name = user_to_delete.get('name', 'Unknown')
    users = [user for user in users if user['id'] != user_id]
    write_users_to_json(users)
    app.logger.info(f'User {user_name} ID: {user_id} deleted by Admin.')
    
    return jsonify({'status': 'ok'})

@app.route('/delete_sheet/<sheet_name>', methods=['POST'])
def delete_sheet(sheet_name):
    if session.get('user_role') == 'Admin':
        if sheet_name in sheets:
            # Check if the current sheet is being deleted
            if session.get('current_sheet_name') == sheet_name:
                # Get a list of all available sheets except the one being deleted
                remaining_sheets = {k: v for k, v in sheets.items() if k != sheet_name}
                
                # Delete the sheet
                del sheets[sheet_name]
                write_sheets_to_json(sheets)  # Update the JSON file
                app.logger.info(f'Sheet {sheet_name} deleted by Admin.')

                # Check if there are remaining sheets to switch to
                if remaining_sheets:
                    # Select the first available sheet after deletion
                    new_sheet_name, new_sheet_id = next(iter(remaining_sheets.items()))
                    set_user_sheet_session(new_sheet_name, new_sheet_id)
                    app.logger.info(f"Switched to new sheet: {new_sheet_name}")
                else:
                    # No more sheets available, reset session
                    session['current_sheet_name'] = None
                    session['current_sheet_id'] = None
                    session['exclude_columns'] = []
                    session['editable_columns'] = []
                    app.logger.info("No sheets left after deletion. Session reset.")

                return '', 204
            else:
                # Simply delete the sheet if it's not the current one
                del sheets[sheet_name]
                write_sheets_to_json(sheets)  # Update the JSON file
                app.logger.info(f'Sheet {sheet_name} deleted by Admin.')
                return '', 204
        else:
            return "Sheet not found", 404
    else:
        return "Unauthorized", 403


#--------------------###############################

# Route to fetch available sheets
@app.route('/get_sheets', methods=['GET'])
def get_sheets():
    try:
        # Extract sheet names from sheets.json or dynamically fetch them from Google Sheets
        sheet_names = list(sheets.keys())
        return jsonify(sheet_names), 200
    except Exception as e:
        return jsonify({"error": "Failed to fetch sheet names", "details": str(e)}), 500

@app.route('/get_user/<int:user_id>', methods=['GET'])
def get_user(user_id):
    user = next((u for u in users if u['id'] == user_id), None)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user), 200

# Existing route to add a new user
@app.route('/add_user', methods=['POST'])
def add_user():
    data = request.json
    if not data:
        return jsonify({"error": "Invalid input"}), 400

    # Check if the email already exists
    existing_user = next((u for u in users if u['email'] == data['email']), None)
    if existing_user:
        return jsonify({"error": "Email already exists. Please use a different email."}), 400

    new_id = max(user['id'] for user in users) + 1 if users else 1

    # Parse the sheets data which contains multiple sheets with their exclude_columns and editable_columns
    sheets = {}
    for sheet in data['sheets']:
        sheet_name = sheet['sheet_name']
        exclude_columns = sheet['exclude_columns']
        editable_columns = sheet['editable_columns']

        # Add sheet details to the dictionary
        sheets[sheet_name] = {
            "exclude_columns": exclude_columns,
            "editable_columns": editable_columns
        }

    # Create a new user dictionary
    new_user = {
        "id": new_id,
        "name": data['name'],
        "email": data['email'],
        "pass": data['password'],
        "role": data['role'],
        "sheets": sheets
    }

    # Add the new user to the users list
    users.append(new_user)

    # Write the updated users list back to the JSON file
    write_users_to_json(users)

    app.logger.info(f'New user added: {new_user["name"]} with email: {new_user["email"]}')
    return jsonify(new_user), 200

# Existing route to edit an existing user
@app.route('/edit_user/<int:user_id>', methods=['PUT'])
def edit_user(user_id):
    app.logger.info(f"Edit request received for user ID: {user_id}")
    data = request.json
    
    # Find the user
    user = next((user for user in users if user['id'] == user_id), None)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Update user basic info
    user['name'] = data['name']
    user['email'] = data['email']
    user['pass'] = data['password']
    user['role'] = data['role']
    
    # Handle multiple sheets
    sheets = {}
    for sheet in data['sheets']:
        sheet_name = sheet['sheet_name']
        exclude_columns = sheet.get('exclude_columns', [])
        editable_columns = sheet.get('editable_columns', [])
        
        # Update the sheet details in the dictionary
        sheets[sheet_name] = {
            "exclude_columns": exclude_columns,
            "editable_columns": editable_columns
        }

    # Update the user sheets with the new data
    user['sheets'] = sheets

    # Write changes to JSON file
    write_users_to_json(users)

    app.logger.info(f'User {user["name"]} updated with email: {user["email"]}')
    return jsonify(user), 200

@app.route('/get_columns/<sheet_name>', methods=['GET'])
def get_sheet_columns(sheet_name):
    if not sheet_name:
        return jsonify({"error": "Sheet name is required"}), 400

    # Ensure the sheet name exists in sheets dictionary
    if sheet_name not in sheets:
        return jsonify({"error": "Invalid sheet name"}), 400

    try:
        # Fetch the sheet ID from the sheets dictionary
        sheet_id = sheets[sheet_name]
        # Open the Google Sheet by its ID
        sheet = gc.open_by_key(sheet_id).sheet1
        # Assuming the first row contains column names
        columns = sheet.row_values(1)
    except Exception as e:
        app.logger.error(f"Error fetching columns for {sheet_name}: {str(e)}")
        return jsonify({"error": "Failed to fetch column names"}), 500

    # Return the columns for the selected sheet
    return jsonify(columns), 200

if __name__ == "__main__":
    app.run(debug = False)