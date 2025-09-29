import os
import sqlite3
import json
from datetime import datetime, timedelta, timezone
import secrets
import qrcode
import io
import base64
from flask import Flask, render_template, request, redirect, url_for, flash, g, session, send_from_directory, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from forms import (RegistrationForm, LoginForm, ProfileForm, ChangePasswordForm, MedicineForm, 
                   ReminderForm, HistoryForm, AppointmentForm, EmergencyContactForm)

# --- App Configuration ---
app = Flask(__name__)

# ADD THIS ENTIRE BLOCK OF CODE RIGHT HERE
# --- Custom Jinja Filter for Indian Date/Time ---
# REPLACE this entire function
def format_datetime_indian(value, format_str='%d-%m-%Y %I:%M %p'):
    if value is None: return ""

    # This function now correctly converts UTC time from the database to IST
    if isinstance(value, str):
        try:
            # Handle ISO format strings from the database
            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except (ValueError, TypeError):
             return value

    # Assume the naive datetime from DB is UTC
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    # Define IST timezone and convert
    ist_tz = timezone(timedelta(hours=5, minutes=30))
    value_in_ist = value.astimezone(ist_tz)

    return value_in_ist.strftime(format_str)

app.jinja_env.filters['datetime_indian'] = format_datetime_indian


app.config['SECRET_KEY'] = 'a_very_secret_key_that_should_be_changed'
app.config['DATABASE'] = 'healthcare.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}

if not os.path.exists(os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])):
    os.makedirs(os.path.join(app.root_path, app.config['UPLOAD_FOLDER']))

# --- Database Helper Functions ---
def get_db():
    if 'db' not in g:
        db_path = os.path.join(app.root_path, app.config['DATABASE'])
        g.db = sqlite3.connect(db_path, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None: db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

@app.cli.command('initdb')
def initdb_command():
    '''Initializes the database.'''
    init_db()
    print('Initialized the database.')

# --- User Authentication (Flask-Login) ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, email, full_name):
        self.id, self.email, self.full_name = id, email, full_name

@login_manager.user_loader
def load_user(user_id):
    user_data = get_db().execute('SELECT id, email, full_name FROM users WHERE id = ?', (user_id,)).fetchone()
    if user_data:
        return User(id=user_data['id'], email=user_data['email'], full_name=user_data['full_name'])
    return None

# --- Global Data for Templates (Context Processor) ---
@app.context_processor
def inject_global_data():
    if not current_user.is_authenticated:
        return {}
    
    db = get_db()
    profiles = db.execute("SELECT id, profile_name, is_manager FROM profiles WHERE manager_user_id = ? ORDER BY is_manager DESC, profile_name ASC", (current_user.id,)).fetchall()
    
    active_profile_id = session.get('active_profile_id')
    if not active_profile_id or not any(p['id'] == active_profile_id for p in profiles):
        primary_profile = next((p for p in profiles if p['is_manager']), None)
        active_profile_id = primary_profile['id'] if primary_profile else (profiles[0]['id'] if profiles else None)
        session['active_profile_id'] = active_profile_id
    
    active_profile = None
    if active_profile_id:
        active_profile = db.execute("SELECT * FROM profiles WHERE id = ?", (active_profile_id,)).fetchone()

    today_name = datetime.now().strftime('%a')
    all_reminders_today = []
    taken_today_ids = set()
    if active_profile_id:
        all_reminders_today = db.execute("SELECT m.id, m.name, r.time FROM reminders r JOIN medicines m ON r.medicine_id = m.id WHERE r.profile_id = ? AND r.days LIKE ?", (active_profile_id, f'%{today_name}%')).fetchall()
        taken_today_rows = db.execute("SELECT DISTINCT medicine_id FROM medicine_intake WHERE profile_id = ? AND DATE(taken_at) = DATE('now', 'localtime')", (active_profile_id,)).fetchall()
        taken_today_ids = {row['medicine_id'] for row in taken_today_rows}
    
    return dict(
        profiles=profiles,
        active_profile=active_profile,
        daily_reminders=[dict(row) for row in all_reminders_today],
        taken_today_ids=list(taken_today_ids)
    )

# --- Helper Functions ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def log_activity(activity_type, description):
    profile_id = session.get('active_profile_id')
    if profile_id:
        db = get_db()
        db.execute('INSERT INTO recent_activities (profile_id, activity_type, description) VALUES (?, ?, ?)',
                   (profile_id, activity_type, description))
        db.commit()

# In app.py, replace the existing function with this one:

# In app.py, replace the existing function with this one:

def calculate_and_save_adherence(profile_id, intake_date=None):
    """
    Calculates adherence based on the formula:
    (Number of intakes) / (Number of missed + Number of intakes) * 100
    """
    if not profile_id: return 100

    db = get_db()
    now = datetime.now()
    today_name = now.strftime('%a')
    current_time_str = now.strftime('%H:%M')
    today_date_str = now.strftime('%Y-%m-%d')

    # 1. Get the set of medicine IDs for all reminders due today up to the current time
    due_reminders_rows = db.execute(
        "SELECT medicine_id FROM reminders WHERE profile_id = ? AND days LIKE ? AND time <= ?",
        (profile_id, f'%{today_name}%', current_time_str)
    ).fetchall()
    due_reminders_set = {row['medicine_id'] for row in due_reminders_rows}

    # 2. Get the set of distinct medicine IDs logged as taken today
    intake_rows = db.execute(
        "SELECT DISTINCT medicine_id FROM medicine_intake WHERE profile_id = ? AND DATE(taken_at) = DATE('now', 'localtime')",
        (profile_id,)
    ).fetchall()
    intake_set = {row['medicine_id'] for row in intake_rows}

    # 3. Calculate the components of the formula
    # num_intake: Medicines that were due AND were taken
    num_intake = len(due_reminders_set.intersection(intake_set))
    
    # num_missed: Medicines that were due but were NOT taken
    num_missed = len(due_reminders_set.difference(intake_set))

    denominator = num_intake + num_missed
    
    if denominator == 0:
        # If no reminders were due yet, adherence is 100%
        adherence_percent = 100
    else:
        adherence_percent = round((num_intake / denominator) * 100)

    # 4. Save the result to the database, which will update the stats page graph
    db.execute("INSERT OR REPLACE INTO adherence (profile_id, date, percentage) VALUES (?, ?, ?)",
               (profile_id, today_date_str, adherence_percent))
    db.commit()

    return adherence_percent

# --- Routes ---
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        db = get_db()
        user_data = db.execute('SELECT * FROM users WHERE email = ?', (form.email.data,)).fetchone()
        if user_data and check_password_hash(user_data['password_hash'], form.password.data):
            user = User(id=user_data['id'], email=user_data['email'], full_name=user_data['full_name'])
            login_user(user)
            
            primary_profile = db.execute("SELECT id FROM profiles WHERE manager_user_id = ? AND is_manager = 1", (user.id,)).fetchone()
            if primary_profile:
                session['active_profile_id'] = primary_profile['id']
            
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    session.pop('active_profile_id', None)
    logout_user()
    return redirect(url_for('index'))

@app.route('/profiles')
@login_required
def profiles():
    return render_template('profiles.html')

@app.route('/switch_profile/<int:profile_id>')
@login_required
def switch_profile(profile_id):
    db = get_db()
    profile = db.execute("SELECT id, profile_name FROM profiles WHERE id = ? AND manager_user_id = ?", (profile_id, current_user.id)).fetchone()
    if profile:
        session['active_profile_id'] = profile_id
        flash(f"Switched to {profile['profile_name']}'s profile.", 'info')
    return redirect(url_for('dashboard'))

@app.route('/medicines')
@login_required
def medicines():
    profile_id = session.get('active_profile_id')
    if not profile_id: return redirect(url_for('profiles'))
    return render_template('medicines.html', medicines=get_db().execute('SELECT * FROM medicines WHERE profile_id = ?', (profile_id,)).fetchall())
    
@app.route('/add_medicine', methods=['GET', 'POST'])
@login_required
def add_medicine():
    profile_id = session.get('active_profile_id')
    if not profile_id: return redirect(url_for('profiles'))
    form = MedicineForm()
    if form.validate_on_submit():
        db = get_db()
        db.execute('INSERT INTO medicines (profile_id, name, current_stock, meal_timing, meal_type, reason) VALUES (?, ?, ?, ?, ?, ?)', (profile_id, form.name.data, form.current_stock.data, form.meal_timing.data, form.meal_type.data, form.reason.data))
        db.commit()
        log_activity('add_medicine', f"Added medicine: {form.name.data}")
        flash(f"{form.name.data} was successfully added.", 'success')
        return redirect(url_for('medicines'))
    return render_template('add_medicine.html', form=form)

@app.route('/reminders', methods=['GET', 'POST'])
@login_required
def reminders():
    profile_id = session.get('active_profile_id')
    if not profile_id: return redirect(url_for('profiles'))
    form = ReminderForm()
    db = get_db()
    medicines = db.execute('SELECT id, name, meal_timing, meal_type FROM medicines WHERE profile_id = ?', (profile_id,)).fetchall()
    form.medicine_id.choices = [('', 'Select a medicine...')] + [(m['id'], m['name']) for m in medicines]
    medicines_data = {m['id']: {'timing': m['meal_timing'], 'meal': m['meal_type']} for m in medicines}
    if form.validate_on_submit():
        days_str = ",".join(form.days.data)
        medicine_id = int(form.medicine_id.data)
        db.execute('INSERT INTO reminders (profile_id, medicine_id, time, days, note) VALUES (?, ?, ?, ?, ?)', (profile_id, medicine_id, form.time.data.strftime('%H:%M'), days_str, form.note.data))
        db.commit()
        medicine_name = dict(form.medicine_id.choices).get(medicine_id)
        log_activity('set_reminder', f"Set reminder for {medicine_name}")
        flash('Reminder set successfully!', 'success')
        return redirect(url_for('reminders'))
    medicine_reminders = db.execute('SELECT r.id, m.name, r.time, r.days, r.note FROM reminders r JOIN medicines m ON r.medicine_id = m.id WHERE r.profile_id = ? ORDER BY r.time', (profile_id,)).fetchall()
    appointment_reminders = db.execute("SELECT id, doctor_name, hospital, date_time, reminder_minutes_before FROM appointments WHERE profile_id = ? AND date_time > ? ORDER BY date_time ASC", (profile_id, datetime.now())).fetchall()
    return render_template('reminders.html', form=form, medicine_reminders=medicine_reminders, appointment_reminders=appointment_reminders, medicines_data=json.dumps(medicines_data))

@app.route('/appointments', methods=['GET', 'POST'])
@login_required
def appointments():
    profile_id = session.get('active_profile_id')
    if not profile_id: return redirect(url_for('profiles'))
    form = AppointmentForm()
    db = get_db()
    if form.validate_on_submit():
        try:
            dt_obj = datetime.strptime(form.date_time.data, '%d-%m-%Y %H:%M')
            db.execute('INSERT INTO appointments (profile_id, doctor_name, hospital, date_time, purpose, reminder_minutes_before) VALUES (?, ?, ?, ?, ?, ?)', (profile_id, form.doctor_name.data, form.hospital.data, dt_obj, form.purpose.data, form.reminder_minutes_before.data))
            db.commit()
            flash('Appointment scheduled.', 'success')
            return redirect(url_for('appointments'))
        except ValueError:
            flash('Invalid date/time format. Please use DD-MM-YYYY HH:MM.', 'danger')
    all_appointments = db.execute('SELECT * FROM appointments WHERE profile_id = ? ORDER BY date_time DESC', (profile_id,)).fetchall()
    return render_template('appointments.html', form=form, appointments=all_appointments)

@app.route('/stats')
@login_required
def stats():
    profile_id = session.get('active_profile_id')
    if not profile_id: return redirect(url_for('profiles'))
    db = get_db()
    adherence_data = db.execute("SELECT date, percentage FROM adherence WHERE profile_id = ? ORDER BY date DESC LIMIT 7", (profile_id,)).fetchall()
    today_name = datetime.now().strftime('%a')
    current_time = datetime.now().strftime('%H:%M')
    missed_doses = db.execute("SELECT m.name, r.time FROM reminders r JOIN medicines m ON r.medicine_id = m.id LEFT JOIN medicine_intake i ON r.medicine_id = i.medicine_id AND DATE(i.taken_at) = DATE('now', 'localtime') WHERE r.profile_id = ? AND r.days LIKE ? AND r.time < ? AND i.id IS NULL", (profile_id, f'%{today_name}%', current_time)).fetchall()
    intake_log = db.execute("SELECT m.name, i.taken_at FROM medicine_intake i JOIN medicines m ON i.medicine_id = m.id WHERE i.profile_id = ? AND DATE(i.taken_at) = DATE('now', 'localtime') ORDER BY i.taken_at", (profile_id,)).fetchall()
    return render_template('stats.html', adherence_data=adherence_data, missed_doses=missed_doses, intake_log=intake_log)

@app.route('/emergency', methods=['GET', 'POST'])
@login_required
def emergency():
    profile_id = session.get('active_profile_id')
    if not profile_id: return redirect(url_for('profiles'))
    form = EmergencyContactForm()
    db = get_db()
    if form.validate_on_submit():
        db.execute('INSERT INTO emergency_contacts (profile_id, name, relationship, phone) VALUES (?, ?, ?, ?)', (profile_id, form.name.data, form.relationship.data, form.phone.data))
        db.commit()
        flash('Emergency contact added.', 'success')
        return redirect(url_for('emergency'))
    contacts = db.execute('SELECT * FROM emergency_contacts WHERE profile_id = ?', (profile_id,)).fetchall()
    return render_template('emergency.html', form=form, contacts=contacts)

@app.route('/history', methods=['GET', 'POST'])
@login_required
def history():
    profile_id = session.get('active_profile_id')
    if not profile_id: return redirect(url_for('profiles'))
    form = HistoryForm()
    db = get_db()
    if form.validate_on_submit():
        user_upload_folder = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], str(profile_id))
        os.makedirs(user_upload_folder, exist_ok=True)
        filename = None
        if form.report_file.data and allowed_file(form.report_file.data.filename):
            filename = secure_filename(form.report_file.data.filename)
            form.report_file.data.save(os.path.join(user_upload_folder, filename))
        db.execute('INSERT INTO medical_history (profile_id, `condition`, description, report_file) VALUES (?, ?, ?, ?)', (profile_id, form.condition.data, form.description.data, filename))
        db.commit()
        flash('Medical history record added.', 'success')
        return redirect(url_for('history'))
    history_records = db.execute('SELECT * FROM medical_history WHERE profile_id = ? ORDER BY created_at DESC', (profile_id,)).fetchall()
    return render_template('history.html', form=form, records=history_records)

# REPLACE the /register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        db = get_db()
        if db.execute('SELECT id FROM users WHERE email = ?', (form.email.data,)).fetchone():
            flash('Email address already exists.', 'danger')
            return render_template('register.html', form=form)
        
        hashed_password = generate_password_hash(form.password.data)
        cursor = db.execute('INSERT INTO users (full_name, email, password_hash) VALUES (?, ?, ?)',
                            (form.full_name.data, form.email.data, hashed_password))
        new_user_id = cursor.lastrowid
        
        dob_obj = None
        if form.date_of_birth.data:
            try:
                dob_obj = datetime.strptime(form.date_of_birth.data, '%d-%m-%Y').date()
            except ValueError:
                flash('Invalid date format for Date of Birth. Please use DD-MM-YYYY.', 'danger')
                return render_template('register.html', form=form)

        db.execute('INSERT INTO profiles (manager_user_id, profile_name, is_manager, gender, date_of_birth) VALUES (?, ?, ?, ?, ?)',
                   (new_user_id, form.full_name.data, 1, form.gender.data, dob_obj))
        db.commit()
        
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# REPLACE the /add_profile route
@app.route('/add_profile', methods=['GET', 'POST'])
@login_required
def add_profile():
    form = ProfileForm()
    if form.validate_on_submit():
        db = get_db()
        dob_obj = None
        if form.date_of_birth.data:
            try:
                dob_obj = datetime.strptime(form.date_of_birth.data, '%d-%m-%Y').date()
            except ValueError:
                flash('Invalid date format. Please use DD-MM-YYYY.', 'danger')
                return render_template('add_profile.html', form=form, title="Add New Dependent Profile")
        
        db.execute('INSERT INTO profiles (manager_user_id, profile_name, date_of_birth, gender) VALUES (?, ?, ?, ?)',
                   (current_user.id, form.profile_name.data, dob_obj, form.gender.data))
        db.commit()
        flash(f'Profile for {form.profile_name.data} created.', 'success')
        return redirect(url_for('profiles'))
    return render_template('add_profile.html', form=form, title="Add New Dependent Profile")

# REPLACE the /profile route
@app.route('/profile')
@login_required
def profile():
    # This route now correctly finds the manager's main profile and redirects to its edit page
    manager_profile = get_db().execute("SELECT id FROM profiles WHERE manager_user_id = ? AND is_manager = 1", (current_user.id,)).fetchone()
    if manager_profile:
        return redirect(url_for('manage_profile', profile_id=manager_profile['id']))
    else:
        # Fallback in case the main profile is missing for some reason
        flash("Main profile not found.", "danger")
        return redirect(url_for('profiles'))

# REPLACE the existing manage_profile function in app.py
@app.route('/manage_profile/<int:profile_id>', methods=['GET', 'POST'])
@login_required
def manage_profile(profile_id):
    db = get_db()
    profile_data = db.execute("SELECT * FROM profiles WHERE id = ? AND manager_user_id = ?", (profile_id, current_user.id)).fetchone()
    if not profile_data:
        flash("Profile not found or access denied.", "danger")
        return redirect(url_for('profiles'))
    
    form = ProfileForm(obj=profile_data)
    password_form = ChangePasswordForm()

    if request.method == 'GET':
        form.profile_name.data = profile_data['profile_name']
        if profile_data['date_of_birth']:
            form.date_of_birth.data = profile_data['date_of_birth'].strftime('%d-%m-%Y')
        form.gender.data = profile_data['gender']

    if form.validate_on_submit() and 'submit_profile' in request.form:
        dob_obj = None
        if form.date_of_birth.data:
            try:
                dob_obj = datetime.strptime(form.date_of_birth.data, '%d-%m-%Y').date()
            except (ValueError, TypeError):
                flash('Invalid date format. Please use DD-MM-YYYY.', 'danger')
                return render_template('manage_profile.html', form=form, password_form=password_form, profile=profile_data)

        user_upload_folder = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], str(profile_id))
        os.makedirs(user_upload_folder, exist_ok=True)
        filename = profile_data['profile_picture']
        if form.profile_picture.data and allowed_file(form.profile_picture.data.filename):
            filename = secure_filename(form.profile_picture.data.filename)
            form.profile_picture.data.save(os.path.join(user_upload_folder, filename))
        
        db.execute('UPDATE profiles SET profile_name = ?, date_of_birth = ?, gender = ?, profile_picture = ? WHERE id = ?',
                   (form.profile_name.data, dob_obj, form.gender.data, filename, profile_id))
        
        if profile_data['is_manager']:
            db.execute('UPDATE users SET full_name = ? WHERE id = ?', (form.profile_name.data, current_user.id))

        db.commit()
        log_activity('profile_update', f"Updated profile for {form.profile_name.data}")
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('manage_profile', profile_id=profile_id))

    if password_form.validate_on_submit() and 'submit_password' in request.form:
        user_data = db.execute('SELECT password_hash FROM users WHERE id = ?', (current_user.id,)).fetchone()
        if check_password_hash(user_data['password_hash'], password_form.current_password.data):
            new_hashed_password = generate_password_hash(password_form.new_password.data)
            db.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_hashed_password, current_user.id))
            db.commit()
            log_activity('password_change', "Changed account password")
            flash('Your password has been changed!', 'success')
            return redirect(url_for('manage_profile', profile_id=profile_id))
        else:
            flash('Incorrect current password.', 'danger')

    return render_template('manage_profile.html', form=form, password_form=password_form, profile=profile_data)

# REPLACE your existing uploaded_file function with this
@app.route('/uploads/<int:profile_id>/<filename>')
@login_required
def uploaded_file(profile_id, filename):
    # Security check: ensure the current user manages the profile they're requesting a file for
    profile = get_db().execute("SELECT id FROM profiles WHERE id = ? AND manager_user_id = ?", (profile_id, current_user.id)).fetchone()
    if not profile:
        return "Access Denied", 403
    
    # Correctly build the path to the specific profile's upload folder
    user_upload_folder = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], str(profile_id))
    return send_from_directory(user_upload_folder, filename)

# REPLACE your existing /dashboard function
@app.route('/dashboard')
@login_required
def dashboard():
    profile_id = session.get('active_profile_id')
    if not profile_id:
        return redirect(url_for('profiles'))

    db = get_db()
    today_name = datetime.now().strftime('%a')
    current_time = datetime.now()
    
    # NEW: Find reminders due within a +/- 15 minute window of now
    due_now_reminders = []
    all_today_reminders = db.execute("""
        SELECT r.time, m.name, m.id as medicine_id FROM reminders r
        JOIN medicines m ON r.medicine_id = m.id
        WHERE r.profile_id = ? AND r.days LIKE ?
        AND m.id NOT IN (SELECT medicine_id FROM medicine_intake WHERE profile_id = ? AND DATE(taken_at) = DATE('now', 'localtime'))
    """, (profile_id, f'%{today_name}%', profile_id)).fetchall()

    for rem in all_today_reminders:
        reminder_time = datetime.strptime(rem['time'], '%H:%M').time()
        reminder_datetime = datetime.combine(current_time.date(), reminder_time)
        time_diff = abs(current_time - reminder_datetime)
        if time_diff <= timedelta(minutes=15):
            due_now_reminders.append(rem)

    upcoming_reminders = db.execute("SELECT r.time, m.name, m.id as medicine_id FROM reminders r JOIN medicines m ON r.medicine_id = m.id WHERE r.profile_id = ? AND r.time > ? AND r.days LIKE ? AND m.id NOT IN (SELECT medicine_id FROM medicine_intake WHERE profile_id = ? AND DATE(taken_at) = DATE('now', 'localtime')) ORDER BY r.time ASC LIMIT 5", (profile_id, current_time.strftime('%H:%M'), f'%{today_name}%', profile_id)).fetchall()
    low_stock_count = db.execute('SELECT COUNT(id) FROM medicines WHERE profile_id = ? AND current_stock <= 6', (profile_id,)).fetchone()[0]
    meds_taken_today = db.execute("SELECT COUNT(id) FROM medicine_intake WHERE profile_id = ? AND DATE(taken_at) = DATE('now', 'localtime')", (profile_id,)).fetchone()[0]
    health_records_count = db.execute("SELECT COUNT(id) FROM medical_history WHERE profile_id = ?", (profile_id,)).fetchone()[0]
    emergency_contacts_count = db.execute("SELECT COUNT(id) FROM emergency_contacts WHERE profile_id = ?", (profile_id,)).fetchone()[0]
    activities = db.execute('SELECT description, timestamp FROM recent_activities WHERE profile_id = ? ORDER BY timestamp DESC LIMIT 5', (profile_id,)).fetchall()
    adherence = calculate_and_save_adherence(profile_id)

        # ADD THESE LINES to app.py inside the dashboard function
    upcoming_appointments = db.execute(
        "SELECT * FROM appointments WHERE profile_id = ? AND date_time > ? ORDER BY date_time ASC",
        (profile_id, datetime.now())
    ).fetchall()
    
    # UPDATE the return statement in the dashboard function to include the new variable
    return render_template('dashboard.html', 
                        adherence=adherence,
                        upcoming_reminders=upcoming_reminders,
                        due_now_reminders=due_now_reminders,
                        upcoming_appointments=upcoming_appointments, # <-- ADD THIS LINE
                        low_stock_count=low_stock_count,
                        meds_taken_today=meds_taken_today,
                        health_records_count=health_records_count,
                        emergency_contacts_count=emergency_contacts_count,
                        activities=activities)
":?"
@app.route('/medicine/take/<int:med_id>', methods=['POST'])
@login_required
def take_medicine(med_id):
    profile_id = session.get('active_profile_id')
    if not profile_id: return redirect(url_for('profiles'))
    db = get_db()
    med = db.execute('SELECT name, current_stock FROM medicines WHERE id = ? AND profile_id = ?', (med_id, profile_id)).fetchone()
    if med:
        db.execute('INSERT INTO medicine_intake (profile_id, medicine_id) VALUES (?, ?)', (profile_id, med_id))
        if med['current_stock'] > 0:
            new_stock = med['current_stock'] - 1
            db.execute('UPDATE medicines SET current_stock = ? WHERE id = ?', (new_stock, med_id))
            db.execute('INSERT INTO stock_updates (profile_id, medicine_id, change) VALUES (?, ?, ?)', (profile_id, med_id, -1))
        db.commit()
        calculate_and_save_adherence(profile_id)
        log_activity('medicine_take', f"Logged intake for {med['name']}")
        flash(f"Logged intake for {med['name']}.", 'success')
    return redirect(request.referrer or url_for('dashboard'))


@app.route('/medicine/add_stock/<int:med_id>', methods=['POST'])
@login_required
def add_stock(med_id):
    profile_id = session.get('active_profile_id')
    if not profile_id: return redirect(url_for('profiles'))
    db = get_db()
    med = db.execute('SELECT name, current_stock FROM medicines WHERE id = ? AND profile_id = ?', (med_id, profile_id)).fetchone()
    try:
        quantity = int(request.form.get('quantity', 0))
    except (ValueError, TypeError):
        quantity = 0
    if med and quantity > 0:
        new_stock = med['current_stock'] + quantity
        db.execute('UPDATE medicines SET current_stock = ? WHERE id = ?', (new_stock, med_id))
        db.execute('INSERT INTO stock_updates (profile_id, medicine_id, change) VALUES (?, ?, ?)', (profile_id, med_id, quantity))
        db.commit()
        flash(f"Added {quantity} to {med['name']}'s stock.", 'success')
    else:
        flash('Please enter a valid quantity.', 'warning')
    return redirect(url_for('medicines'))

@app.route('/medicine/delete/<int:med_id>', methods=['POST'])
@login_required
def delete_medicine(med_id):
    profile_id = session.get('active_profile_id')
    if not profile_id: return redirect(url_for('profiles'))
    db = get_db()
    db.execute('DELETE FROM medicines WHERE id = ? AND profile_id = ?', (med_id, profile_id))
    db.commit()
    flash('Medicine deleted.', 'success')
    return redirect(url_for('medicines'))

@app.route('/delete_reminder/<int:rem_id>', methods=['POST'])
@login_required
def delete_reminder(rem_id):
    profile_id = session.get('active_profile_id')
    if not profile_id: return redirect(url_for('profiles'))
    db = get_db()
    db.execute('DELETE FROM reminders WHERE id = ? AND profile_id = ?', (rem_id, profile_id))
    db.commit()
    flash('Reminder deleted.', 'info')
    return redirect(url_for('reminders'))

@app.route('/history/delete/<int:rec_id>', methods=['POST'])
@login_required
def delete_history(rec_id):
    profile_id = session.get('active_profile_id')
    if not profile_id: return redirect(url_for('profiles'))
    db = get_db()
    rec = db.execute('SELECT report_file FROM medical_history WHERE id = ? AND profile_id = ?', (rec_id, profile_id)).fetchone()
    if rec and rec['report_file']:
        file_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], str(profile_id), rec['report_file'])
        if os.path.exists(file_path): os.remove(file_path)
    db.execute('DELETE FROM medical_history WHERE id = ? AND profile_id = ?', (rec_id, profile_id))
    db.commit()
    flash('History record deleted.', 'success')
    return redirect(url_for('history'))

@app.route('/delete_appointment/<int:apt_id>', methods=['POST'])
@login_required
def delete_appointment(apt_id):
    profile_id = session.get('active_profile_id')
    if not profile_id: return redirect(url_for('profiles'))
    db = get_db()
    db.execute('DELETE FROM appointments WHERE id = ? AND profile_id = ?', (apt_id, profile_id))
    db.commit()
    flash('Appointment deleted.', 'info')
    return redirect(url_for('appointments'))

@app.route('/emergency/delete/<int:cid>', methods=['POST'])
@login_required
def delete_emergency(cid):
    profile_id = session.get('active_profile_id')
    if not profile_id: return redirect(url_for('profiles'))
    db = get_db()
    db.execute('DELETE FROM emergency_contacts WHERE id = ? AND profile_id = ?', (cid, profile_id))
    db.commit()
    flash('Emergency contact deleted.', 'info')
    return redirect(url_for('emergency'))

@app.route('/generate_qr')
@login_required
def generate_qr():
    profile_id = session.get('active_profile_id')
    if not profile_id: return redirect(url_for('profiles'))
    db = get_db()
    token = secrets.token_urlsafe(16)
    expires_at = datetime.now() + timedelta(minutes=15)
    db.execute("INSERT INTO share_tokens (profile_id, token, expires_at) VALUES (?, ?, ?)",
               (profile_id, token, expires_at))
    db.commit()
    share_url = url_for('share_page', token=token, _external=True)
    img = qrcode.make(share_url)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_image_data = base64.b64encode(buf.getvalue()).decode('utf-8')
    log_activity('generate_qr', 'Generated a shareable QR code')
    return render_template('display_qr.html', qr_image_data=qr_image_data)

# REPLACE your existing share_page function with this
@app.route('/share/<token>')
def share_page(token):
    db = get_db()
    token_data = db.execute("SELECT * FROM share_tokens WHERE token = ? AND expires_at > ?", (token, datetime.now())).fetchone()
    if not token_data:
        return "<h2>Invalid or Expired Link</h2>", 404
    
    profile_id = token_data['profile_id']
    # This query now includes the profile picture
    profile = db.execute("SELECT profile_name, date_of_birth, gender, profile_picture FROM profiles WHERE id = ?", (profile_id,)).fetchone()
    
    if not profile:
        return "<h2>Profile not found.</h2>", 404

    # Calculate age from date of birth
    age = None
    if profile['date_of_birth']:
        today = datetime.now().date()
        born = profile['date_of_birth']
        age = today.year - born.year - ((today.month, today.day) < (born.month, born.day))

    history = db.execute("SELECT `condition`, description, created_at, report_file FROM medical_history WHERE profile_id = ? ORDER BY created_at DESC", (profile_id,)).fetchall()
    contacts = db.execute("SELECT name, relationship, phone FROM emergency_contacts WHERE profile_id = ?", (profile_id,)).fetchall()
    
    return render_template('share_page.html', profile=profile, age=age, history=history, contacts=contacts, token=token)

@app.route('/shared_file/<token>/<filename>')
def serve_shared_file(token, filename):
    db = get_db()
    token_data = db.execute("SELECT profile_id FROM share_tokens WHERE token = ? AND expires_at > ?", (token, datetime.now())).fetchone()
    if not token_data:
        return "Unauthorized or expired link.", 401
    profile_id = token_data['profile_id']
    user_upload_folder = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], str(profile_id))
    return send_from_directory(user_upload_folder, filename)

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    db = get_db()
    # Deletes the main user account and all associated profiles via CASCADE
    db.execute('DELETE FROM users WHERE id = ?', (current_user.id,))
    db.commit()
    flash('Your account and all associated data have been permanently deleted.', 'success')
    return redirect(url_for('index'))

# ADD this missing function to app.py
@app.route('/export_data')
@login_required
def export_data():

    db = get_db()
    
    # We export data for ALL profiles managed by the current user
    profiles_data = db.execute("SELECT * FROM profiles WHERE manager_user_id = ?", (current_user.id,)).fetchall()
    
    full_export = {}
    
    for profile in profiles_data:
        profile_id = profile['id']
        profile_name = profile['profile_name']
        
        medicines = db.execute('SELECT * FROM medicines WHERE profile_id = ?', (profile_id,)).fetchall()
        reminders = db.execute('SELECT * FROM reminders WHERE profile_id = ?', (profile_id,)).fetchall()
        history = db.execute('SELECT * FROM medical_history WHERE profile_id = ?', (profile_id,)).fetchall()
        appointments = db.execute('SELECT * FROM appointments WHERE profile_id = ?', (profile_id,)).fetchall()
        contacts = db.execute('SELECT * FROM emergency_contacts WHERE profile_id = ?', (profile_id,)).fetchall()
        
        full_export[profile_name] = {
            'profile_details': dict(profile),
            'medicines': [dict(m) for m in medicines],
            'reminders': [dict(r) for r in reminders],
            'medical_history': [dict(h) for h in history],
            'appointments': [dict(a) for a in appointments],
            'emergency_contacts': [dict(c) for c in contacts]
        }
        # Clean up data by removing IDs that are not useful in export
        full_export[profile_name]['profile_details'].pop('id', None)
        full_export[profile_name]['profile_details'].pop('manager_user_id', None)

    return Response(
        json.dumps(full_export, indent=4, default=str),
        mimetype='application/json',
        headers={'Content-Disposition': 'attachment;filename=health_data_export.json'}
    )

# ADD this new route to app.py
@app.route('/delete_profile/<int:profile_id>', methods=['POST'])
@login_required
def delete_profile(profile_id):
    db = get_db()
    
    # Security check: find the profile to make sure it belongs to the current user
    profile = db.execute("SELECT * FROM profiles WHERE id = ? AND manager_user_id = ?", 
                         (profile_id, current_user.id)).fetchone()
    
    if not profile:
        flash("Profile not found or access denied.", "danger")
        return redirect(url_for('profiles'))
    
    # Security check: PREVENT the user from deleting their own main profile
    if profile['is_manager']:
        flash("You cannot delete your own primary profile.", "danger")
        return redirect(url_for('profiles'))
    
    # If checks pass, delete the profile
    db.execute("DELETE FROM profiles WHERE id = ?", (profile_id,))
    db.commit()
    
    flash(f"Profile '{profile['profile_name']}' has been deleted.", "success")
    return redirect(url_for('profiles'))

# ADD this new route to app.py
@app.route('/my_account')
@login_required
def my_account():
    # This route automatically finds the manager's profile and redirects
    manager_profile = get_db().execute("SELECT id FROM profiles WHERE manager_user_id = ? AND is_manager = 1", (current_user.id,)).fetchone()
    if manager_profile:
        return redirect(url_for('manage_profile', profile_id=manager_profile['id']))
    else:
        # Fallback in case the main profile is missing for some reason
        flash("Main account profile not found.", "danger")
        return redirect(url_for('profiles'))
    
# ADD this new route to app.py
@app.route('/intake_log')
@login_required
def intake_log():
    profile_id = session.get('active_profile_id')
    if not profile_id:
        flash("Please select a profile first.", "warning")
        return redirect(url_for('profiles'))

    db = get_db()
    
    log_entries = db.execute("""
        SELECT m.name, i.taken_at 
        FROM medicine_intake i JOIN medicines m ON i.medicine_id = m.id 
        WHERE i.profile_id = ? 
        ORDER BY i.taken_at DESC
    """, (profile_id,)).fetchall()
    return render_template('intake_log.html', log_entries=log_entries)


if __name__ == '__main__':
    app.run(debug=True)
    
