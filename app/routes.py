from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_login import login_user, LoginManager, current_user, logout_user, login_required
from app import app, db
from app.forms import RegistrationForm, LoginForm
from app.models import User, Scan, CVE
from app.utils import common_ports
from werkzeug.security import generate_password_hash, check_password_hash
import json
import shodan
import requests
import time
import joblib
import pandas as pd
import os
import socket
from datetime import datetime

################################################### API KEYS 
SHODAN_API_KEY = 'LDAxkgwomLK17x6VFVGUhiNZ6ZlWUktz'
NVD_API_KEY= '2a5467cd-1a42-451f-ab2f-dd356ecb7f7c'
###################################################


####################################### FILE PATHS
# Path to the final_model_CVE.joblib file

MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models')

MODEL_PATH = os.path.join(MODELS_DIR, 'final_model_CVE.joblib')
#MODEL_PATH = 'final_model_CVE.joblib'



DATASETDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'datasets')

DATASET_PATH = os.path.join(DATASETDIR, 'output_cve_2020.csv')
###################################### 


###################################### LOADING MODEL AND CSV DATA 
final_model = joblib.load(MODEL_PATH)
csv_data = pd.read_csv(DATASET_PATH)
######################################

#from app.utils import clean_data_for_serialization, generate_firewall_rules, generate_firewall_rule, fill_data_for_cve, get_cve_info_list


def generate_firewall_rules(open_ports, action, filter_ip, os_type):
    firewall_rules = []

    for port in open_ports:
        firewall_rule = generate_firewall_rule(port, action, filter_ip, os_type)
        firewall_rules.append(firewall_rule)

    return firewall_rules
def generate_firewall_rule(port, action, filter_ip, os_type):
    if os_type.lower() == 'linux':
        if action.lower() == 'allow':
            return f"iptables -A INPUT -p tcp --dport {port} -j ACCEPT"
        elif action.lower() == 'block':
            return f"iptables -A INPUT -p tcp --dport {port} -j DROP"
        elif action.lower() == 'filter' and filter_ip:
            return f"iptables -A INPUT -p tcp --dport {port} -s {filter_ip} -j ACCEPT && iptables -A INPUT -p tcp --dport {port} -j DROP"
        else:
            return 'Unsupported action'
    elif os_type.lower() == 'windows':
        if action.lower() == 'allow':
            return f"netsh advfirewall firewall add rule name='Allow Port {port}' dir=in action=allow protocol=TCP localport={port}"
        elif action.lower() == 'block':
            return f"netsh advfirewall firewall add rule name='Block Port {port}' dir=in action=block protocol=TCP localport={port}"
        elif action.lower() == 'filter' and filter_ip:
            return f"netsh advfirewall firewall add rule name='Filter Port {port}' dir=in action=allow protocol=TCP localport={port} remoteip={filter_ip}"
        else:
            return 'Unsupported action'
    elif os_type.lower() == 'osx':
        if action.lower() == 'allow':
            return f"pass in proto tcp from any to any port {port}"
        elif action.lower() == 'block':
            return f"block in proto tcp from any to any port {port}"
        elif action.lower() == 'filter' and filter_ip:
            return f"pass in proto tcp from {filter_ip} to any port {port}"
        else:
            return 'Unsupported action'
    else:
        return 'Unsupported operating system'


def fill_data_for_cve(cve_id, year):
    base_dir = "/Users/isaac/uni/Year 4/FYP- Final year Project /FYP-projectFile/project-managed/app/datasets/"
    csv_file_path = os.path.join(base_dir, f'output_cve_{year}.csv')
    #print("CSV File Path:", csv_file_path)  # Check file path
    if os.path.exists(csv_file_path):
        #print("File path correct")
        csv_data = pd.read_csv(csv_file_path)
        
        csv_row = None  # Initialize csv_row to None
        if cve_id in csv_data['ID'].values:
            csv_row = csv_data[csv_data['ID'] == cve_id].iloc[0]
        else:
            print(f"Error: CVE {cve_id} not found in the dataset")
            return pd.DataFrame()  # Return empty DataFrame if CVE is not found

        if csv_row is not None:  # Check if csv_row is not None before using it
            new_data = pd.DataFrame({
                'ID': [cve_id],
                'Version': [csv_row['Version']],
                'AccessVector': [csv_row['AccessVector']],
                'AccessComplexity': [csv_row['AccessComplexity']],
                'Authentication': [csv_row['Authentication']],
                'ConfidentialityImpact': [csv_row['ConfidentialityImpact']],
                'IntegrityImpact': [csv_row['IntegrityImpact']],
                'AvailabilityImpact': [csv_row['AvailabilityImpact']],
                'BaseScore': [csv_row['BaseScore']],
                'Severity': [csv_row['Severity']],
                'ExploitabilityScore': [csv_row['ExploitabilityScore']],
                'ImpactScore': [csv_row['ImpactScore']],
                'ACInsufInfo': [csv_row['ACInsufInfo']],
                'ObtainAllPrivilege': [csv_row['ObtainAllPrivilege']],
                'ObtainUserPrivilege': [csv_row['ObtainUserPrivilege']],
                'ObtainOtherPrivilege': [csv_row['ObtainOtherPrivilege']],
                'UserInteractionRequired': [csv_row['UserInteractionRequired']]
            })
            return new_data
    else:
        print(f"Error: CSV file not found at path {csv_file_path}")
    return pd.DataFrame()



def clean_data_for_serialization(data):
    # Exclude any non-serializable keys from the data
    return {key: value for key, value in data.items() if not callable(value)}

@app.route('/search', methods=['GET', 'POST'])
def search():
    if not current_user.is_authenticated:
        # If user is not authenticated, redirect to login page or handle accordingly
        flash('You need to log in to access this page.', 'danger')
        return redirect(url_for('login'))  
    if request.method == 'POST':
        input_value = request.form.get('input_value')

        try:
            # Check if the input is an IP address
            ip_address = socket.inet_aton(input_value)
        except socket.error:
            try:
                # If it's not a valid IP address, treat it as a hostname
                ip_address = socket.gethostbyname(input_value)
            except socket.gaierror:
                error_message = "Invalid Input. Please enter a valid IP address or hostname"
                return render_template('index.html', error_message=error_message)

        # Convert the IP address to a string
        ip_address = socket.inet_ntoa(ip_address) if isinstance(ip_address, bytes) else ip_address

        api = shodan.Shodan(SHODAN_API_KEY)

        try:
            host_info = api.host(ip_address)
            return render_template('results.html', host_info=host_info, common_ports=common_ports)
        except shodan.APIError as e:
            error_message = f'Error : {e}'
            return render_template('index.html', error_message=error_message)
        except Exception as ex:
            return f'An error occurred: {ex}'
    return render_template('index.html')

# New homepage route
@app.route('/', methods=['GET', 'POST'])
def homepage():
    return render_template('homepage.html')

def get_cve_info_list(host_info):
    cve_info_list = []
    print(host_info)
    if 'vulns' in host_info:
        for cve in host_info['vulns']:
            #print(f"Sleeping NOW before request for CVE {cve}")
            #time.sleep(1)
            response_parse=request.get(f'https://cve.circl.lu/api/cve/{cve}')
            #response = requests.get(f'https://services.nvd.nist.gov/rest/json/cve/1.0/{cve}?api_key={NVD_API_KEY}')
            if response_parse.status_code == 200:
                cve_info_data = fill_data_for_cve(cve)
                cve_info_data['HostInfo'] = clean_data_for_serialization(host_info)
                cve_info_data['NVDData'] = response_parse.json()
                cve_info_list.append(cve_info_data.to_dict())
            else:
                cve_info_list.append({"Error": "Error Retrieving the data from NIST"})
    return cve_info_list
@app.route('/cve_info', methods=['POST'])
def cve_info():
    if not current_user.is_authenticated:
        # If user is not authenticated, redirect to login page or handle accordingly
        return redirect(url_for('login'))  
    ip_address = request.form.get('ip_address')
    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        host_info = api.host(ip_address)
        cve_info_list = []

        # Begin transaction
        print("SAVING INFO TO THE DATABASE")
        if 'hostnames' in host_info:
            hostname = host_info['hostnames'][0]
        else:
            hostname = 'Unknown'  # Provide a default value if 'hostnames' is not present
    
        ip_address = host_info.get('ip_str', 'Unknown')  # Get the IP address from host_info
        timestamp = datetime.utcnow()

        scan = Scan(user_id=current_user.id, ip_address=ip_address, hostname=hostname, timestamp=timestamp)

        if 'vulns' in host_info:
            for cve in host_info['vulns']:
                year = cve.split('-')[1]
                #print(f"Sleeping before request for CVE {cve}")
                # time.sleep(2)  # Consider uncommenting this if necessary
                response = requests.get(f'https://cve.circl.lu/api/cve/{cve}')
                print(response)
                if response.status_code == 200:
                    cve_data = fill_data_for_cve(cve, year)
                    if cve_data.empty:
                        print(f"Skipping CVE {cve}: No data found.")
                        continue
                    vulnerability_score = final_model.predict(cve_data)
                    cve_info = {
                        'CVE': cve,
                        'NVDData': response.json(),
                        'VulnerabilityScore': vulnerability_score[0]
                    }
                    cve_info_list.append(cve_info)
                    #print(f"Processed CVE: {cve}")

                    # Extract summary from NVDData
                    summary = response.json().get('summary', 'Summary not available')

                    # Create CVE instance and associate with scan
                    cve_instance = CVE(cve_id=cve, description=summary, vulnerability_score=vulnerability_score[0])
                    scan.cves.append(cve_instance)
                    # Create CVE instance and associate with scan
                else:
                    print(f"Error retrieving data for CVE {cve}: {response.status_code}")
                    cve_info_list.append({
                        'CVE': cve,
                        'Error': f"Error retrieving data for CVE {cve}: {response.status_code}"
                    })

        db.session.add(scan)
        db.session.commit()
        print("SAVED!")

        return jsonify(cve_info_list)
    except shodan.APIError as e:
        return jsonify(error=str(e))
    except Exception as ex:
        # Rollback transaction in case of error
        db.session.rollback()
        return jsonify(error=str(ex))


api = shodan.Shodan(SHODAN_API_KEY)

    

def get_open_ports(ip_address):
    try:
        result = api.host(ip_address)
        open_ports = [str(port) for port in result['ports']]
        return open_ports
    except shodan.exception.APIError as e:
        return str(e)

@app.route('/generate_rule', methods=['POST'])
def generate_rule():

    try:
        ip_address = request.form.get('ip_address')
        action = request.form.get('action')
        filter_ip = request.form.get('filter_ip')
        os_type = request.form.get('os_type')

        # Check if the IP address is valid before proceeding

        open_ports = get_open_ports(ip_address)

        # Generate firewall rules based on open ports
        firewall_rules = [
            generate_firewall_rule(port, action, filter_ip, os_type)
            for port in open_ports
        ]

        return jsonify(firewall_rules=firewall_rules)

    except Exception as e:
        print(f"Error: {e}")
        return jsonify(error=str(e)), 500  # Return error response with HTTP status code 500

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        # Check if password and confirm password fields match
        if form.password.data != form.confirm_password.data:
            print("NOT MATCHING!")
            flash('Passwords do not match!!!.', 'danger')
            return redirect(url_for('register'))

        # Hash the password
        # Hash the password using werkzeug.security
        hashed_password = generate_password_hash(form.password.data)
        # Create a new User instance with hashed password
        user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password)
        # Check if username or email already exists in the database
        if User.query.filter_by(username=user.username).first():
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(email=user.email).first():
            flash('Email already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        # Add user to the database
        db.session.add(user)
        db.session.commit()

        # Flash success message and redirect to login page
        flash('Your account has been created! You can now log in.', 'success')
        
        return redirect(url_for('login'))
    else:
        # Handle form validation errors
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{field.title()} {error}', 'danger')

    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)  # Log in the user
            flash('Login successful!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html', title='Login', form=form)




@app.route('/logout', methods=['POST'])
def logout():
    logout_user()  # Clear the user's session
    flash('You have been logged out.', 'success')  # Flash a logout message
    return redirect(url_for('login'))  # Redirect to the login page

@app.route('/profile')
def profile():
    if current_user.is_authenticated:
        # User is logged in, you can access their information
        user_id = current_user.id
        username = current_user.username
        email = current_user.email
        # Any other user-related information you need
        return render_template('profile.html', user=current_user)
    else:
        # User is not logged in, handle the case accordingly
        flash('You need to log in to access this page.', 'danger')
        return redirect(url_for('login'))


@app.route('/save_cve_info', methods=['POST'])
def save_cve_info():
    try:
        data = json.loads(request.data) # Parse the JSON string into a dictionary
        cve_info = data.get('cve_info')
        ip_address = data.get('ip_address')

        if cve_info is None:
            return jsonify(error='No CVE information provided')

        scan = Scan.query.filter_by(ip_address=ip_address).first()
        if not scan:
            hostname = "Unknown"
            user_id = current_user.id
            scan = Scan(user_id=user_id, ip_address=ip_address, hostname=hostname, timestamp=datetime.utcnow())
            db.session.add(scan)
            db.session.commit()

        for cve_data in cve_info:
            print(type(cve_data)) # Add this line to check the type of cve_data
            cve_id = cve_data.get('CVE')
            vulnerability_score = cve_data.get('VulnerabilityScore')
            description = cve_data.get('Description')
            cve = CVE(scan_id=scan.id, cve_id=cve_id, vulnerability_score=vulnerability_score, description=description)
            db.session.add(cve)

        db.session.commit()
        return jsonify(success=True)
    except Exception as e:
        db.session.rollback()
        return jsonify(error=str(e))

# Route handler to retrieve user-specific scan information
@app.route('/user_scans')
def user_scans():
    if not current_user.is_authenticated:
        flash('You must be logged in to view this page.', 'error')
        return redirect(url_for('login'))  # Corrected redirect call
    user_scans = Scan.query.filter_by(user_id=current_user.id).all()
    # Render a template to display the user's scans
    return render_template('scans.html', user_scans=user_scans)

@app.route('/scan/<int:scan_id>')
def scan_details(scan_id):
    # Retrieve scan details from the database based on the scan_id
    scan = Scan.query.get(scan_id)
    if scan is None:
        flash('Scan not found', 'error')
        return redirect(url_for('user_scans'))

    # Render template with scan details
    return render_template('scan_details.html', scan=scan)


@app.route('/info')
def info():
    return render_template('info.html')




    


