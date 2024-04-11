import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import pytest
from app import app, db
from app.forms import RegistrationForm, LoginForm
from app.models import User, Scan, CVE
from app.utils import common_ports
import tempfile 

# Import the TestConfig class from test_config.py
from test_config import TestConfig

# Use the TestConfig class for testing configuration
app.config.from_object(TestConfig)
import pytest
from app import app, db
from app.models import User

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    client = app.test_client()

   with app.app_context():
       db.create_all()

    yield client

    with app.app_context():
       db.drop_all()

def test_register(client):
    response = client.post('/register', data={
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'password',
        'confirm_password': 'password'
    }, follow_redirects=True)
    
    #print(response.data)
    assert b'Your account has been created! You can now log in.' in response.data
    assert b'Your account has been created! You can now log in.' in response.data

    # Check if the user is added to the database
    with app.app_context():
        user = User.query.filter_by(username='testuser').first()
        assert user is not None
        assert user.email == 'test@example.com'

def test_login(client):
    # First, register a test user
    client.post('/register', data={
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'password',
        'confirm_password': 'password'
    }, follow_redirects=True)

    # Now, attempt to log in with the registered user
    response = client.post('/login', data={
        'username': 'testuser',
        'password': 'password'
    }, follow_redirects=True)
    #print(response.data)
    assert b'Login successful' in response.data
    

def test_login2(client):
    # First, register a test user
    client.post('/register', data={
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'password',
        'confirm_password': 'password'
    }, follow_redirects=True)

    # Now, attempt to log in with the registered user
    response = client.post('/login', data={
        'username': 'testuser',
        'password': 'password'
    }, follow_redirects=True)
    #print(response.data)
    assert b'Login successful' in response.data
    



from unittest.mock import patch, MagicMock

import requests

@patch('requests.post')
def test_cve_info(mock_post, client):
    # Mock Shodan API response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "hostnames": ["example.com"],
        "ip_str": "192.168.1.1",
        "vulns": ["CVE-2022-1234", "CVE-2022-5678"]
    }
    mock_post.return_value = mock_response

    # Make a POST request to the /cve_info endpoint
    response = client.post('/cve_info', data={"ip_address": "192.168.1.1"})

   # Assert that the response status code is 200
    assert response.status_code == 200

    # Assert that the response contains the expected CVE information
    assert b"CVE-2022-1234" in response.data
    assert b"CVE-2022-5678" in response.data

@patch('requests.post')
def test_cve_info_error(mock_post, client):
    # Mock Shodan API response
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.json.return_value = {"error": "Shodan API error message"}
    mock_post.return_value = mock_response

    # Make a POST request to the /cve_info endpoint
    response = client.post('/cve_info', data={"ip_address": "192.168.1.1"})

    # Assert that the response status code is 500 due to Shodan API error
    assert response.status_code == 500
    # Assert that the error message is returned in the response
    assert b"Shodan API error message" in response.data

def test_cve_circl_api():
    # Mock the requests.get method
    with patch('requests.get') as mock_get:
        # Define the mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        # Define the sample data you expect to receive
        mock_response.json.return_value = {
            "CVE": "CVE-2022-1234",
            "Description": "XSS in livehelperchat in GitHub repository livehelperchat/livehelperchat prior to 3.97. This vulnerability has the potential to deface websites, result in compromised user accounts, and can run malicious code on web pages, which can lead to a compromise of the user’s device.",
            "CVSS": "7.1",
            "References": ["https://huntr.dev/bounties/0d235252-0882-4053-85c1-b41b94c814d4"]
        }
        # Set the mock response for the requests.get method
        mock_get.return_value = mock_response

        # Define the CVE ID to be used in the API call
        cve_id = "CVE-2022-1234"

        # Make the API call
        response = requests.get(f'https://cve.circl.lu/api/cve/{cve_id}')

        # Assert that the requests.get method is called with the correct URL
        mock_get.assert_called_once_with(f'https://cve.circl.lu/api/cve/{cve_id}')

        # Assert that the response status code is 200
        assert response.status_code == 200

        # Assert that the response data matches the expected data
        expected_data = {
            "CVE": "CVE-2022-1234",
            "Description": "XSS in livehelperchat in GitHub repository livehelperchat/livehelperchat prior to 3.97. This vulnerability has the potential to deface websites, result in compromised user accounts, and can run malicious code on web pages, which can lead to a compromise of the user’s device.",
            "CVSS": "7.1",
            "References": ["https://huntr.dev/bounties/0d235252-0882-4053-85c1-b41b94c814d4"]
        }
        assert response.json() == expected_data