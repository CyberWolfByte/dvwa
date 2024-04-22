import requests
from bs4 import BeautifulSoup
from enum import Enum
import string
import urllib

# Enum to represent the various security levels available in DVWA.
class SecurityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    IMPOSSIBLE = "impossible"

# Class to manage CSRF tokens for DVWA sessions.
class CSRFManager:

    # Decorator to automatically set CSRF token for requests.
    @staticmethod
    def set_csrf_token(func):
        def wrapper(*args, **kwargs):
            # Retrieve CSRF token and update the session with it.
            token, _ = CSRFManager.get_token(args[0]._session, args[1])
            if token is not None:
                args[0].user_token = token["value"]
            return func(*args, **kwargs)
        return wrapper
    
    # Method to get CSRF token from a given URL.
    @staticmethod
    def get_token(session:requests.Session, url:str):
        response = session.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        csrf_token = soup.find("input", {"name": "user_token"})
        return csrf_token, response.url

# Class to manage session and security level for DVWA.
class DVWASessionProxy:
    login_data = {
        "username": "admin",
        "password": "password",
        "Login": "Login"
    }

    def __init__(self, url):
        self._session = requests.Session()
        self.url = f"{url}/login.php"
        self.data = {}  # Data dictionary to store session-specific data such as CSRF tokens.
    
    # Getter for security level.
    @property
    def security(self):
        return self._session.cookies.get_dict()["security"]
    
    # Setter for security level, allowing to change the security level of DVWA.
    @security.setter
    def security(self, security_level: SecurityLevel):
        self._session.cookies.pop("security", None)  # Remove existing security cookie if any.
        self._session.cookies.set("security", security_level.value)
 
    # Getter for user CSRF token.
    @property
    def user_token(self):
        return self.data["user_token"]
    
    # Setter for CSRF token.
    @user_token.setter
    def user_token(self, value):
        self.data["user_token"] = value

    def __enter__(self):
        # Login to DVWA upon entering the context.
        self.post(self.url, data= {**self.data, **DVWASessionProxy.login_data}) 
        return self
    
    # Generic GET request wrapper.
    def get(self, url ,headers=None, params=None):
        return self._session.get(url, headers=headers, params=params)
    
    # Generic POST request wrapper, automatically includes CSRF token if available.
    @CSRFManager.set_csrf_token
    def post(self, url ,headers=None, data=None):
        return self._session.post(url, headers=headers, data={**self.data, **data})
    
    # Close session upon exiting the context.
    def __exit__(self, exc_type, exc_val, exc_tb):
        self._session.close()

# Class to parse responses from DVWA for SQL injection testing.
class DVWASQLiResponseParser:
    def __init__(self, response):
        self.response = response

    # Method to extract and return an "interesting" value from the response, for validation purposes.
    def get_interesting_value(self):
        soup = BeautifulSoup(self.response.content, 'html.parser')
        interesting_value = soup.find("pre")
        return interesting_value
            
    # Check if a specific string is present in the "interesting" value, indicating success/failure.
    def check_presence(self, target_string):
        return target_string in self.get_interesting_value().text