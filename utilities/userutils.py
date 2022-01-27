import uuid
import time
import re
import bcrypt
import db
from models.response import post_error
import jwt
import secrets
from .app_enums import EnumVals
import config
from datetime import datetime, timedelta
from flask_mail import Mail, Message
from app import mail
from flask import render_template
from config import USR_MONGO_COLLECTION, USR_TOKEN_MONGO_COLLECTION
import logging
log = logging.getLogger('file')

SECRET_KEY          =   secrets.token_bytes()

mail_server         =   config.MAIL_SENDER
mail_ui_link        =   config.BASE_URL
reset_pwd_link      =   config.RESET_PWD_ENDPOINT
token_life          =   config.AUTH_TOKEN_EXPIRY_HRS
verify_mail_expiry  =   config.USER_VERIFY_LINK_EXPIRY
apikey_expiry       =   config.USER_API_KEY_EXPIRY  
role_codes          =   []
role_details        =   []

class UserUtils:

    @staticmethod
    def generate_uuid():
        """UUID generation."""

        return(uuid.uuid4().hex)


    @staticmethod
    def validate_email_format(email):
        """Email validation

        Max length check
        Regex validation for emails.
        """
        if len(email) > config.EMAIL_MAX_LENGTH:
            return False
        regex = '([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)'
        if (re.search(regex, email)):
            return True
        else:
            return False


    @staticmethod
    def hash_password(password):
        """Password hashing using bcrypt."""

        # converting str to byte before hashing
        password_in_byte    = bytes(password, 'utf-8')  
        salt                = bcrypt.gensalt()
        return(bcrypt.hashpw(password_in_byte, salt))


    @staticmethod
    def validate_password(password):
        """Password rule check

        Minimum x chars long,as defined by 'MIN_LENGTH' on config,
        Must contain upper,lower,number and a special character.
        """

        if len(password) < config.PWD_MIN_LENGTH:
            return post_error("Invalid password", "password should be minimum {} characteristics long".format(config.PWD_MIN_LENGTH), None)
        if len(password) > config.PWD_MAX_LENGTH:
            return post_error("Invalid password", "password cannot exceed {} characteristics long".format(config.PWD_MAX_LENGTH), None)
        regex   = ("^(?=.*[a-z])(?=." + "*[A-Z])(?=.*\\d)" +
                 "(?=.*[-+_!@#$%^&*., ?]).+$")
        pattern = re.compile(regex)
        if re.search(pattern, password) is None:
            return post_error("Invalid password", "password must contain atleast one uppercase,one lowercase, one numeric and one special character", None)


    @staticmethod
    def validate_phone(phone):
        """Phone number validation
        
        10 digits, starts with 6,7,8 or 9.
        """
        pattern = re.compile("(0/91)?[6-9][0-9]{9}")
        if (pattern.match(phone)) and len(phone) == 10:
            return True
        else:
            return False

    @staticmethod
    def email_availability(email):
        """Email validation
        
        Verifying whether the email is already taken or not
        """
        try:
            #connecting to mongo instance/collection
            collections = db.get_db()[USR_MONGO_COLLECTION]  
            #searching username with verification status = True 
            user_record = collections.find({"userName": email}) 
            if user_record.count() != 0:
                return post_error("Data not valid", "This email address is already registered . Please use another email address.", None)
                    
            log.info("Email is not already taken, validated")
        except Exception as e:
            log.exception("Database connection exception |{}".format(str(e)))
            return post_error("Database exception", "An error occurred while working on the database:{}".format(str(e)), None)

   
    @staticmethod
    def token_validation(token):
        """Auth-token Validation for auth-token-search
        
        matching with existing active tokens on database,
        decoding the token,
        updating user token status on database in case of token expiry.
        """
        try:
            decoded = jwt.decode(token, config.SECRET_KEY, algorithm='HS256')
            print(decoded,"*************")
            return decoded
        except jwt.exceptions.ExpiredSignatureError as e:
            log.exception("Auth-token expired, time limit exceeded")
            return post_error("Invalid token", "User session timed out, Please login again")
        except Exception as e:
            log.exception("Auth-token expired, jwt decoding failed")
            return post_error("Invalid token", "Not a valid token")

    @staticmethod
    def generate_token(userdetails):
        """Issuing new token

        defining expiry period for token,
        jwt token generated with payload as user_name.
        """
        try:
            # seting time limit for token expiry
            time_limit = datetime.utcnow() + timedelta(hours=token_life)
            #creating payload for token 
            payload = {"userName": userdetails["userName"], "exp": time_limit}
            #generating token
            token = jwt.encode(payload, config.SECRET_KEY, algorithm='HS256')
            return token
        except Exception as e:
            log.info(f"Database connection exception :{str(e)}")
            return post_error("Database connection exception", "An error occurred while connecting to the database", None)


    @staticmethod
    def validate_user_input_creation(user):
        """Validating user creation inputs.

        -Mandatory key checks
        -Email Validation
        -Password Validation 
        """
        obj_keys = {'firstName','lastName','email','password','gender','age'}
        for key in obj_keys:
            if (user.get(key) == None) :
                    log.info("Mandatory key checks failed")
                    return post_error("Data Missing","firstName,lasName,email,password, gender and age are mandatory for user creation",None)
        log.info("Mandatory key checks successful")
 
        email_availability_status = UserUtils.email_availability(user["email"])
        if email_availability_status is not None:
            log.info("Email validation failed, already taken")
            return email_availability_status

        if (UserUtils.validate_email_format(user["email"]) == False):
            log.info("Email validation failed")
            return post_error("Data not valid", "Email given is not valid", None)
        log.info("Email  validated")

        password_validity = UserUtils.validate_password(user["password"])
        if password_validity is not None:
            log.info("Password validation failed")
            return password_validity
        log.info("Password validated")

        if user["age"] <config.MIN_AGE_ALLOWED:
            return post_error("Data not valid", f"User should be minimum of {config.MIN_AGE_ALLOWED} years old to create an account.", None)

        if user.get("phoneNo") != None:
            phone_validity = UserUtils.validate_phone(user["phoneNo"])          
            if phone_validity is False:
                return post_error("Data not valid", "Phone number given is not valid", None)
            log.info("Phone number  validated")



    @staticmethod
    def validate_user_login_input(user_email, password):
        """User credentials validation
        
        checking whether the user is verified and active,
        password matching.
        """

        try:
            collections = db.get_db()[USR_MONGO_COLLECTION]
            #fetching the user details from db
            result = collections.find({'userName': user_email}, {
                'password': 1, '_id': 0,'isActive':1})
            if result.count() == 0:
                log.info("{} is not a registred user".format(user_email))
                return post_error("Not verified", "This email address is not registered with the system. Please sign up.", None)
            password_in_db = result[0]["password"].encode("utf-8")
            try:
                if bcrypt.checkpw(password.encode("utf-8"), password_in_db)== False:
                    log.info("Password validation failed for {}".format(user_email))
                    return post_error("Invalid Credentials", "Incorrect username or password", None)
            except Exception as e:
                log.exception(f"exception while decoding password : {e}")
                return post_error("Invalid Credentials", "Incorrect username or password", None)                 
        except Exception as e:
            log.exception("Exception while validating email and password for login"+str(e))
            return post_error("Invalid Credentials", "Incorrect username or password", None)


    @staticmethod
    def generate_email_notification(user_records,task_id):

        for user_record in user_records:
            email       =   user_record["email"]
            timestamp   =   eval(str(time.time()).replace('.', '')[0:13])
            name        =   None
            user_id     =   None
            link        =   None

            email_subject   =   EnumVals.ConfirmationSubject.value
            template        =   'usr_confirm_registration.html'
            name            =   user_record["name"]
            try:
                msg = Message(subject=email_subject,sender=mail_server,recipients=[email])
                msg.html = render_template(template,ui_link=mail_ui_link,user_name=name)
                mail.send(msg)
                log.info("Generated email notification for {} ".format(email))
            except Exception as e:
                log.exception("Exception while generating email notification | {}".format(str(e)))
                return post_error("Exception while generating email notification","Exception occurred:{}".format(str(e)),None)
            
    @staticmethod
    def validate_username(user_email):
        """Validating userName/Email"""

        try:
            #connecting to mongo instance/collection
            collections = db.get_db()[USR_MONGO_COLLECTION]
            #searching for record matching user_name
            valid = collections.find({"userName":user_email,"isActive":True})
            if valid.count() == 0:
                log.info("Not a valid email/username")
                return post_error("Not Valid","This email address is not a registered/active in the system",None)
        except Exception as e:
            log.exception("exception while validating username/email"+str(e),  MODULE_CONTEXT, e)
            return post_error("Database exception","Exception occurred:{}".format(str(e)),None)




                

        
