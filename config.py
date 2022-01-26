import os
import time

#CROSS_MODULE_COMMON_CONFIGS
MONGO_SERVER_HOST   =   os.environ.get('ULCA_MONGO_CLUSTER', 'mongodb://localhost:27017')#,localhost:27018/?replicaSet=foo


#MODULE-SPECIFIC-CONFIGS

#module configs
DEBUG   =   False
CONTEXT_PATH    =   "/api"
HOST    =   '0.0.0.0'
PORT    =   5001
ENABLE_CORS =   False

#mongodb-configs
MONGO_DB_SCHEMA                 =   os.environ.get('UMS_MONGO_IDENTIFIER', 'socnet-user-management')
USR_MONGO_COLLECTION            =   os.environ.get('UMS_USR_COLLECTION', 'users')
USR_MESSAGE_COLLECTION          =   os.environ.get('UMS_USR_MSG_COLLECTION', 'user_posts')
USR_TOKEN_MONGO_COLLECTION      =   os.environ.get('UMS_USR_KEY_COLLECTION', 'ulca-user-keys')
SECRET_KEY                      =   os.environ.get('UMS_SECRET_KEY',"secret_key")
#common-variables
MIN_AGE_ALLOWED         =   os.environ.get('UMS_PASSWORD_MIN_LENGTH', 15)
PWD_MAX_LENGTH          =   os.environ.get('UMS_PASSWORD_MAX_LENGTH', 25)
EMAIL_MAX_LENGTH        =   os.environ.get('UMS_EMAIL_MAX_LENGTH', 256)
OFFSET_VALUE            =   os.environ.get('UMS_OFFSET_VALUE', 0)
LIMIT_VALUE             =   os.environ.get('UMS_LIMIT_VALUE', 20)
AUTH_TOKEN_EXPIRY_HRS   =   os.environ.get('UMS_TOKEN_EXP_HRS', 24)
ADMIN_ROLE_KEY          =   os.environ.get('UMS_ADMIN_ROLE_KEY', 'ADMIN')
LOGIN_AUTENTICATOR      =   os.environ.get('UMS_LOGIN_AUTENTICATORS',['ULCA'])


#gmail server configs
MAIL_SETTINGS           =   {
                                "MAIL_SERVER"   : os.environ.get('ULCA_EMAIL_SERVER','smtp.gmail.com'),
                                "MAIL_PORT"     : eval(os.environ.get('ULCA_EMAIL_SECURE_PORT','465')),
                                "MAIL_USE_TLS"  : False,
                                "MAIL_USE_SSL"  : True,
                                "MAIL_USERNAME" : os.environ.get('ULCA_EMAIL','xxxxxxx'),
                                "MAIL_PASSWORD" : os.environ.get('ULCA_EMAIL_PASSWORD','xxxxx')
                            }
MAIL_SENDER             =   os.environ.get('ULCA_SENDER_EMAIL','ulca@tarento.com')
USER_VERIFY_LINK_EXPIRY =   os.environ.get('ULCA_VERIFY_LINK_EXP_HRS',48)
USER_API_KEY_EXPIRY     =   os.environ.get('ULCA_API_KEY_EXP_DAYS',30)
#React-app base url
BASE_URL                =   os.environ.get('ULCA_REACT_APP_BASE_URL','https://dev.ulcacontrib.org/')
RESET_PWD_ENDPOINT      =   os.environ.get('ULCA_RESET_PWD_ENDPOINT','user/reset-password/')
