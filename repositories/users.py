from webbrowser import get
from config import USR_MONGO_COLLECTION, USR_MESSAGE_COLLECTION, USR_TOKEN_MONGO_COLLECTION
from models import post_error, UserModel
from utilities import UserUtils
from db import get_db
import logging
log = logging.getLogger('file')
import datetime

userModel   =   UserModel()

class UserManagementRepositories:
    
    def create_users(self,user):

        user_data                  =   {}
        hashed                     =   UserUtils.hash_password(user["password"])
        user_id                    =   UserUtils.generate_uuid()

        user_data["userID"]        =   user_id
        user_data["userName"]      =   user["email"]
        user_data["firstName"]     =   user["firstName"]
        user_data["lastName"]      =   user["lastName"]
        user_data["password"]      =   hashed.decode("utf-8")
        user_data["gender"]        =   user["gender"]
        user_data["age"]           =   user["age"]
        user_data["isActive"]      =   True
        user_data["createdAt"]     =   datetime.datetime.utcnow()

        usr_collection = get_db()[USR_MONGO_COLLECTION]
        result = userModel.insert(usr_collection,user_data)
        if not result:
            return False


    def user_login(self,user_name):
        """User Login

        fetching token from db for previously logged in user,
        validating the token,
        generating new token in case of new user or expired token.
        """

        try:
            #searching for token against the user_name
            tok_collection = get_db()[USR_TOKEN_MONGO_COLLECTION]
            token_available = userModel.search(tok_collection,{"userName":user_name,"active":True},{"_id":0})
            if token_available:
                validity = UserUtils.token_validation(token_available[0]["token"])
                if "errorID" not in validity:
                    return {"userName": user_name,"token": token_available[0]["token"]}

            log.info(f"Generating new token for {user_name}")
            new_token   =   UserUtils.generate_token({"userName":user_name})
            if "errorID" not in new_token:
                userModel.insert(tok_collection,{"userName":user_name,"token":new_token,"active":True})
                return {"userName": user_name,"token": new_token}
        except Exception as e:
            log.exception(f"Database connection exception :{str(e)} ")
            return post_error("Database  exception", "An error occurred while processing on the database:{}".format(str(e)))

    def user_logout(self,user_name):
        tok_collection = get_db()[USR_TOKEN_MONGO_COLLECTION]
        userModel.remove(tok_collection,{"userName":user_name})
        return True

    def status_update(self,userName,message,tags):
        record          =   {}
        record["messageID"] =   UserUtils.generate_uuid()
        record["userName"] =userName
        record["message"]=message
        record["tags"]=tags
        record["postedTime"]=str(datetime.datetime.utcnow())

        msg_collection = get_db()[USR_MESSAGE_COLLECTION]
        result = userModel.insert(msg_collection,record)
        if not result:
            return False
    
    def follow_user(self,userName,follow_id):
        usr_collection = get_db()[USR_MONGO_COLLECTION]
        result = UserModel.update(usr_collection,{"userName":userName},{ "$push": { "followingIDs":follow_id } })
        if not result:
            return False

    def view_feeds(self,userName):
        usr_collection = get_db()[USR_MONGO_COLLECTION]
        user = UserModel.search(usr_collection,{"userName":userName},{"followingIDs":1})
        if not user:
            return False
        followingIDs = user[0]["followingIDs"]
        msg_collection = get_db()[USR_MESSAGE_COLLECTION]
        result = UserModel.search(msg_collection,{"userName":{"$in":followingIDs}},{"message":1})
        if not result:
            return False
        return result

