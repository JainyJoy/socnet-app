from config import USR_MONGO_COLLECTION, USR_MESSAGE_COLLECTION, USR_TOKEN_MONGO_COLLECTION
from models import post_error, UserModel
from utilities import UserUtils
from db import get_db
import logging
log = logging.getLogger('file')
import datetime

# userModel   =   UserManagementModel()

class UserManagementRepositories:
    
    def create_users(self,user):

        user_data                  =   {}
        hashed                     =   UserUtils.hash_password(user["password"])
        user_id                    =   UserUtils.generate_uuid()

        user_data["userID"]        =   user_id
        user_data["userName"]      =   user["email"]
        user_data["firstName"]     =   user["firstName"]
        user_data["lasName"]       =   user["lasName"]
        user_data["password"]      =   hashed.decode("utf-8")
        user_data["gender"]        =   user["gender"]
        user_data["age"]           =   user["age"]
        user_data["isActive"]      =   True
        user_data["createdAt"]     =   datetime.datetime.utcnow()

        result = UserModel.insert(USR_MONGO_COLLECTION,user_data)
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
            token_available = UserModel.search(USR_TOKEN_MONGO_COLLECTION,{"userName":user_name,"active":True},{"_id":0})
            if token_available is not None:
                validity = UserUtils.token_validation(token_available[0]["token"])
                if "errorID" not in validity:
                    return {"userName": user_name,"token": token_available[0]["token"]}

            log.info(f"Generating new token for {user_name}")
            new_token   =   UserUtils.generate_token({"userName":user_name})
            UserModel.insert(USR_TOKEN_MONGO_COLLECTION,{"userName":user_name,"token":new_token,"active":True})
            return {"userName": user_name,"token": new_token.decode("UTF-8")}

        
        except Exception as e:
            log.exception(f"Database connection exception :{str(e)} ")
            return post_error("Database  exception", "An error occurred while processing on the database:{}".format(str(e)))

    def user_logout(self,user_name):
        result = userModel.user_logout(user_name)
        return result

    def status_update(self,userName,message,tags):
        record          =   {}
        record["messageID"] =   UserUtils.generate_uuid()
        record["userName"] =userName
        record["message"]=message
        record["tags"]=tags
        record["postedTime"]=str(datetime.datetime.utcnow())

        result = UserModel.insert(USR_MONGO_COLLECTION,record)
        if not result:
            return False
    
    def follow_user(self,userName,follow_id):
        result = UserModel.update(USR_MONGO_COLLECTION,{"userName":userName},{ "$push": { "followingIDs":follow_id } })
        if not result:
            return False

    def view_feeds(self,userName,follow_id):
        user = UserModel.search(USR_MONGO_COLLECTION,{"userName":userName},{"followingIDs":1})
        if not user:
            return False
        followingIDs = user[0]["followingIDs"]
        result = UserModel.search(USR_MESSAGE_COLLECTION,{"userName":{"$in":followingIDs}},{"message":1})
        if not result:
            return False
        return result

