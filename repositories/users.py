from models import UserManagementModel
from models import post_error
from utilities import UserUtils
import time
import datetime

userModel   =   UserManagementModel()

class UserManagementRepositories:
    
    def create_users(self,users):

        records                         =   []
        for user in users:
            users_data                  =   {}
            hashed                      =   UserUtils.hash_password(user["password"])
            user_id                     =   UserUtils.generate_uuid()

            users_data["userID"]        =   user_id
            users_data["userName"]      =   user["email"]
            users_data["firstName"]     =   user["firstName"]
            users_data["lasName"]       =   user["lasName"]
            users_data["password"]      =   hashed.decode("utf-8")
            users_data["gender"]        =   user["gender"]
            users_data["age"]           =   user["age"]
            if "phoneNo" in user:
                users_data["phoneNo"]   =   user["phoneNo"]
            users_data["isActive"]      =   True
            users_data["createdAt"]     =   datetime.datetime.utcnow()
            records.append(users_data)
        if not records:
            return post_error("Data Null", "Data recieved for user creation is empty", None)

        result = userModel.create_users(records)
        if result is not None:
            return result

    def status_update(self,userName,message,tags):
        record          =   {}
        record["messageID"] =   UserUtils.generate_uuid()
        record["userName"] =userName
        record["message"]=message
        record["tags"]=tags
        record["postedTime"]=str(datetime.datetime.utcnow())

        result = userModel.post_an_update(userName,record)
        if result is not None:
            return result
        else:
            return True

    def user_login(self,user_name, password):
        result = userModel.user_login(user_name, password)
        return result

    def user_logout(self,user_name):
        result = userModel.user_logout(user_name)
        return result
