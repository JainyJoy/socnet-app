from db import get_db
from utilities import UserUtils, EnumVals, normalize_bson_to_json
from .response import post_error
from config import USR_MONGO_COLLECTION, USR_MESSAGE_COLLECTION, USR_TOKEN_MONGO_COLLECTION
import time
import logging

log = logging.getLogger("file")


class UserManagementModel(object):
    def create_users(self, records):
        """Inserting user records to the databse"""

        try:
            # connecting to mongo instance/collection
            collections = get_db()[USR_MONGO_COLLECTION]
            # inserting user records on db
            results = collections.insert(records)
            log.info("Count of users created : {}".format(len(results)))
            if len(records) != len(results):
                return post_error(
                    "Database exception",
                    "User creation failed due to databse error",
                    None,
                )
            # email notification for registered user
            user_notified = UserUtils.generate_email_notification(
                records, EnumVals.ConfirmationTaskId.value
            )
            if user_notified is not None:
                return user_notified
        except Exception as e:
            log.exception("Database connection exception {}".format(str(e)))
            return post_error(
                "Database  exception", "User creation failed due to databse error", None
            )

    def user_login(self,user_name, password):
        """User Login

        fetching token from db for previously logged in user,
        validating the token,
        generating new token in case of new user or expired token.
        """

        try:
            #searching for token against the user_name
            token_available = UserUtils.get_token(user_name)

            if token_available["status"] == False:
                log.info("Generating new token for {}".format(user_name))
                #issuing new token
                new_token   =   UserUtils.generate_token({"user_name":user_name},USR_TOKEN_MONGO_COLLECTION)
                #dict value is returned if generate_token returned error
                if isinstance(new_token,dict):
                    log.info("Failed to generate new token for {}".format(user_name))
                    return new_token
                else:
                    return_data = {
                        "userName": user_name,
                        "token": new_token.decode("UTF-8")}
                    return return_data

            elif token_available["status"] == True:
                log.info(f"Returning back existing token for {user_name}")
                token = token_available["data"]
                return_data = {
                    "userName": user_name,
                    "token": token}
                return return_data
        except Exception as e:
            log.exception(f"Database connection exception :{str(e)} ")
            return post_error("Database  exception", "An error occurred while processing on the database:{}".format(str(e)))

    def user_logout(self, user_name):
        """User Logout

        updating active status to False on user token collection.
        """

        try:
            # connecting to mongo instance/collection
            collections = get_db()[USR_MONGO_COLLECTION]
            # fetching user data
            record = collections.find({"user": user_name, "active": True})
            if record.count() == 0:
                return False
            if record.count() != 0:
                for user in record:
                    # updating status = False for user token collection
                    collections.update(
                        user,
                        {
                            "$set": {
                                "active": False,
                                "end_time": eval(
                                    str(time.time()).replace(".", "")[0:13]
                                ),
                            }
                        },
                    )
                    log.info(
                        "Updated database record on user log out for {}".format(
                            user_name
                        )
                    )
                return True
        except Exception as e:
            log.exception(f"Database exception : {e}")
            return post_error(
                "Database connection exception",
                "An error occurred while connecting to the database:{}".format(str(e)),
                None,
            )

    def post_an_update(self, user, record):
        """Updating user records in the database"""

        try:
            # connecting to mongo instance/collection
            collections = get_db()[USR_MESSAGE_COLLECTION]
            results = collections.update(
                        {"userName": user}, {"$set": record}
                    )

            if "writeError" in list(results.keys()):
                log.exception(f"writeError on db")
                return post_error(
                    "Database error",
                    "some of the records where not updated",
                    None,
                )

        except Exception as e:
            log.exception(f"Database connection exception : {e} ")
            return post_error(
                "Database connection exception",
                "An error occurred while connecting to the database:{}".format(str(e)),
                None,
            )


    def profile_update(self, user, record):
            """Updating user records in the database"""

            try:
                # connecting to mongo instance/collection
                collections = get_db()[USR_MESSAGE_COLLECTION]
                results = collections.update(
                            {"userName": user}, {"$set": record}
                        )

                if "writeError" in list(results.keys()):
                    log.exception(f"writeError on db")
                    return post_error(
                        "Database error",
                        "some of the records where not updated",
                        None,
                    )

            except Exception as e:
                log.exception(f"Database connection exception : {e} ")
                return post_error(
                    "Database connection exception",
                    "An error occurred while connecting to the database:{}".format(str(e)),
                    None,
                )


    def get_latest_feeds(self, user, record):
            """Updating user records in the database"""

            try:
                # connecting to mongo instance/collection
                collections = get_db()[USR_MESSAGE_COLLECTION]
                results = collections.update(
                            {"userName": user}, {"$set": record}
                        )

                if "writeError" in list(results.keys()):
                    log.exception(f"writeError on db")
                    return post_error(
                        "Database error",
                        "some of the records where not updated",
                        None,
                    )

            except Exception as e:
                log.exception(f"Database connection exception : {e} ")
                return post_error(
                    "Database connection exception",
                    "An error occurred while connecting to the database:{}".format(str(e)),
                    None,
            )
