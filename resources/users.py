from email import message
from flask_restful import Resource
from repositories import UserManagementRepositories
from models import CustomResponse, Status, post_error
from utilities import UserUtils
from flask import request, jsonify
import logging

log = logging.getLogger("file")
userRepo = UserManagementRepositories()


class CreateUser(Resource):
    def post(self):
        body = request.get_json()
        log.info(f"Registration request received for {body['email']} ")
        validity = UserUtils.validate_user_input_creation(body)
        if validity is not None:
            log.info(f"User validation failed for {body['email']}")
            return validity, 400

        try:
            result = userRepo.create_users(body)
            if result is not None:
                log.error("User creation failed | {}".format(str(result)))
                return result, 400
            else:
                res = CustomResponse(Status.SUCCESS_USR_CREATION.value, None)
                log.info("User creation successful")
                return res.getresjson(), 200
        except Exception as e:
            log.exception("Exception while creating user records: {}".format(str(e)))
            return (
                post_error(
                    "Exception occurred",
                    "Exception while performing user creation:{}".format(str(e)),
                    None,
                ),
                400,
            )


class UserLogin(Resource):
    def post(self):
        body = request.get_json()
        if "email" not in body or not body["email"]:
            return post_error("Data Missing", "email not found", None), 400
        if "password" not in body or not body["password"]:
            return post_error("Data Missing", "password not found", None), 400

        email = body["email"]
        password = body["password"]
        log.info("Request for login from {}".format(email))

        validity = UserUtils.validate_user_login_input(email, password)
        if validity is not None:
            log.error("Login credentials check failed for {}".format(email))
            return validity, 400
        log.info("Login credentials check passed for {}".format(email))
        try:
            result = userRepo.user_login(email, password)
            if "errorID" in result:
                log.exception("Login failed for {}".format(email))
                return result, 400
            log.info("Login successful for {}".format(email))
            res = CustomResponse(Status.SUCCESS_USR_LOGIN.value, result)
            return res.getresjson(), 200
        except Exception as e:
            log.exception("Exception while  user login | {}".format(str(e)))
            return (
                post_error(
                    "Exception occurred", "Exception while performing user login", None
                ),
                400,
            )


class UserLogout(Resource):
    def post(self):
        body = request.get_json()
        if "userName" not in body or not body["userName"]:
            return post_error("Data Missing", "userName not found", None), 400
        user_name = body["userName"]

        log.info("Request for logout from {}".format(user_name))
        try:
            result = userRepo.user_logout(user_name)
            if result == False:
                log.info("Logout failed for {}".format(user_name))
                res = CustomResponse(Status.FAILURE_USR_LOGOUT.value, None)
                return res.getresjson(), 400
            else:
                log.info("{} logged out successfully".format(user_name))
                res = CustomResponse(Status.SUCCESS_USR_LOGOUT.value, None)
            return res.getres()
        except Exception as e:
            log.exception("Exception while logout: " + str(e))
            return (
                post_error(
                    "Exception occurred", "Exception while performing user logout", None
                ),
                400,
            )



class StatusUpdate(Resource):
    def post(self):
        body = request.get_json()
        message = body["message"]
        tags    = body["hashtags"]
        token   = request.headers["auth-token"]

        log.info("Status update request received ")
        token_validity = UserUtils.token_validation(token)
        if "errorID" in token_validity :
            return token_validity, 400
        user_validity = UserUtils.validate_username(token_validity["userName"])
        if user_validity is not None:
            return user_validity, 400

        try:
            result = userRepo.status_update(token_validity["userName"], message,tags)
            if result == True:
                log.info("User/s updation successful")
                res = CustomResponse(Status.SUCCESS_USR_UPDATION.value, None)
                return res.getresjson(), 200
            else:
                log.info("User updation failed | {}".format(str(result)))
                return result, 400

        except Exception as e:
            log.exception("Exception while updating user records: " + str(e))
            return (
                post_error(
                    "Exception occurred",
                    "Exception while performing user updation:{}".format(str(e)),
                    None,
                ),
                400,
            )


class FollowUser(Resource):
    def post(self):
        body = request.get_json()
        if "users" not in body or not body["users"]:
            return post_error("Data Missing", "users not found", None), 400

        users = body["users"]
        user_id = None
        user_id = request.headers["x-user-id"]
        log.info("Updation request received for {} user/s".format(len(users)))
        log.info("User/s validation started")
        for i, user in enumerate(users):
            validity = UserUtils.validate_user_input_updation(user)
            if validity is not None:
                log.info("User validation failed for user{}".format(i + 1))
                return validity, 400
        log.info("Users are validated")

        try:
            result = userRepo.update_users(users, user_id)
            if result == True:
                log.info("User/s updation successful")
                res = CustomResponse(Status.SUCCESS_USR_UPDATION.value, None)
                return res.getresjson(), 200
            else:
                log.info("User updation failed | {}".format(str(result)))
                return result, 400

        except Exception as e:
            log.exception("Exception while updating user records: " + str(e))
            return (
                post_error(
                    "Exception occurred",
                    "Exception while performing user updation:{}".format(str(e)),
                    None,
                ),
                400,
            )

class ViewFeeds(Resource):
    def post(self):
        body = request.get_json()
        if "users" not in body or not body["users"]:
            return post_error("Data Missing", "users not found", None), 400

        users = body["users"]
        user_id = None
        user_id = request.headers["x-user-id"]
        log.info("Updation request received for {} user/s".format(len(users)))
        log.info("User/s validation started")
        for i, user in enumerate(users):
            validity = UserUtils.validate_user_input_updation(user)
            if validity is not None:
                log.info("User validation failed for user{}".format(i + 1))
                return validity, 400
        log.info("Users are validated")

        try:
            result = userRepo.update_users(users, user_id)
            if result == True:
                log.info("User/s updation successful")
                res = CustomResponse(Status.SUCCESS_USR_UPDATION.value, None)
                return res.getresjson(), 200
            else:
                log.info("User updation failed | {}".format(str(result)))
                return result, 400

        except Exception as e:
            log.exception("Exception while updating user records: " + str(e))
            return (
                post_error(
                    "Exception occurred",
                    "Exception while performing user updation:{}".format(str(e)),
                    None,
                ),
                400,
            )



class Health(Resource):
    def get(self):
        response = {"code": "200", "status": "ACTIVE"}
        return jsonify(response)
