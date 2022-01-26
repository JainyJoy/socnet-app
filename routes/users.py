from flask import Blueprint
from flask_restful import Api
from resources import (
    CreateUser,
    UserLogin,
    UserLogout,
    StatusUpdate,
    FollowUser,
    ViewFeeds,
    Health,
)


NET_SITE_BLUEPRINT = Blueprint("socnet-site", __name__)

Api(NET_SITE_BLUEPRINT).add_resource(CreateUser, "/v1/user/signup")

Api(NET_SITE_BLUEPRINT).add_resource(UserLogin, "/v1/user/login")

Api(NET_SITE_BLUEPRINT).add_resource(UserLogout, "/v1/user/logout")

Api(NET_SITE_BLUEPRINT).add_resource(StatusUpdate, "/v1/user/update")

Api(NET_SITE_BLUEPRINT).add_resource(FollowUser, "/v1/user/update")

Api(NET_SITE_BLUEPRINT).add_resource(ViewFeeds, "/v1/user/update")

Api(NET_SITE_BLUEPRINT).add_resource(Health, "/health")
