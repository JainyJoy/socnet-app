import enum


class Status(enum.Enum):

    SUCCESS                 =   {"message" : "Request successful"}
    FAILURE_BAD_REQUEST     =   {"message" : "Request failed"}
    SUCCESS_USR_CREATION    =   {"message" : "User registration successful"}
    SUCCESS_USR_LOGIN       =   {"message" : "Logged in successfully"}
    SUCCESS_USR_UPDATION    =   {"message" : "User details updated successfully"}


   

    