import logging
import pymongo
log = logging.getLogger('file')
import config


class UserRepo:
    
    def __init__(self):
        pass
        
    #method to instantiate mongo client object
    def instantiate(self):
        client = pymongo.MongoClient(config.MONGO_DB_SCHEMA)
        return client

    #insert operation on mongo
    def insert(self, data):
        col = self.get_mongo_instance()
        if isinstance(data, dict):
            data = [data]
        col.insert_many(data)
        return len(data)

    #mongo upsert 
    def upsert(self, condition, object_in):
        try:
            col = self.get_mongo_instance()
            col.update(condition,object_in, upsert=True)
        except Exception as e:
            log.exception(f'Exception in repo upsert: {e}', e)

    # Searches the object from mongo collection
    def search(self, query, exclude=None, offset=None, res_limit=None):
        try:
            col = self.get_mongo_instance()
            if offset is None and res_limit is None:
                res = col.find(query, exclude).sort([('_id', 1)])
            else:
                res = col.find(query, exclude).sort([('_id', -1)]).skip(offset).limit(res_limit)
            result = []
            for record in res:
                result.append(record)
            return result
        except Exception as e:
            log.exception(f'Exception in repo search: {e}', e)
            return []
    



