import logging
log = logging.getLogger('file')


class UserModel:
    
    #insert operation on mongo
    def insert(self, col,data):
        try:
            if isinstance(data, dict):
                data = [data]
            col.insert_many(data)
            return True
        except Exception as e:
            log.exception(f'Exception in repo insert: {e}')
            return None

    #mongo upsert 
    def update(self,col, condition, object_in,upsert=False):
        try:
            col.update(condition,object_in,upsert)
            return True
        except Exception as e:
            log.exception(f'Exception in repo upsert: {e}')
            return None


    # Searches the object from mongo collection
    def search(self,col, query, exclude=None, offset=None, res_limit=None):
        try:
            if offset is None and res_limit is None:
                res = col.find(query, exclude).sort([('_id', 1)])
            else:
                res = col.find(query, exclude).sort([('_id', -1)]).skip(offset).limit(res_limit)
            result = []
            for record in res:
                result.append(record)
            return result
        except Exception as e:
            log.exception(f'Exception in repo search: {e}')
            return None
    



