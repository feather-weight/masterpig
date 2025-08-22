import os
import logging
from pymongo import MongoClient

_client = None
_db = None

def get_db():
    global _client, _db
    uri = os.getenv("MONGO_URI")
    dbname = os.getenv("MONGO_DB", "scanner")
    if not uri:
        return None
    if _db is not None:
        return _db
    try:
        _client = MongoClient(uri, serverSelectionTimeoutMS=2000)
        _client.admin.command("ping")
        _db = _client[dbname]
        return _db
    except Exception as exc:
        logging.error("Mongo connection failed: %s", exc)
        return None
