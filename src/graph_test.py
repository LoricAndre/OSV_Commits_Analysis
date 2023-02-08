#!/usr/bin/env python3

from utils.swh_sqlite import SQLCon
from requests import post
from os import environ as env

DBPATH = env.get("DB_PATH", "data/swh.db")
OSV_QUERY_API = "https://api.osv.dev/v1/query"

class TestClass:
    db = SQLCon(DBPATH)

    def random_db(self, vuln_table="vulns"):
        row = db.e("SELECT * FROM %s ORDER BY RANDOM() LIMIT 1;" % vuln_table)
        res = post(OSV_QUERY_API, data = {
             "commit": row.id
             })
        print(res)
