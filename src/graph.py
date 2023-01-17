from os import environ as env
from tqdm import tqdm
import logging as log

from utils.swh_grpc import GraphClient
from utils.swh_sqlite import SQLCon

HOST = env.get("GPRC_HOST", "localhost")
PORT = env.get("GRPC_PORT", "50091")
DBPATH = env.get("DB_PATH", "data/swh.db")

log.basicConfig(
    format='(%(name)s) - [%(levelname)s] %(message)s', level=log.INFO)


def main():
    log.info("Using DB at %s and gRPC server at %s:%s", DBPATH, HOST, PORT)
    db = SQLCon(DBPATH)
    client = GraphClient(HOST, PORT)
    try:
        log.info("Processing 0-ending ranges...")
        items = db.e(
            "select start, id from OSV where type = 'GIT' and start != '0' and end = '0'")
        for start, uid in tqdm(items):
            db.color_nodes(client.descendants([start]), uid)
        db.commit()
        log.info("Processing 0-starting ranges...")
        items = db.e(
            "select end, id from OSV where type = 'GIT' and end != '0' and start = '0'")
        for end, uid in tqdm(items):
            db.color_nodes(client.ancestors([end]), uid)
        db.commit()
        log.info("Processing closed ranges...")
        items = db.e(
            "select start, end, id from OSV where type = 'GIT' and start != '0' and end != 0")
        for start, end, uid in tqdm(items):
            # db.color_nodes(set(client.descendants([start])) - set(client.descendants([end])), uid)
            db.color_nodes(client.descendants([start]), uid)
            db.uncolor_nodes(client.descendants([end]), uid)
        db.commit()

    except KeyboardInterrupt:
        log.error("Aborting...")
    client.close()
    db.close()


if __name__ == "__main__":
    main()
