#!/usr/bin/env python3

from os import environ as env
from os import cpu_count
from pqdm.threads import pqdm
from tqdm import tqdm
import logging as log

from utils.swh_grpc import GraphClient
from utils.swh_sqlite import SQLCon

HOST = env.get("GPRC_HOST", "localhost")
PORT = env.get("GRPC_PORT", "50091")
DBPATH = env.get("DB_PATH", "data/swh.db")
THREADS = int(env.get("THREADS", min(32, cpu_count())))
MULTITHREAD = (THREADS > 1)

log.basicConfig(
    format='(%(name)s) - [%(levelname)s] %(message)s', level=log.INFO)

def naive_color(db, client):
    log.info("Processing 0-ending ranges...")
    items = db.e(
        "select start, id from OSV where type = 'GIT' and start != '0' and end = '0'")

    if MULTITHREAD:
        pqdm(items, lambda x: db.color_nodes(client.descendants(
            [x[0]]), x[1]), n_jobs=THREADS, exception_behaviour='immediate')
    else:
        for start, uid in tqdm(items):
            db.color_nodes(client.descendants([start]), uid)
    db.commit()
    log.info("Processing 0-starting ranges...")
    items = db.e(
        "select end, id from OSV where type = 'GIT' and end != '0' and start = '0'")
    if MULTITHREAD:
        pqdm(items, lambda x: db.color_nodes(client.ancestors(
            [x[0]]), x[1]), n_jobs=THREADS, exception_behaviour='immediate')
    else:
        for end, uid in tqdm(items):
            db.color_nodes(client.ancestors([end]), uid)
    db.commit()
    log.info("Processing closed ranges...")
    items = db.e(
        "select start, end, id from OSV where type = 'GIT' and start != '0' and end != 0")
    if MULTITHREAD:
        pqdm(items, lambda x: db.color_nodes(client.descendants([x[0]]), x[2]) + db.color_nodes(
            client.descendants([x[1]]), x[2]), n_jobs=THREADS, exception_behaviour='immediate')
    else:
        for start, end, uid in tqdm(items):
            # db.color_nodes(set(client.descendants([start])) - set(client.descendants([end])), uid)
            db.color_nodes(client.descendants([start]), uid)
            db.uncolor_nodes(client.descendants([end]), uid)
    db.commit()

def dfs_color(db, client):
    computed = dict() # dict[sha: dict[vuln_id: bool]]
    vulns = db.e("select start, end, id from OSV where type = 'GIT'")
    ends = dict() # dict[sha: list[vuln_id_list]]
    starts = dict() # dict[sha: list[vuln_id_list]]
    # Build start and end
    for vuln in vulns:
        start = vuln["start"]
        end = vuln["end"]
        if start != '0':
            ids = starts.get(start, [])
            ids.append(vuln["id"])
            starts[start] = ids
        if end != '0':
            ids = ends.get(end, [])
            ids.append(vuln["id"])
            ends[end] = ids

    def color_node(node):
        res = computed.get(node, {})
        if res != {}:
            parents = client.parents(node)
            for parent in parents:
                pvulns = computed.get(parent, None)
                if pvulns is None: # Not computed yet, need to
                    pvulns = color_node(parent)
                for vuln_id, affected in pvulns.items():
                    if affected:
                        res[vuln_id] = affected # If not, will keep the same value
                end_ids = ends.get(node, [])
                for end_id in end_ids:
                    res[end_id] = False
            start_ids = starts.get(node, [])
            for start_id in start_ids:
                res[start_id] = True
            computed[node] = res
        return res

    for vuln in tqdm(vulns):
        end = vuln["end"]
        if end in client:
            color_node(end)

def main():
    log.info("Using DB at %s and gRPC server at %s:%s", DBPATH, HOST, PORT)
    if MULTITHREAD:
        log.info("Running using %d threads.", THREADS)
    db = SQLCon(DBPATH)
    client = GraphClient(HOST, PORT)
    try:
        # naive_color(db, client)
        dfs_color(db, client)
    except KeyboardInterrupt:
        log.warning("User interrupt, aborting...")
    client.close()
    db.close()


if __name__ == "__main__":
    main()
