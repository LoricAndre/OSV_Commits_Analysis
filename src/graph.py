#!/usr/bin/env python3

from os import environ as env
from os import cpu_count
import time
import logging as log
from sys import setrecursionlimit
from pqdm.threads import pqdm
from tqdm import tqdm

setrecursionlimit(int(1e9))

from utils.swh_grpc import GraphClient
from utils.swh_sqlite import SQLCon

HOST = env.get("GPRC_HOST", "localhost")
PORT = env.get("GRPC_PORT", "50091")
DBPATH = env.get("DB_PATH", "data/swh.db")
THREADS = 0 # int(env.get("THREADS", min(32, cpu_count())))
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
        start, end, uid = vuln
        if start != '0':
            ids = starts.get(start, [])
            ids.append(uid)
            starts[start] = ids
        if end != '0':
            ids = ends.get(end, [])
            ids.append(uid)
            ends[end] = ids

    def color_vuln(vuln):
        vuln_start, vuln_end, vuln_id = vuln
        res = computed.get(vuln_end, {})
        if res == {}:
            parents = client.parents(vuln_end)
            for parent in parents:
                pvulns = computed.get(parent, None)
                if pvulns is None: # Not computed yet, need to
                    pvulns = color_vuln((vuln_start, parent, vuln_id))
                for vuln_id, affected in pvulns.items():
                    if affected:
                        res[vuln_id] = affected # If not, will keep the same value
                end_ids = ends.get(vuln_end, [])
                for end_id in end_ids:
                    res[end_id] = False
            start_ids = starts.get(vuln_end, [])
            for start_id in start_ids:
                res[start_id] = True
            if vuln_start == '0':
                res[vuln_id] = True
            computed[vuln_end] = res
            print(vuln, res)
            db.color_one(vuln_end, [v for v, b in res.items() if b])
        return res

    for vuln in tqdm(vulns):
        start, end, uid = vuln
        if end in client: # TODO handle 0 end
            color_vuln(vuln)
            db.commit()
            break

def topo_color(db, client):
    all_vulns = db.e("select start, end, id from OSV where type = 'GIT'")
    vulns = {} # TODO maybe use the db for this
    # Build starts and ends
    starts = {}
    ends = {}
    for vuln in all_vulns:
        start, end, uid = vuln
        s = starts.get(start, set())
        s.add(uid)
        starts[start] = s
        e = ends.get(end, set())
        e.add(uid)
        ends[end] = s

    for node in tqdm(client.topo_sort()):
        node = node.strip(' \n\r\t')
        s = time.time()
        parents = list(client.parents(node))
        print("T", time.time() - s)
        res = starts.get(node, set())
        if len(parents) == 0: # TODO right-open vulns, need to be handled in the right connex component
            res.update(ends.get('0', set()))
        else:
            for parent in parents:
                res.update(vulns[parent])
        res -= ends.get(node, set())
        vulns[node] = res
        # db.color_one(node, res)
        # db.commit()

def main():
    log.info("Using DB at %s and gRPC server at %s:%s", DBPATH, HOST, PORT)
    if MULTITHREAD:
        log.info("Running using %d threads.", THREADS)
    db = SQLCon(DBPATH)
    client = GraphClient(HOST, PORT)
    try:
        # naive_color(db, client)
        # dfs_color(db, client)
        topo_color(db, client)
    except KeyboardInterrupt:
        log.warning("User interrupt, aborting...")
    client.close()
    db.close()


if __name__ == "__main__":
    main()
