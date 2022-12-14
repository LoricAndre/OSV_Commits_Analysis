import grpc

import swh.graph.grpc.swhgraph_pb2 as swhgraph
import swh.graph.grpc.swhgraph_pb2_grpc as swhgraph_grpc

import sqlite3
from os import environ as env
from tqdm import tqdm
from typing import List, Iterator

HOST = env.get("GPRC_HOST", "localhost")
PORT = env.get("GRPC_PORT", "50091")


class GraphClient(swhgraph_grpc.TraversalServiceStub):
    def get_node(self, sha: str) -> str:
        swhid = "swh:1:rev:%s" % sha
        try:
            node = self.GetNode(swhgraph.GetNodeRequest(swhid=swhid))
            return node.swhid.split(':')[3]
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.INVALID_ARGUMENT:
                return ''
            else:
                raise e

    def __contains__(self, sha: str) -> bool:
        return self.get_node(sha) != ''

    def bfs(self, sha_list: List[str], backwards=False) -> Iterator[str]:
        src = ["swh:1:rev:%s" % sha for sha in sha_list if sha in self]
        if backwards:
            direction = swhgraph.GraphDirection.BACKWARD
        else:
            direction = swhgraph.GraphDirection.FORWARD
        nodes = self.Traverse(swhgraph.TraversalRequest(
            src=src, direction=direction))
        for node in nodes:
            if node.swhid.split(':')[2] == "rev":
                yield node.swhid.split(':')[3]

    def ancestors(self, sha_list: List[str]) -> Iterator[str]:
        return self.bfs(sha_list)

    def descendants(self, sha_list: List[str]) -> Iterator[str]:
        return self.bfs(sha_list, True)


class SQLCon:
    def __init__(self, path: str):
        self.con = sqlite3.connect(path)
        self.cur = self.con.cursor()
        self.cur.execute('''CREATE TABLE IF NOT EXISTS vulns
             (sha, uid)''')
        self.cur.execute('''PRAGMA synchronous = OFF''')

    def e(self, query, *args):
        return self.cur.execute(query % args).fetchall()

    def em(self, query, items):
        self.cur.executemany(query, items)

    def commit(self):
        return self.con.commit()

    def close(self):
        return self.con.close()


def color_nodes(nodes, uid, db, table="vulns"):
    # print(len(*zip(nodes)))
    # db.em("insert into %s values (?, '%s')" % (table, uid), zip(nodes))

    for node in tqdm(nodes):
        q = "insert into %s (sha, uid) values ('%s', '%s')" % (table, node, uid)
        try:
            db.e(q)
        except Exception as e:
            print("Error executing query", q)
            raise e


def uncolor_nodes(nodes, uid, db):
    db.e("delete from vulns where uid='%s' and sha in ('%s')",
         uid, "','".join(nodes))
    # db.em("delete from vulns where uid='%s' and sha in (?)" % uid, zip(nodes))


def insert_items(items, db, table="vulns"):
    if items:
        q = "insert into %s (sha, uid) values " % table
        q += ",".join(["('%s','%s')" % item for item in items])
        try:
            db.e(q)
        except Exception as e:
            print("Error executing query", q)
            raise e


def main():
    db = SQLCon("data/swh.db")
    with grpc.insecure_channel("%s:%s" % (HOST, PORT)) as channel:
        client = GraphClient(channel)
        try:
            # for vuln in tqdm(db.e("select * from OSV where type = 'GIT'")):
            #     uid, cve, _, _, _, _, _, start, end = vuln
            #     if start == '0':
            #         color_nodes(client.ancestors([end]), uid, db)
            #     elif end == '0':  # Check what happens if found
            #         color_nodes(client.descendants([start]), uid, db)
            #     else:
            #         # nodes = [node for node in client.descendants(
            #         #     [start]) if node not in client.descendants([end])]
            #         # color_nodes(nodes, uid, db)
            #         color_nodes(client.descendants([start]), uid, db)
            #         db.e("delete from vulns where uid='%s' and sha in ('%s')",
            #              uid, "','".join(client.descendants([end])))
            #     db.commit()
            print("Processing 0-ending ranges...")
            items = db.e(
                "select start, id from OSV where type = 'GIT' and start != '0' and end = '0'")
            for start, uid in tqdm(items):
                color_nodes(client.descendants([start]), uid, db)
            db.commit()
            print("Processing 0-starting ranges...")
            items = db.e(
                "select end, id from OSV where type = 'GIT' and end != '0' and start = '0'")
            for end, uid in tqdm(items):
                print("a")
                color_nodes(client.ancestors([end]), uid, db)
                print("c")
            db.commit()
            print("Processing closed ranges...")
            items = db.e(
                "select start, end, id from OSV where type = 'GIT' and start != '0' and end != 0")
            for start, end, uid in tqdm(items):
                color_nodes(client.descendants([start]), uid, db)
                uncolor_nodes(client.descendants([end]), uid, db)
            db.commit()

        except KeyboardInterrupt:
            print("Aborting...")
    db.close()


if __name__ == "__main__":
    main()
