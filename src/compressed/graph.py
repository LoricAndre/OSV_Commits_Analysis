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

    def e(self, query, *args):
        return self.cur.execute(query % args).fetchall()

    def close(self):
        return self.con.close()


def color_nodes(nodes, uid, db, table="vulns"):
    items = ["('%s','%s')" % (node, uid) for node in nodes]
    if items:
        q = "insert into %s (sha, uid) values " % table
        q += ",".join(items)
        try:
            db.e(q)
        except Exception as e:
            print("Error executing query", q)
            raise e


def main():
    db = SQLCon("data/swh.db")
    with grpc.insecure_channel("%s:%s" % (HOST, PORT)) as channel:
        client = GraphClient(channel)
        for vuln in tqdm(db.e("select * from OSV where type = 'GIT'")):
            uid, cve, _, _, _, _, _, start, end = vuln
            if start == '0':
                color_nodes(client.ancestors([end]), uid, db)
            elif end == '0':  # Check what happens if found
                color_nodes(client.descendants([start]), uid, db)
            else:
                # nodes = [node for node in client.descendants(
                #     [start]) if node not in client.descendants([end])]
                # color_nodes(nodes, uid, db)
                color_nodes(client.descendants([start]), uid, db)
                db.e("delete from vulns where uid='%s' and sha in ('%s')",
                     uid, "','".join(client.descendants([end])))


if __name__ == "__main__":
    main()
