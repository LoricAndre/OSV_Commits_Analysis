import grpc

import swh.graph.grpc.swhgraph_pb2 as swhgraph
import swh.graph.grpc.swhgraph_pb2_grpc as swhgraph_grpc
from google.protobuf.field_mask_pb2 import FieldMask

from typing import List, Iterator


class GraphClient(swhgraph_grpc.TraversalServiceStub):
    def __init__(self, host, port):
        self.channel = grpc.insecure_channel("%s:%s" % (host, port))
        super().__init__(self.channel)

    def close(self):
        self.channel.close()

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

    def bfs(self, sha_list: List[str], backwards=False, **kwargs) -> Iterator[str]:
        src = ["swh:1:rev:%s" % sha for sha in sha_list if sha in self]
        if src == []:
            return iter(())
        if backwards:
            direction = swhgraph.GraphDirection.BACKWARD
        else:
            direction = swhgraph.GraphDirection.FORWARD
        nodes = self.Traverse(swhgraph.TraversalRequest(
            src=src, direction=direction, edges="rev:rev", mask=FieldMask(paths=["swhid"]), **kwargs))
        return map(lambda n: n.swhid.split(':')[-1], nodes)

    def ancestors(self, sha_list: List[str]) -> Iterator[str]:
        return self.bfs(sha_list)

    def descendants(self, sha_list: List[str]) -> Iterator[str]:
        return self.bfs(sha_list, True)

    def parents(self, sha):
        return self.bfs([sha], backwards=True, max_depth=1)
