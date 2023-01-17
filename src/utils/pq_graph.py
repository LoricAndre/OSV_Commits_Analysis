#!/usr/bin/env python3
import parquet
import graph_tool as gt
from graph_tool import topology, search
from tqdm import tqdm
from utils.ddict import DDict
import logging as log
import pickle
from binascii import b2a_hex


class CommitGraph(gt.Graph):
    def __init__(self):
        super().__init__()
        self.vulns = DDict()
        self.uids = DDict()
        self.v = DDict()
        # self.roots = []

    def from_parquet(self, file):
        n = parquet.read_footer(file).num_rows

        with open(file, 'rb') as f:
            rows = parquet.reader(f, ['id', 'parent_id'])
            for row in tqdm(rows, total=n):
                uid, parent = map(lambda x: b2a_hex(x).decode(), row)
                vertex = self.v.get(uid, self.add_vertex())
                parent_vertex = self.v.get(parent, self.add_vertex())
                self.v[uid] = vertex
                self.uids[vertex] = uid
                self.v[parent] = parent_vertex
                self.uids[parent_vertex] = parent
                self.add_edge(parent_vertex, vertex)  # Order ?

    def dump(self, file):
        with open(file, 'wb') as f:
            pickle.dump(self, f)

    @staticmethod
    def loadf(file=None):
        if file:
            in_ext = file.split('.')[-1]
            if in_ext == 'parquet':
                log.info("Loading parquet file %s" % file)
                g = CommitGraph()
                g.from_parquet(file)
            elif in_ext == 'pickle':
                log.info("loading pickle file %s" % file)
                with open(file, 'rb') as f:
                    g = pickle.load(f)
            else:
                g = CommitGraph()
        else:
            g = CommitGraph()
        log.info("Loaded graph with %d vertices and %d edges" %
                 (g.num_vertices(), g.num_vertices()))
        # if len(g.roots) == 0 and g.num_vertices() > 0:
        #     g.roots = g.get_roots()
        return g

    def __getitem__(self, uid):
        return self.v[uid]

    # def get_roots(self):
    #     log.info("Computing roots...")
    #
    #     log.info("Getting components...")
    #     comp, a = topology.label_components(self)
    #     components = a
    #     print(components)
    #     log.info("Found %d components with average size %f" %
    #              (len(components), components.mean()))
    #     for c in tqdm(range(len(a))):
    #         for i in range(len(comp.a)):
    #             if comp.a[i] == c:
    #                 components[c] = i
    #                 break
    #
    #     def get_root(v):
    #         parents = np.array([0])
    #         while parents.size > 0:
    #             parents = self.get_out_neighbors(v)
    #             print(int(v), map(int, parents))
    #             v = parents.item(0)
    #         print("Found root %d" % int(v))
    #
    #         return v
    #
    #     log.info("Getting roots from components...")
    #     roots = list(map(get_root, tqdm(components)))
    #     log.info("Done.")
    #
    #     return roots
    def update_vertex_vuln(self, vuln, vertex):
        sha = self.uids[int(vertex)]
        vulns = self.vulns.get(sha, [])
        vulns.append(vuln.id)
        self.vulns[sha] = vulns

    def colorize_one_closed(self, vuln):
        start = self.v.get(vuln.Start, False)
        end = self.v.get(vuln.End, False)
        if not (start and end):
            log.warning(
                "Failed to find start or end commit for vuln %s" % vuln.id)
            return
        log.info("Coloring vuln %s" % vuln.id)
        for path in topology.all_shortest_paths(self, start, end):
            for u in path:
                self.update_vertex_vuln(vuln, u)

    def colorize_one_semi(self, vuln):
        end = self.v.get(vuln.End, False)
        if not end:
            log.warning("Failed to find end commit for vuln %s" % vuln.id)
            return
        log.info("Coloring vuln %s" % vuln.id)
        rev = gt.GraphView(self, reversed=True)
        self.update_vertex_vuln(vuln, end)
        for e in search.dfs_iterator(rev, source=end):
            self.update_vertex_vuln(vuln, e.target())

    def colorize(self, vuln):
        start = self.v.get(vuln.Start, False)
        end = self.v.get(vuln.End, False)
        if not end:
            log.warning("Failed to find end commit for vuln %s" % vuln.id)
            return
        if start:
            self.colorize_one_closed(vuln)
        else:
            self.colorize_one_semi(vuln)

    # def colorize(self, ranges):
    #     cves = []
    #     ends = {}
    #
    #     for vertex in tqdm(search.dfs_iterator(self)):
    #         uid = self.uids[vertex]
    #         is_start = ranges.get(uid, [])  # Handle 0
    #         for vuln in is_start:
    #             ends[vuln.end] = ends.get(
    #                 vuln.end, []) + vuln.vulns  # Global ends ?
    #             cves += vuln.vulns
    #         self.vulns[vertex] = cves
    #         for vuln in ends.get(uid, []):
    #             cves.remove(vuln)
    #     return self
