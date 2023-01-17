import sqlite3

class SQLCon:
    def __init__(self, path: str, table="vulns"):
        self.con = sqlite3.connect(path)
        self.cur = self.con.cursor()
        self.cur.execute('''CREATE TABLE IF NOT EXISTS vulns
             (sha, uid)''')
        self.cur.execute('''PRAGMA synchronous = OFF''')
        self.vuln_table = table

    def e(self, query, *args):
        return self.cur.execute(query % args).fetchall()

    def em(self, query, items):
        self.cur.executemany(query, items)

    def commit(self):
        return self.con.commit()

    def close(self):
        return self.con.close()

    def color_nodes(self, nodes, uid):
        self.em("insert into %s values (?, '%s')" % (self.vuln_table, uid), zip(nodes))
        return 0

    def uncolor_nodes(self, nodes, uid):
        self.em("delete from %s where uid='%s' and sha=?" % (self.vuln_table, uid), zip(nodes))
        return 0
