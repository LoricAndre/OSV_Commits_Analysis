#!/usr/bin/env python3

from swh import CommitGraph
from utils import DDict
from osv import OSV

from glob import glob
from cmd import Cmd
import json
import os
import sys
import importlib
import logging as log

log.basicConfig(
    format='(%(name)s) - [%(levelname)s] %(message)s', level=log.INFO)


class MyPrompt(Cmd):
    def __init__(self):
        super().__init__()
        self.graph_files = glob("*.parquet", root_dir="data", recursive=True)
        self.graph_file = "<>"
        self.vuln_files = glob("*.csv", root_dir="data", recursive=True)
        self.vuln_file = "<>"
        self._prompt()

        self.g = None
        self.vulns = None
        self.mods = DDict()
        self.intro = """
  ___       __ _                         _  _         _ _                    ___     _         _            
 / __| ___ / _| |___ __ ____ _ _ _ ___  | || |___ _ _(_) |_ __ _ __ _ ___   / __|___| |___ _ _(_)______ _ _ 
 \__ \/ _ \  _|  _\ V  V / _` | '_/ -_) | __ / -_) '_| |  _/ _` / _` / -_) | (__/ _ \ / _ \ '_| |_ / -_) '_|
 |___/\___/_|  \__|\_/\_/\__,_|_| \___| |_||_\___|_| |_|\__\__,_\__, \___|  \___\___/_\___/_| |_/__\___|_|  
                                                                |___/

Run `help` `?` for help about available commands.
By default, runs python code. If prepended by `!`, run as a system command.
"""

    def _prompt(self):
        self.prompt = "(graph: %s, vulns: %s) |> " % (
            self.graph_file, self.vuln_file)

    def _wrap(self, fn):
        try:
            fn()
            self._prompt()
        except Exception as e:
            print("%s: %s" % (type(e), str(e)))

    def emptyline(self):
        pass

    def do_graph(self, file):
        'Load graph from parquet file in `data` dir'
        def fn():
            self.graph_file = file
            self.g = CommitGraph.loadf("data/%s" % file)
        return self._wrap(fn)

    def do_vulns(self, file):
        'Load vulnerability list from csv file in `data` dir'
        def fn():
            self.vuln_file = file
            self.vulns = OSV("data/%s" % file)
        return self._wrap(fn)

    def do_load(self, files):
        'Load data from files'
        def fn():
            for file in files.split(' '):
                ext = file.split(".")[-1]
                if ext == "parquet":
                    self.do_graph(file)
                elif ext == "csv":
                    self.do_vulns(file)
                else:
                    raise Exception("Unknown data type %s" % file)
        return self._wrap(fn)

    def do_save(self, file):
        'Save vulnerabilities dictionary to JSON file in `data` dir'
        def fn():
            with open("data/%s" % file, "w") as f:
                json.dump(self.g.vulns, f)
        return self._wrap(fn)

    def do_color(self, _):
        'Color commit graph with vulnerabilities'
        def fn():
            for _, vuln in self.vulns.git.iterrows():
                self.g.colorize(vuln)
        return self._wrap(fn)

    def do_search(self, sha):
        'Get vulnerabilities associated to commit'
        def fn():
            print(self.g.vulns.get(sha, []))
        return self._wrap(fn)

    def do_import(self, module):
        'Import a python module'
        def fn():
            self.mods[module] = importlib.import_module(module)
            print("Module %s made availe as self.mods.%s" % (module, module))
        return self._wrap(fn)

    def complete_graph(self, text, line, begidx, endidx):
        res = [s for s in self.graph_files if s.startswith(text)]
        return res

    def complete_vulns(self, text, line, begidx, endidx):
        res = [s for s in self.vuln_files if s.startswith(text)]
        return res

    def complete_load(self, text, line, begidx, endidx):
        return self.complete_graph(text, line, begidx, endidx) + self.complete_vulns(text, line, begidx, endidx)

    def default(self, cmd):
        'By default, run python code. If prepended by `!`, run as a system command'
        try:
            if cmd.startswith("!"):
                os.system(cmd[1:])
            else:
                self.mem = eval(cmd)
                print(self.mem)
        except Exception as e:
            print("Error: %s" % str(e))

    def do_exit(self, _):
        'Exit shell'
        print("Goodbye !")
        return True
    do_EOF = do_exit


if __name__ == '__main__':
    MyPrompt().cmdloop()
