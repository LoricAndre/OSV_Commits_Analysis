#!/usr/bin/env python3
from softwareHeritage import CommitGraph, OSV
from glob import glob
from cmd import Cmd
from tqdm import tqdm


class MyPrompt(Cmd):
    def __init__(self):
        super().__init__()
        self.data_files = glob("*.parquet", root_dir="data", recursive=True)
        self.data_file = "<>"
        self.vuln_files = glob("*.csv", root_dir="data", recursive=True)
        self.vuln_file = "<>"
        self._prompt()

    def _prompt(self):
        self.prompt = "(data: %s, vulns: %s) |> " % (
            self.data_file, self.vuln_file)

    def _wrap(self, fn):
        try:
            fn()
            self._prompt()
        except Exception as e:
            print("%s: %s" % (type(e), str(e)))

    def emptyline(self):
        pass

    def do_data(self, file):
        def fn():
            self.data_file = file
            self.g = CommitGraph.loadf("data/%s" % file)
        return self._wrap(fn)

    def do_vulns(self, file):
        def fn():
            self.vuln_file = file
            self.vulns = OSV("data/%s" % file)
        return self._wrap(fn)

    def do_load(self, files):
        def fn():
            for file in files.split(' '):
                ext = file.split(".")[-1]
                if ext == "parquet":
                    self.do_data(file)
                elif ext == "csv":
                    self.do_vulns(file)
                else:
                    raise Exception("Unknown data type %s" % file)
        return self._wrap(fn)

    def do_color(self, _):
        def fn():
            for _, vuln in tqdm(self.vulns.git.iterrows()):
                self.g.colorize(vuln)
        return self._wrap(fn)

    def do_search(self, sha):
        def fn():
            print(self.g.vulns.get(sha, []))
        return self._wrap(fn)

    def complete_data(self, text, line, begidx, endidx):
        res = [s for s in self.data_files if s.startswith(text)]
        return res

    def complete_vulns(self, text, line, begidx, endidx):
        res = [s for s in self.vuln_files if s.startswith(text)]
        return res

    def complete_load(self, text, line, begidx, endidx):
        return self.complete_data(text, line, begidx, endidx) + self.complete_vulns(text, line, begidx, endidx)

    def help_vulns(self):
        print("Load vulns csv file.")

    def help_data(self):
        print("Load parquet file.")

    def help_search(self):
        print("Search for commit and get vulns")

    def default(self, cmd):
        try:
            self.mem = eval(cmd)
            print(self.mem)
        except Exception as e:
            print("Error: %s" % str(e))

    def do_exit(self, _):
        print("Goodbye !")
        return True
    do_EOF = do_exit


if __name__ == '__main__':
    MyPrompt().cmdloop()
