import pandas as pd

class OSV:
    def __init__(self, file):
        self.all = pd.read_csv(file)
        self.git = self.all[self.all.Type == "GIT"]
        self.closed = self.git[self.git.Start != "0"]
