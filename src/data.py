#!/usr/bin/env python3
import sys
import pandas as pd

def load(csv):
    return pd.read_csv(csv)

def main(args):
    df = load(args[0])
    total = len(df)
    git_count = len(df[df["Type"]=="GIT"])
    ecosystem_count = len(df[df["Type"]=="ECOSYSTEM"])
    semver_count = len(df[df["Type"]=="SEMVER"])
    print(df)
    print("Found %d ranges" % total)
    print("%d (%.2f%%) are git ranges" % (git_count, git_count * 100 / total))
    print("%d (%.2f%%) are ecosystem ranges" % (ecosystem_count, ecosystem_count * 100 / total))
    print("%d (%.2f%%) are semver ranges" % (semver_count, semver_count * 100 / total))

if __name__ == "__main__":
    main(sys.argv[1:])
