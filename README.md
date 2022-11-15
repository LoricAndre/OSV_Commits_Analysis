OSV.dev analysis
===

# SQLite
## Setup
```sql
.mode csv
.import all.csv OSV
```

## Results
```
sqlite> select count(*) from OSV where Type is 'GIT';
14185
sqlite> select count(*) from OSV where Type is 'GIT' and Start is 0;
4577
sqlite> select count(*) from OSV where Type is 'GIT' and Start is not 0;
9608
sqlite> select count(*) from OSV where Type is 'GIT' and End is 0;
0
sqlite> select count(*) from OSV where Type is 'GIT' and End is not 0;
14185
sqlite> select count(*) from OSV where Type is 'GIT' and Start is 0;
4577
sqlite> select count(id),Ecosystem from OSV where Type is 'GIT' group by Ecosystem;
10464,Linux
2549,OSS-Fuzz
1172,PyPI
sqlite> select count(id),Ecosystem from OSV where Type is 'GIT' and Start is 0 group by Ecosystem;
3402,Linux
9,OSS-Fuzz
1166,PyPI
sqlite> select count(id),Ecosystem from OSV where Start is 0 group by Ecosystem;
747,Debian:10
306,Debian:11
808,Debian:3.0
708,Debian:3.1
708,Debian:4.0
752,Debian:5.0
1155,Debian:6.0
1799,Debian:7
1826,Debian:8
1568,Debian:9
6,"GitHub Actions"
848,Go
15,Hex
3402,Linux
1925,Maven
204,NuGet
9,OSS-Fuzz
887,Packagist
2,Pub
4711,PyPI
330,RubyGems
458,crates.io
2057,npm
sqlite> select count(id) from OSV where Start is 0;
25231
sqlite> select count(id) from OSV where End is 0;
0
```
