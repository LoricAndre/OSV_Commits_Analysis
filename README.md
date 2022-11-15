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
# Number of ranges by year
sqlite> select substr(PublicationDate, 1, 4) as year,count(id) from OSV group by year;
2002,94
2003,202
2004,265
2005,422
2006,379
2007,371
2008,419
2009,483
2010,237
2011,373
2012,274
2013,383
2014,588
2015,759
2016,895
2017,1428
2018,2167
2019,2052
2020,4564
2021,11520
2022,17149
# Number of git ranges by year
sqlite> select substr(PublicationDate, 1, 4) as year,count(id) from OSV where Type is "GIT" group by year;
2012,4
2013,5
2014,11
2015,7
2016,10
2017,37
2018,20
2019,21
2020,1186
2021,4504
2022,8380
# Percentage of git ranges by year
sqlite> create table GIT_YEAR as select substr(PublicationDate, 1, 4) as year,count(id) as count from OSV where Type is "GIT" group by year;
sqlite> create table ALL_YEAR as select substr(PublicationDate, 1, 4) as year,count(id) as count from OSV group by year;
sqlite> select ALL_YEAR.year, (GIT_YEAR.count*100/ALL_YEAR.count) from GIT_YEAR join ALL_YEAR on GIT_YEAR.year = ALL_YEAR.year;
2012,1
2013,1
2014,1
2015,0
2016,1
2017,2
2018,0
2019,1
2020,25
2021,39
2022,48
```
