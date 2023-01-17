OSV.dev analysis
===

## Setup

### Data

Run `make data/swh.db` to fetch the data from OSV and add it to the database, creating a csv file at `data/osv.csv`.

### `graph-tool`
#### Shell
The shell is used to colorize graphs using parquet file and is not optimized for large graphs.

#### Requirements
The shell and more specifically `utils/pq_graph.py` require `graph-tool`. As this is a package not available through `pip`, a docker image is used for this module.

#### Data
The shell uses a parquet file for the commit graph and a csv for the vulnerabilities.

#### Run
To run these files, run `make build` to build the docker image, then `make shell` or `make src/xxx.py` to run it in the docker container.


### gRPC
#### `graph.py`
This script will create a database of commit <-> vulnerability associations using a gRPC server and the vulnerabilities csv loaded into a sqlite table.

#### Requirements
The swh.graph module can raise errors during install, requiring `postgresql` and [cmph](https://github.com/zvelo/cmph/blob/master/INSTALL) installed.
These packages will be installed in the docker container, but if you want to avoid using it, you need to install them yourself.

#### Run
Simply run `make colorize` or `src/graph.py`.

## Stats

| Request | Result | Notes |
| - | - | - |
| All git ranges | 14185 |
| All incomplete git ranges | 4577 | 0-starting ranges |
| All complete git ranges | 9608 |
| | |
| Range count by ecosystem | | |
| Linux | 10464 |
| OSS-Fuzz | 2549 |
| PyPI | 1172 |
| | |
| Range count by ecosystem | | |
| Linux | 3402 |
| OSS-Fuzz | 9 |
| PyPI | 1166 |
| | |
| Number of ranges by year | | |
|2002|94
|2003|202
|2004|265
|2005|422
|2006|379
|2007|371
|2008|419
|2009|483
|2010|237
|2011|373
|2012|274
|2013|383
|2014|588
|2015|759
|2016|895
|2017|1428
|2018|2167
|2019|2052
|2020|4564
|2021|11520
|2022|17149
| | |
|Number of git ranges by year||
|2012|4
|2013|5
|2014|11
|2015|7
|2016|10
|2017|37
|2018|20
|2019|21
|2020|1186
|2021|4504
|2022|8380
|||
| Percentage of git ranges by year||
|2012|1%
|2013|1%
|2014|1%
|2015|0%
|2016|1%
|2017|2%
|2018|0%
|2019|1%
|2020|25%
|2021|39%
|2022|48%

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

# osv.dev API

```bash
curl -X POST -d \                                                                                      %  11:12
          '{"commit": "9de932c0458a608b1ac0c8fd174d1dd9adfb20b9"}' \
          "https://api.osv.dev/v1/query"
# {"vulns":[{"id":"PYSEC-2014-82","details":"FileSystemBytecodeCache in Jinja2 2.7.2 does not properly create temporary directories, which allows local users to gain privileges by pre-creating a temporary directory with a user's uid.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2014-1402.","aliases":["CVE-2014-0012"],"modified":"2021-08-27T03:22:05.027573Z","published":"2014-05-19T14:55:00Z","references":[{"type":"REPORT","url":"https://bugzilla.redhat.com/show_bug.cgi?id=1051421"},{"type":"WEB","url":"https://github.com/mitsuhiko/jinja2/pull/292"},{"type":"FIX","url":"https://github.com/mitsuhiko/jinja2/commit/acb672b6a179567632e032f547582f30fa2f4aa7"},{"type":"WEB","url":"http://seclists.org/oss-sec/2014/q1/73"},{"type":"WEB","url":"https://github.com/mitsuhiko/jinja2/pull/296"},{"type":"ADVISORY","url":"http://secunia.com/advisories/60738"},{"type":"WEB","url":"http://www.gentoo.org/security/en/glsa/glsa-201408-13.xml"},{"type":"ADVISORY","url":"http://secunia.com/advisories/56328"}],"affected":[{"package":{"name":"jinja2","ecosystem":"PyPI","purl":"pkg:pypi/jinja2"},"ranges":[{"type":"GIT","repo":"https://github.com/mitsuhiko/jinja2","events":[{"introduced":"0"},{"fixed":"acb672b6a179567632e032f547582f30fa2f4aa7"}]},{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.7.3"}]}],"versions":["2.0","2.0rc1","2.1","2.1.1","2.2","2.2.1","2.3","2.3.1","2.4","2.4.1","2.5","2.5.1","2.5.2","2.5.3","2.5.4","2.5.5","2.6","2.7","2.7.1","2.7.2"],"database_specific":{"source":"https://github.com/pypa/advisory-database/blob/main/vulns/jinja2/PYSEC-2014-82.yaml"}}],"schema_version":"1.3.0"},{"id":"PYSEC-2019-220","details":"In Pallets Jinja before 2.8.1, str.format allows a sandbox escape.","aliases":["CVE-2016-10745","GHSA-hj2j-77xm-mc5v"],"modified":"2021-11-22T04:57:52.929678Z","published":"2019-04-08T13:29:00Z","references":[{"type":"ARTICLE","url":"https://palletsprojects.com/blog/jinja-281-released/"},{"type":"FIX","url":"https://github.com/pallets/jinja/commit/9b53045c34e61013dc8f09b7e52a555fa16bed16"},{"type":"ADVISORY","url":"https://access.redhat.com/errata/RHSA-2019:1022"},{"type":"WEB","url":"http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00030.html"},{"type":"ADVISORY","url":"https://access.redhat.com/errata/RHSA-2019:1237"},{"type":"ADVISORY","url":"https://access.redhat.com/errata/RHSA-2019:1260"},{"type":"WEB","url":"https://usn.ubuntu.com/4011-1/"},{"type":"WEB","url":"https://usn.ubuntu.com/4011-2/"},{"type":"WEB","url":"http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00064.html"},{"type":"ADVISORY","url":"https://access.redhat.com/errata/RHSA-2019:3964"},{"type":"ADVISORY","url":"https://access.redhat.com/errata/RHSA-2019:4062"},{"type":"ADVISORY","url":"https://github.com/advisories/GHSA-hj2j-77xm-mc5v"}],"affected":[{"package":{"name":"jinja2","ecosystem":"PyPI","purl":"pkg:pypi/jinja2"},"ranges":[{"type":"GIT","repo":"https://github.com/pallets/jinja","events":[{"introduced":"0"},{"fixed":"9b53045c34e61013dc8f09b7e52a555fa16bed16"}]},{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.8.1"}]}],"versions":["2.0","2.0rc1","2.1","2.1.1","2.2","2.2.1","2.3","2.3.1","2.4","2.4.1","2.5","2.5.1","2.5.2","2.5.3","2.5.4","2.5.5","2.6","2.7","2.7.1","2.7.2","2.7.3","2.8"],"database_specific":{"source":"https://github.com/pypa/advisory-database/blob/main/vulns/jinja2/PYSEC-2019-220.yaml"}}],"schema_version":"1.3.0"}]}
```

L'API est stateful, la recherche se fait via l'API [Google Cloud Datastore](https://github.com/googleapis/python-ndb)
