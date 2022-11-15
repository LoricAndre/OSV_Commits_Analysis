#!/usr/bin/env bash


ECOSYSTEMS=(Android
  crates.io
  Debian
  Go
  Hex
  Linux
  Maven
  npm
  NuGet
  OSS-Fuzz
  Packagist
  Pub
  PyPI
  RubyGems
  GitHub%20Actions
)

fetch() {
  ECOSYSTEMS=$@
  yes A | for ECOSYSTEM in ${ECOSYSTEMS}; do
    echo "Fetching data for ${ECOSYSTEM}"
    wget "https://osv-vulnerabilities.storage.googleapis.com/$ECOSYSTEM/all.zip" && \
      unzip -q all.zip && rm all.zip
  done
}

to_csv() {
  a=(${@})
  nargs=${#a[@]}
  fin=${a[@]::$nargs-1}
  fout=${a[$nargs-1]}
  make_headers $fout
  jq --raw-output '[.id, .aliases[0], .modified, .published] + (.affected[] | [.package.name, .package.ecosystem] + (.ranges[] | [.type] + (.events | [map(select(has("introduced")).introduced), map(select(has("fixed")).fixed)] | transpose[0]))) | @csv' $fin >> $fout
}

make_headers() {
  fout=$1
  echo "id,CVE,Modification Date,Publication Date,Package Name,Ecosystem,Type,Start,End" > $fout
}

# fetch ${ECOSYSTEMS[@]}
to_csv Data/*.json all.csv
