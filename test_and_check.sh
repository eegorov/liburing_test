#!/bin/bash
for x in $(find . -type f) ; do ( cat ${x} | nc 127.0.0.1 8000 > ${x}.cat & ) ; done ; sleep 60 ; killall nc
for x in $(find -name '*.cat') ; do orig_file=$(echo ${x} | sed -e "s/.cat$//"); diff -u ${x} ${orig_file} ; done
