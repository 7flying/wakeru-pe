#!/bin/bash

if [ "$#" -ne 3 ]; then
    echo "Usage: " $0 "<input_file> <output_file>"
else
    INFILE=$1
    OUTFILE=$2
    objdump -d $INFILE|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|\
        cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ / /g'|\
        paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g' >> $OUTFILE
fi
