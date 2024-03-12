#!/bin/bash

touch $t/foo.txt
cat $t/foo.txt

stat $t/foo.txt &> /dev/null

echo "Hello, world!" > $t/bar.txt
