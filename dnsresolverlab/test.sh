#!/bin/bash

counter=1

until [ $counter -gt 100 ]
do
	echo
	echo Test: $counter
	make test
	((counter++))
done
