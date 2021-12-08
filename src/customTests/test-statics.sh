#!/bin/bash
# this tests section 2.1's functionality, both with an invalid and valid case.
curl -v --path-as-is -0 "localhost:13945/testdir1/../../test.txt" #Invalid 
curl -v --path-as-is -0 "localhost:13945/test.txt"	# valid
