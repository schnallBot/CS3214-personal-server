#!/bin/bash
# This tests section 2.2's functionality, the authenticator.
# the following requests showcase a correct and incorrect attempt at logging in.
curl -v -0 --path-as-is -H "Conent-Type:application/json" --data '{"username":"user0","password":"thepassword"}' localhost:13945/api/login
