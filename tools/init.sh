#!/bin/sh
set -e

echo "We will now set up a password for your new vault..."
curl --unix-socket ~/.resivault.sock -X POST -u admin --fail-with-body http://localhost/initialize
curl --unix-socket ~/.resivault.sock -X GET --fail-with-body http://localhost/status
echo
