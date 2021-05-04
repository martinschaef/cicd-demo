#!/bin/sh
mkdir -p owasp-benchmark/results

jq -rs 'reduce .[] as $item ({}; . * $item)' $(find . -type f -name "codeguru-results.json" )  > owasp-benchmark/results/combined.json

cd owasp-benchmark
mvn clean compile
./createScorecards.sh