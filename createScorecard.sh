#!/bin/sh
mkdir -p owasp-benchmark/results

jq -rs 'reduce .[] as $item ({}; . * $item)' $(find . -type f -name "codeguru-results.json" )  > owasp-benchmark/results/combined.json

rm owasp-benchmark/results/Benchmark_1.2-*.xml # remove findings of other tools
cd owasp-benchmark
mvn clean compile
./createScorecards.sh
