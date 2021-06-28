#!/bin/sh
mkdir -p owasp-benchmark/results

jq -rs '{findings: (([.[].runs[0].results]) | flatten)}' $(find . -type f -name "codeguru-results.sarif.json" )  > owasp-benchmark/results/combined.json

# Remove findings of other tools
rm owasp-benchmark/results/Benchmark_1.2-*.xml

# Copy the parser for the guru format into owasp.
cp finding_parser/AWSCodeGuruReader.java owasp-benchmark/src/main/java/org/owasp/benchmark/score/parsers/ 
cp finding_parser/BenchmarkScore.java owasp-benchmark/src/main/java/org/owasp/benchmark/score/

# Create the score card
cd owasp-benchmark
mvn clean compile
./createScorecards.sh
