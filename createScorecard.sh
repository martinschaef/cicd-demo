#!/bin/sh
mkdir -p owasp-benchmark/results
cp cwe022-findings/codeguru-results.json owasp-benchmark/results/022.json 2>/dev/null
cp cwe078-findings/codeguru-results.json owasp-benchmark/results/078.json 2>/dev/null
cp cwe079-findings/codeguru-results.json owasp-benchmark/results/079.json 2>/dev/null
cp cwe090-findings/codeguru-results.json owasp-benchmark/results/090.json 2>/dev/null
cp cwe327-findings/codeguru-results.json owasp-benchmark/results/327.json 2>/dev/null
cp cwe328-findings/codeguru-results.json owasp-benchmark/results/328.json 2>/dev/null
cp cwe614-findings/codeguru-results.json owasp-benchmark/results/614.json 2>/dev/null
cp cwe643-findings/codeguru-results.json owasp-benchmark/results/643.json 2>/dev/null

cd owasp-benchmark
mvn clean compile
./createScorecards.sh