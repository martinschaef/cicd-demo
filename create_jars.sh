#!/bin/sh
OWASP_DIR=./owasp-benchmark
OWASP_BUILD_DIR=$OWASP_DIR/target/classes
BY_CWE_DIR=./by-cwe

cd $OWASP_DIR
mvn compile -DskipTests
cd -

# Since OWASP is very big it will not be fully analyzed within 10 minutes and we would end up with a
# trunkated list of findings. To get the full list, we split it up into smaller jobs by cwe.
for FILE in packaging-hints/*.txt; do     
    CWE_NAME=$(basename $FILE .txt)
    CWE_DIR=$BY_CWE_DIR/$CWE_NAME

    echo "Copying $CWE_NAME to $CWE_DIR";
    mkdir -p $CWE_DIR
    # copy the properties files.
    cp $OWASP_BUILD_DIR/*.properties $CWE_DIR
    # copy the helper classes that are shared by all CWEs.
    mkdir -p $CWE_DIR/org/owasp/benchmark
    cp -r $OWASP_BUILD_DIR/org/owasp/benchmark/helpers $CWE_DIR/org/owasp/benchmark

    # copy the classes for each CWE.
    mkdir -p $CWE_DIR/org/owasp/benchmark/testcode
    while read p; do
      cp $OWASP_BUILD_DIR/$p $CWE_DIR/$p
    done < $FILE
done