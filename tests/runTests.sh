#!/bin/bash

cwd=$(pwd)

cd ../build

# Prepare for tests by placing log files into build
cp ../tests/small.log small.log
mkdir many_small
cp small.log many_small/s1.log
cp small.log many_small/s2.log
mkdir many_small/nested/
cp small.log many_small/nested/s3.log
mkdir odd_format_small
# cp ../oddformat.log odd_format_small/oddformat.log
cp ../tests/small.log odd_format_small/small.log
mkdir net_log
cp ../tests/v5_small.log net_log/v5_small.log

numTests=0
numSuccess=0

# Run tests
for t in $(ls test_*); do
  # Reset the database folder
  rm -rf test/
  # Run the test
  eval "./$t 2>/dev/null" # Would prefer another way to do this
  status=$?
  # Track the success rate
  numTests=$((numTests+1))
  if [[ $status -eq 0 ]]; then
    numSuccess=$((numSuccess+1))
    echo "$t: PASSED"
  else
    echo "$t: FAILED"
  fi
done

# Report success rate
echo -e "\n\nPassed $numSuccess/$numTests tests\n"

# Clear all tests
rm -rf test/ testProcessed many_small/ net_log/ odd_format_small/ small.log

cd $cwd
