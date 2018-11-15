#!/bin/sh

for testFile in public_basic_tests/*.json
do
   python tool.py ${testFile}
   #echo "${file#.*}"
  
#  echo ${fileName}
#  myOutput = "outputs/${fileName}.myoutput.json"
#  testOutput = "outputs/${fileName}.output.json"
#  diff ${myOutput} ${testOutput}
done

