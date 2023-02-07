#!/bin/bash 

make
rm result.txt

taskset -c 0 ./attacker >> result.txt &

for i in {0..144}
do
    echo "Leaking bit $i... "
    echo -e -n "Leaking bit $i: " >> result.txt
    sleep .01
    for j in {0..10}
    do
        taskset -c 0 ./victim $i &> /dev/null
    done

    echo "" >> result.txt
done

python3 parseResult.py 

make clean
echo -e "killing attacker"
kill -9 $(pidof attacker)