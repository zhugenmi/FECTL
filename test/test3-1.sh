start_time=$(date +%s.%N)
for i in `seq 100`
do
	cat test3-2.py | python
done
end_time=$(date +%s.%N)
elapsed_time=$(echo  "($end_time - $start_time) * 1000" | bc -l)
echo "Operation : $elapsed_time ms"
