pcaps_dir=./input

for port in $(seq 1000 1999); do
	x=0
	for f in $(ls $pcaps_dir/*.pcap); do
		x=$(($x + $(tcpdump -nr "$f" dst port $port 2>&1 | grep -P '^\d' -c)))
	done
	echo "$port: $x"
done
