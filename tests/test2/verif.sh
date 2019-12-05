pcaps_dir=.

x=0
for f in $(ls $pcaps_dir/*.pcap); do
	x=$(($x + $(tcpdump -nr "$f" 2>&1 | grep -P '^\d' -c)))
done
echo "$x"
