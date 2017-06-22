FILE=$1

echo ""
echo "Scanning IPs: {zmeu|masscan|python|perl|curl|black|mui|jorgee}"
echo "====================================="
cat $FILE | egrep -a -i "zmeu|masscan|python|perl|curl|black|mui|jorgee" | egrep -o "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | sort -u

echo ""
echo "HTTP urls (object):"
echo "====================================="
cat $FILE | egrep -o "http://[ a-z:/0-9A-Z.-+]*" | sort -u | cut -d " " -f 2 | sort -u

echo ""
echo "WGET/FTP (objects):"
echo "====================================="
cat $FILE | egrep -o "wget[ a-z:/0-9.A-Z-]*" | sort -u | cut -d " " -f 2

echo ""
echo "cmd= (objects):"
echo "====================================="
cat $FILE | egrep -o "cmd=[ a-z:i/A-Z0-9.%'-]*" | sort -u
