FILE=$1

echo ""
echo "Scanning IPs:"
echo "====================================="
cat $FILE | egrep -a -i "{zmeu|masscan|python|perl|curl|black|mui}" | egrep -o "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | sort -u

echo ""
echo "HTTP urls (object):"
echo "====================================="
cat $FILE | egrep -o "http[a-zA-Z0-9./:]*" | sort -u | cut -d " " -f 2

echo ""
echo "WGET (objects):"
echo "====================================="
cat $FILE | egrep -o "wget [a-zA-Z0-9./:]*" | sort -u | cut -d " " -f 2

echo ""
echo "TFTP (objects):"
echo "====================================="
cat $FILE | egrep -o "tftp [ a-zA-Z0-9\.\-]*" | sort -u
