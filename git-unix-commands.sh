Usage(){
	echo "Usage:"
	echo "$0 <operation>"
	echo "Available operation:"
	echo "	      -c Git Clone"
	echo "	      -d Git Diff"
	echo "	      -l Git Log"
	echo "	      -f Git Fetch"
	echo "	      -p Git Pull"
	echo "	      -ps Git Push"
	echo "	      -m Set Commit Message"
	exit 1
}

message="no message"
operation=""

if [ "$#" -eq 0 ]; then
    Usage
fi

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -c|-d|-l|-f|-p|-ps)
            operation="$1"
            shift
            ;;
        -m)
            message="$2"
            shift 2
            ;;
        *)
            Usage
            ;;
    esac
done

case "$operation" in
	-c)
		echo "You chose - Git Clone"
		git -c core.quotepath=false --no-optional-locks clone https://github.com/TaiwanMiya/Ais.IO.git ./
		;;
	-d)
		echo "You chose - Git Diff"
		git -c core.quotepath=false --no-optional-locks --no-pager diff
		;;
	-l)
		echo "You chose - Git Log"
		git -c core.quotepath=false --no-optional-locks --no-pager log
		;;
	-f)
		echo "You chose - Git Fetch"
		git -c core.quotepath=false --no-optional-locks fetch -v --tags origin
		git -c core.quotepath=false --no-optional-locks rev-parse HEAD @{u}
		;;
	-p)
		echo "You chose - Git Pull"
		git -c core.quotepath=false --no-optional-locks reset --hard origin/master
		git -c core.quotepath=false --no-optional-locks clean -fd
		git -c core.quotepath=false --no-optional-locks pull
		;;
	-ps)
		echo "You chose - Git Push"
		git -c core.quotepath=false --no-optional-locks add -f -- .
		git -c core.quotepath=false --no-optional-locks commit -v -q -m "$message"
		git -c core.quotepath=false --no-optional-locks push -v --tags origin master:master
		;;
	*)
		Usage
		;;
esac
