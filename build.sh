SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ] ; do SOURCE="$(readlink "$SOURCE")"; done
SDIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
cd $SDIR

CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "app"

