#!/bin/sh
### BEGIN INIT INFO
# Provides:          aims
# Required-Start:    $network $local_fs
# Required-Stop:
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Advanced iptables management script
# Description:       aims provides an alternative to configuring iptables
#                    firewalls
### END INIT INFO

# Author: Matt Ferris <matt@bueller.ca>

# PATH should only include /usr/* if it runs after the mountnfs.sh script
PATH=/sbin:/usr/sbin:/bin:/usr/bin
NAME=aims             # Introduce the short server's name here
BIN=/usr/bin/$NAME
SCRIPTNAME=/etc/init.d/$NAME

# Exit if the package is not installed
[ -x $BIN ] || exit 0

# Read configuration variable file if it is present
[ -r /etc/default/$NAME ] && . /etc/default/$NAME

# Exit unless the packge has been enabled
[ "$ENABLE" = "1" ] || exit 0

case "$1" in
  start)
	$BIN load /etc/aims/aims.rules
  ;;
  stop)
	$BIN unload
  ;;
  restart|force-reload)
	$0 stop
	$0 start
  ;;
  *)
	echo "Usage: $SCRIPTNAME {start|stop|restart}" >&2
	exit 3
	;;
esac
