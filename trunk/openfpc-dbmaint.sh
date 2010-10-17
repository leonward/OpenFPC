#!/bin/bash 

#########################################################################################
# Copyright (C) 2010 Leon Ward 
# openfpc-dbmaint.pl - Part of the OpenFPC - (Full Packet Capture) project
#
# Quick script to create an OpenFPC connection database.
#
# The mysql function source in addfuncs() came from edward@openfpc.org
# -Leon 
#########################################################################################
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#########################################################################################

function die
{
	echo ERROR: $1
	exit 1
}


function addfuncs
{
	# Create mysql IPv6 functions

	SQL="
use $SESSION_DB_NAME;
DELIMITER //
CREATE FUNCTION INET_ATON6(n CHAR(39))
RETURNS DECIMAL(39) UNSIGNED
DETERMINISTIC
BEGIN
    RETURN CAST(CONV(SUBSTRING(n FROM  1 FOR 4), 16, 10) AS DECIMAL(39))
                       * 5192296858534827628530496329220096 -- 65536 ^ 7
         + CAST(CONV(SUBSTRING(n FROM  6 FOR 4), 16, 10) AS DECIMAL(39))
                       *      79228162514264337593543950336 -- 65536 ^ 6
         + CAST(CONV(SUBSTRING(n FROM 11 FOR 4), 16, 10) AS DECIMAL(39))
                       *          1208925819614629174706176 -- 65536 ^ 5
         + CAST(CONV(SUBSTRING(n FROM 16 FOR 4), 16, 10) AS DECIMAL(39))
                       *               18446744073709551616 -- 65536 ^ 4
         + CAST(CONV(SUBSTRING(n FROM 21 FOR 4), 16, 10) AS DECIMAL(39))
                       *                    281474976710656 -- 65536 ^ 3
         + CAST(CONV(SUBSTRING(n FROM 26 FOR 4), 16, 10) AS DECIMAL(39))
                       *                         4294967296 -- 65536 ^ 2
         + CAST(CONV(SUBSTRING(n FROM 31 FOR 4), 16, 10) AS DECIMAL(39))
                       *                              65536 -- 65536 ^ 1
         + CAST(CONV(SUBSTRING(n FROM 36 FOR 4), 16, 10) AS DECIMAL(39))
         ;
END;
//

CREATE FUNCTION INET_NTOA6(n DECIMAL(39) UNSIGNED)
RETURNS CHAR(39)
DETERMINISTIC
BEGIN
  DECLARE a CHAR(39)             DEFAULT '';
  DECLARE i INT                  DEFAULT 7;
  DECLARE q DECIMAL(39) UNSIGNED DEFAULT 0;
  DECLARE r INT                  DEFAULT 0;
  WHILE i DO
    -- DIV doesnt work with nubers > bigint
    SET q := FLOOR(n / 65536);
    SET r := n MOD 65536;
    SET n := q;
    SET a := CONCAT_WS(':', LPAD(CONV(r, 10, 16), 4, '0'), a);

    SET i := i - 1;
  END WHILE;

  SET a := TRIM(TRAILING ':' FROM CONCAT_WS(':',
                                            LPAD(CONV(n, 10, 16), 4, '0'),
                                            a));

  RETURN a;

END;
//
DELIMITER ;	
"
	mysql -u$DBUSER -p$DBPASS -e "$SQL"
}

function config
{

	CONFIG=/etc/openfpc/openfpc.conf

	echo ---------------------------
	echo Reading configuration from $CONFIG
	source /etc/openfpc/openfpc.conf || die "Unable to read config file $CONFIG"
	echo ---------------------------
	echo Enter user/pass to connect to your local mysql server
	read -p "DB Username: " DBUSER
	read -p "DB Password: " DBPASS
}

function create
{
	echo CREATING DATABASE
	echo ---------------------------
	# Test we have access
	mysql -u$DBUSER -p$DBPASS -e 'SHOW DATABASES;' > /dev/null || die "Unable to connect to database"

	# Check if DB already exists
	mysql -u$DBUSER -p$DBPASS -e "USE $SESSION_DB_NAME;" > /dev/null 2>&1 && die "Database $SESSION_DB_NAME already exists"

	# Create new DB	
	mysql -u$DBUSER -p$DBPASS -e "CREATE DATABASE $SESSION_DB_NAME;" > /dev/null 2>&1 || die "Unable to create DB $SESSION_DB_NAME"

	# Create new DB user
	mysql -u$DBUSER -p$DBPASS -e "use 'mysql'; CREATE USER '$SESSION_DB_USER'@'localhost' IDENTIFIED BY '$SESSION_DB_PASS';"
	mysql -u$DBUSER -p$DBPASS -e "use $SESSION_DB_NAME; GRANT ALL PRIVILEGES ON *.* TO '$SESSION_DB_USER'@'localhost';"
	echo Done.
}

function drop
{
	echo REMOVING DATABASE
	echo ---------------------------
	# Test we have access
	mysql -u$DBUSER -p$DBPASS -e 'SHOW DATABASES;' > /dev/null 2>&1 || die "Unable to connect to database"
	# Check if DB already exists
	mysql -u$DBUSER -p$DBPASS -e "USE $SESSION_DB_NAME;" > /dev/null 2>&1 || die "Database $SESSION_DB_NAME Not found!"
	mysql -u$DBUSER -p$DBPASS -e "DROP DATABASE $SESSION_DB_NAME;" > /dev/null 2>&1 || die "Database $SESSION_DB_NAME Not found!"
	mysql -u$DBUSER -p$DBPASS -e "use 'mysql'; DROP USER '$SESSION_DB_USER'@'localhost';" || die "Unable to remove user $SESSION_DB_USER"

	echo Done.
}
case $1 in 
	create)
		config
		create
		addfuncs
	;;

	drop)
		config
		drop
	;;
	clean)
	;;
	*)
		echo -e "Usage...."
		echo -e "openfpc-dbmaint.sh create DB and user"
		echo -e "openfpc-dbmaint.sh drop DB and user"

	;;

esac
