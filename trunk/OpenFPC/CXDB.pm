package OpenFPC::CXDB;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);
use Date::Simple ('date', 'today');
use Getopt::Long qw/:config auto_version auto_help/;
use DBI;
use Switch;
require Exporter;

@EXPORT = qw(ALL);
$VERSION = '0.1';

=head2 cx_build_query

 Build query to the cxdb.
 Takes inputs: 
  $SRC_IP,$SRC_PORT,$DST_IP,$DST_PORT,$PROTO,$FROM_DATE,$TO_DATE,$LIMIT,$DEBUG
 Returns:
  $QUERY

=cut

sub cx_build_query {
   my ($SRC_IP,$SRC_PORT,$DST_IP,$DST_PORT,$PROTO,$FROM_DATE,$TO_DATE,$LIMIT,$DEBUG) = @_;
   my $today = today();
   my $weekago = $today - 7;
   my $yesterday = $today->prev;
   my $DLIMIT = 100;

   my $QUERY = q();
   $QUERY = qq[SELECT start_time,INET_NTOA(src_ip),src_port,INET_NTOA(dst_ip),dst_port,ip_proto,src_flags,dst_flags \
                FROM sessions IGNORE INDEX (p_key) WHERE ];

   if (defined $FROM_DATE && $FROM_DATE =~ /^\d\d\d\d\-\d\d\-\d\d$/) {
      print "Searching from date: $FROM_DATE 00:00:01\n" if $DEBUG;
      $QUERY = $QUERY . qq[start_time > '$FROM_DATE 00:00:01' ];
   } else {
      print "Searching from date: $yesterday\n" if $DEBUG;
      $QUERY = $QUERY . qq[start_time > '$yesterday' ];
   }

   if (defined $TO_DATE && $TO_DATE =~ /^\d\d\d\d\-\d\d\-\d\d$/) {
      print "Searching to date: $TO_DATE 23:59:59\n" if $DEBUG;
      $QUERY = $QUERY . qq[AND end_time < '$TO_DATE 23:59:59' ];
   }
   
   if (defined $SRC_IP && $SRC_IP =~ /^([\d]{1,3}\.){3}[\d]{1,3}$/) {
      print "Source IP is: $SRC_IP\n" if $DEBUG;
      $QUERY = $QUERY . qq[AND INET_NTOA(src_ip)='$SRC_IP' ];
   }
   
   if (defined $SRC_PORT && $SRC_PORT =~ /^([\d]){1,5}$/) {
      print "Source Port is: $SRC_PORT\n" if $DEBUG;
      $QUERY = $QUERY . qq[AND src_port='$SRC_PORT' ];
   }
   
   if (defined $DST_IP && $DST_IP =~ /^([\d]{1,3}\.){3}[\d]{1,3}$/) {
      print "Destination IP is: $DST_IP\n" if $DEBUG;
      $QUERY = $QUERY . qq[AND INET_NTOA(dst_ip)='$DST_IP' ];
   }
   
   if (defined $DST_PORT && $DST_PORT =~ /^([\d]){1,5}$/) {
      print "Destination Port is: $DST_PORT\n" if $DEBUG;
      $QUERY = $QUERY . qq[AND dst_port='$DST_PORT' ];
   }
   
   if (defined $PROTO && $PROTO =~ /^([\d]){1,3}$/) {
      print "Protocol is: $PROTO\n" if $DEBUG;
      $QUERY = $QUERY . qq[AND ip_proto='$PROTO' ];
   }
   
   if (defined $LIMIT && $LIMIT =~ /^([\d])+$/) {
      print "Limit: $LIMIT\n" if $DEBUG;
      $QUERY = $QUERY . qq[ORDER BY start_time LIMIT $LIMIT ];
   } else {
      print "Limit: $DLIMIT\n" if $DEBUG;
      $QUERY = $QUERY . qq[ORDER BY start_time LIMIT $DLIMIT ];
   }
   
   print "\nmysql> $QUERY;\n\n" if $DEBUG;
   return $QUERY;
}

=head2 cx_exec_query

 Takes a QUERY and db-info and executes it.
 Prints out the result.
 Takes Inputs:
  $dsn, $db_user_name, $db_password, $QUERY
 Returns:  (Needs to be implemented)
  N on success
  M on failure

=cut

sub cx_exec_query {
   my ($dsn, $db_user_name, $db_password, $QUERY) = @_;
   #my $dsn = 'DBI:mysql:openfpc:'.$db_host;

   my $dbh = DBI->connect($dsn, $db_user_name, $db_password);
   
   my $pri = $dbh->prepare( qq{ $QUERY } );
   $pri->execute();
   
   while (my ($starttime,$src_ip,$src_port,$dst_ip,$dst_port,$proto,$src_flags,$dst_flags) = $pri->fetchrow_array()) {
       next if not defined $src_ip or not defined $dst_ip;
       my $SFlags = tftoa($src_flags);
       my $DFlags = tftoa($dst_flags);
       printf("% 15s:%-5s -> % 15s:%-5s (%s) [%s|%s]\n",$src_ip,$src_port,$dst_ip,$dst_port,$proto,$SFlags,$DFlags);
   }
   
   $pri->finish();
   $dbh->disconnect();
}

=head2 tftoa

 Takes decimal representation of TCP flags,
 and returns ascii defined values.

=cut

sub tftoa {
    my $Flags = shift;
    my $out = "";

    $out .= "S" if ( $Flags & 0x02 );
    $out .= "A" if ( $Flags & 0x10 );
    $out .= "P" if ( $Flags & 0x08 );
    $out .= "U" if ( $Flags & 0x20 );
    $out .= "E" if ( $Flags & 0x40 );
    $out .= "C" if ( $Flags & 0x80 );
    $out .= "F" if ( $Flags & 0x01 );
    $out .= "R" if ( $Flags & 0x04 );

    return "-" if $out eq "";
    return $out;
}

=head2 getctxsummary
	Update connection summary data in DB
	Takes ($dbname, $dbuser, $dbpass, $summarytype, $starttime, $endtime, $limit)
	Returns ($success,$error_message, @AoA_of_results);
=cut

sub getctxsummary{
	my $dbname = shift;
	my $dbuser = shift;
	my $dbpass = shift;
	my $type = shift;		# Type of connection summary
	my $stime = shift;		# Start time for summary
	my $etime = shift;		# End time for summary
	my $limit = shift;		# Return top $limit results
	my $debug=0;			# Print debug data
	my @table=();			# Data returned to caller

	my $error="None";		# Error text

	if ($debug) {
		print "DEBUG: DB Name = $dbname \n" .
			"     : DB User = $dbuser \n" .
			"     : DB Pass = $dbpass \n" .
			"     : Table = $type \n" .
			"     : Start time = $stime (" . localtime($stime) . ")\n" .
			"     : End ime = $stime (" . localtime($etime) . ")\n" ;
	}

	# If stime/etime are not specified, use a default value of one hour
	unless ($stime and $etime) {
		print "DEBUG: Using default time window of 1 hour\n" if ($debug);
		$etime = time();
		$stime = $etime-3600;
	}

	lc $type;
	switch ($type) {
		case "top_source_ip_by_connection" {
			($error,@table)=getresults(
				$dbname,
				$dbuser,
				$dbpass, 
				"SELECT inet_ntoa(src_ip) AS source, COUNT(src_ip) AS count FROM session \
					where unix_timestamp(start_time) between $stime and $etime \
					GROUP BY src_ip ORDER BY count DESC LIMIT $limit");
			unshift(@table, [ "Source IP", "Session Count" ]);
		}
		case "top_source_ip_by_volume" {
			($error,@table)=getresults(
				$dbname,
				$dbuser,
				$dbpass, 
				"SELECT inet_ntoa(src_ip) AS source_ip, SUM(dst_bytes+src_bytes) AS bytes FROM session \
					where unix_timestamp(start_time) between $stime and $etime \
					GROUP BY source_ip ORDER BY bytes DESC LIMIT $limit");
			unshift(@table, [ "Source IP", "Bytes" ]);
		} 
		case "top_destination_ip_by_connection" {
			($error,@table)=getresults(
				$dbname,
				$dbuser,
				$dbpass, 
				"SELECT inet_ntoa(dst_ip) AS source, COUNT(dst_ip) AS count FROM session \
					where unix_timestamp(start_time) between $stime and $etime \
					GROUP BY dst_ip ORDER BY count DESC LIMIT $limit");
			unshift(@table, [ "Dest IP", "Session Count" ]);
		}
		case "top_destination_ip_by_volume" {
			($error,@table)=getresults(
				$dbname,
				$dbuser,
				$dbpass, 
				"SELECT inet_ntoa(dst_ip) AS dest_ip, SUM(dst_bytes+src_bytes) AS bytes FROM session \
					where unix_timestamp(start_time) between $stime and $etime \
					GROUP BY dest_ip ORDER BY bytes DESC LIMIT $limit");
			unshift(@table, [ "Dest IP", "Bytes" ]);
		}
		case "top_source_tcp_by_connection"{
			($error,@table)=getresults(
				$dbname,
				$dbuser,
				$dbpass, 
        			"SELECT src_port AS spt, COUNT(src_port) AS count FROM session \
					WHERE ip_proto=6 \
					AND unix_timestamp(start_time) between $stime and $etime \
					GROUP BY src_port ORDER BY count DESC LIMIT $limit");
			unshift(@table, [ "Source TCP Port", "Session Count" ]);
		}
		case "top_source_tcp_by_volume" {
			($error,@table)=getresults(
				$dbname,
				$dbuser,
				$dbpass, 
				"SELECT src_port AS spt, SUM(dst_bytes+src_bytes) as bytes from session \
					WHERE ip_proto=6 \
					AND unix_timestamp(start_time) between $stime and $etime \
					GROUP BY src_port ORDER BY bytes DESC limit 20");
			unshift(@table, [ "Source TCP Port", "Bytes" ]);
		}
		case "top_destination_tcp_by_connection" {
			($error,@table)=getresults(
				$dbname,
				$dbuser,
				$dbpass, 
        			"SELECT dst_port AS dpt, COUNT(dst_port) AS count FROM session \
					WHERE ip_proto=6 \
					AND unix_timestamp(start_time) between $stime and $etime \
					GROUP BY dst_port ORDER BY count DESC LIMIT $limit");
			unshift(@table, [ "Dest TCP Port", "Session Count" ]);
		}
		case "top_destination_tcp_by_volume" {
			($error,@table)=getresults(
				$dbname,
				$dbuser,
				$dbpass, 
				"SELECT dst_port AS dpt, SUM(dst_bytes+src_bytes) as bytes from session \
					WHERE ip_proto=6 \
					AND unix_timestamp(start_time) between $stime and $etime \
					GROUP BY dst_port ORDER BY bytes DESC limit 20");
			unshift(@table, [ "Dest TCP Port", "Bytes" ]);
		}
		case "top_destination_udp_by_connection" {
			($error,@table)=getresults(
				$dbname,
				$dbuser,
				$dbpass, 
        			"SELECT dst_port AS dpt, COUNT(dst_port) AS count FROM session \
					WHERE ip_proto=17 \
					AND unix_timestamp(start_time) between $stime and $etime \
					GROUP BY dst_port ORDER BY count DESC LIMIT $limit");
			unshift(@table, [ "Dest UDP Port", "Session Count" ]);
		}
		case "top_destination_udp_by_volume" {
			($error,@table)=getresults(
				$dbname,
				$dbuser,
				$dbpass, 
				"SELECT dst_port AS dpt, SUM(dst_bytes+src_bytes) as bytes from session \
					WHERE ip_proto=17 \
					AND unix_timestamp(start_time) between $stime and $etime \
					GROUP BY dst_port ORDER BY bytes DESC limit 20");
			unshift(@table, [ "Dest UDP Port", "Bytes" ]);

		}
		case "top_source_udp_by_connection" {
			($error,@table)=getresults(
				$dbname,
				$dbuser,
				$dbpass, 
        			"SELECT src_port AS spt, COUNT(spt_port) AS count FROM session \
					WHERE ip_proto=17 \
					AND unix_timestamp(start_time) between $stime and $etime \
					GROUP BY src_port ORDER BY count DESC LIMIT $limit");
			unshift(@table, [ "Source UDP Port", "Session Count" ]);

		}
		case "top_source_udp_by_volume" {
			($error,@table)=getresults(
				$dbname,
				$dbuser,
				$dbpass, 
				"SELECT src_port AS spt, SUM(dst_bytes+src_bytes) as bytes from session \
					WHERE ip_proto=17 \
					AND unix_timestamp(start_time) between $stime and $etime \
					GROUP BY src_port ORDER BY bytes DESC limit 20");
			unshift(@table, [ "Source UDP Port", "Bytes" ]);

		}
		case "top_session_by_time" {

		}
		case "top_session_by_volume" {

		}
		else {
			$error="Invalid summary table type $type\n";
			print "ERROR: Invalid table type $type\n" if ($debug);
		}	
	}

	unless ($error) {
		if ($debug){
			print "DEBUG: getctxsummary results\n";
			foreach my $row (@table) {
				foreach (@$row) {
						printf '%20s', "$_";
						print "|"
				}
				print "\n";
			}
			print "-----------------------------\n";
		}
		return(1,"Success",@table);
	} else {
		return(0,$error,0);
	}
}

=head2 getresults
	Get results from a query.
	Takes $dbname, $dbuser, $dbpass, SQL qeery
	Returns (@table, $error) 
=cut

sub getresults{
	my $dbname = shift;
	my $dbuser = shift;
	my $dbpass = shift;
	my $query = shift;
	my $debug=0;
	my @results=();
	my $error=0;

	if ($debug) {
		print "DEBUG: DB Name = $dbname \n" .
			"     : DB User = $dbuser \n" .
			"     : DB Pass = $dbpass \n" .
			"     : Query = $query\n";
	}

	if (my $dbh= DBI->connect("dbi:mysql:database=$dbname;host=localhost",$dbuser,$dbpass)) {
		print "DEBUG: Connected to DB\n" if ($debug);
		if (my $query=$dbh->prepare($query)) {
                	if ($query->execute()) {
           	     		my @row;
             	  	 	while ( @row = $query->fetchrow_array ) {
					if ($debug){
						foreach (@row) {
							printf '%20s', "$_";
							print " | ";
						}
						print "\n";
					}
					push @results, [@row];		# Add this row to the Results AoA
				}
                	} else {
				$error="Unable to exec query\n";
			}
	   	} else {
			$error="Unable to prep query $DBI::errstr\n";
		}
		$dbh->disconnect or print "Unable to disconnect from DB $DBI::errstr";
		return($error,@results);
	} else {
		print "DEBUG: Error: Unable to connect to DB - $dbname, $dbuser, $dbpass\n" if ($debug);	
		return($error,@results);
	}
}

1;
