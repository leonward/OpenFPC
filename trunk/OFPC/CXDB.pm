package OFPC::CXDB;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);
use Date::Simple ('date', 'today');
use Getopt::Long qw/:config auto_version auto_help/;
use OFPC::Config;
use OFPC::Common;
use Data::Dumper;
use DBI;
use Switch;
require Exporter;

@EXPORT = qw(ALL);
$VERSION = '0.1';



=head2 wantdebug
	Check if debug is enabled via a shell variable OFPCDEBUG=1
	If so, return a value that enables debug in this function.
=cut
	
sub wantdebug{
	my $var="OFPCDEBUG";
	my $debug=$ENV{$var}; 
	return($debug); 
}

=head2 cx_search
	Search over the connection DB and return a href of results;

=cut

sub cx_search{
	my $dbname=shift;
	my $dbuser=shift;
	my $dbpass=shift;
	my $r=shift;
	my $debug=wantdebug();
	my $t;

	unless ($r->{'stime'} and $r->{'etime'}) {
		print "DEBUG: No time set, instead using default time window of 1 hour\n" if ($debug);
		$r->{'etime'} = time();
		$r->{'stime'} = $r->{'etime'}-3600;
		print "     : Start time: $r->{'stime'} (" . localtime($r->{'stime'}) . ")\n" if $debug;
		print "     : End time  : $r->{'etime'} (" . localtime($r->{'etime'}) . ")\n" if $debug;
	}

	my $q=buildQuery($r);
	print "DEBUG: Query is $q\n" if $debug;

	($t)=getresults($dbname, $dbuser, $dbpass, $q);

	my @cols = ("Time", "Source IP", "sPort", "Destination", "dPort", "Proto", "src_bytes", "dst_bytes", "total_bytes"); 
	my @format = (22,   18,           8,       18,            8,      8,        14,          14,          14);
	$t->{'title'} = "Custom Search";
	$t->{'type'} = "search";
	$t->{'cols'} = [ @cols ];
	$t->{'format'} = [ @format ];
	$t->{'stime'} = $r->{'stime'};
	$t->{'etime'} = $r->{'etime'};
	$t->{'nodename'} = $config{'NODENAME'};
	return($t);
}


=head2 buildQuery

 Build query to the cxdb.
 Takes inputs: 
 	request hash (contains search constraints)
 Returns:
  $QUERY

=cut

sub buildQuery {
	my $r=shift;
	my $debug=wantdebug();
	#my ($SRC_IP,$SRC_PORT,$DST_IP,$DST_PORT,$PROTO,$FROM_DATE,$TO_DATE,$LIMIT,$DEBUG) = @_;
	my $today = today();
	my $weekago = $today - 7;
	my $yesterday = $today->prev;
	my $DLIMIT=100;
	my $SRC_IP = $r->{'sip'} if $r->{'sip'};
	my $DST_IP = $r->{'dip'} if $r->{'dip'};
	my $SRC_PORT = $r->{'spt'} if $r->{'spt'};
	my $DST_PORT = $r->{'dpt'} if $r->{'dpt'};
	my $PROTO = $r->{'proto'} if $r->{'proto'};
	my $LIMIT = $r->{'limit'} if $r->{'limit'};	
	print "We have $LIMIT\n";
	my $QUERY = q();

	$QUERY = qq[SELECT start_time,INET_NTOA(src_ip),src_port,INET_NTOA(dst_ip),dst_port,ip_proto,src_bytes, dst_bytes,(src_bytes+dst_bytes) as total_bytes\
	            FROM session IGNORE INDEX (p_key) WHERE ];

	if ( $r->{'stime'} =~ /^\d+$/) {
	   $QUERY = $QUERY . "unix_timestamp(start_time) between $r->{'stime'} and $r->{'etime'} ";

	}

	if (defined $SRC_IP && $SRC_IP =~ /^([\d]{1,3}\.){3}[\d]{1,3}$/) {
	  print "Source IP is: $SRC_IP\n" if $debug;
	  $QUERY = $QUERY . qq[AND INET_NTOA(src_ip)='$SRC_IP' ];
	}

	if (defined $SRC_PORT && $SRC_PORT =~ /^([\d]){1,5}$/) {
	  print "Source Port is: $SRC_PORT\n" if $debug;
	  $QUERY = $QUERY . qq[AND src_port='$SRC_PORT' ];
	}

	if (defined $DST_IP && $DST_IP =~ /^([\d]{1,3}\.){3}[\d]{1,3}$/) {
	  print "Destination IP is: $DST_IP\n" if $debug;
	  $QUERY = $QUERY . qq[AND INET_NTOA(dst_ip)='$DST_IP' ];
	}

	if (defined $DST_PORT && $DST_PORT =~ /^([\d]){1,5}$/) {
	  print "Destination Port is: $DST_PORT\n" if $debug;
	  $QUERY = $QUERY . qq[AND dst_port='$DST_PORT' ];
	}

	if (defined $PROTO && $PROTO =~ /^([\d]){1,3}$/) {
	  print "Protocol is: $PROTO\n" if $debug;
	  $QUERY = $QUERY . qq[AND ip_proto='$PROTO' ];
	}

	if (defined $LIMIT && $LIMIT =~ /^([\d])+$/) {
	  print "Limit: $LIMIT\n" if $debug;
	  $QUERY = $QUERY . qq[ORDER BY start_time LIMIT $LIMIT ];
	} else {
	  print "Limit: $DLIMIT\n" if $debug;
	  $QUERY = $QUERY . qq[ORDER BY start_time LIMIT $DLIMIT ];
	}

	print "\nmysql> $QUERY;\n\n" if $debug;
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
        -Leon Ward - 2010
=cut

sub getctxsummary{
	my $dbname = shift;
	my $dbuser = shift;
	my $dbpass = shift;
	my $type = shift;		# Type of connection summary
	my $stime = shift;		# Start time for summary
	my $etime = shift;		# End time for summary
	my $limit = shift;		# Return top $limit results
	my $debug=wantdebug();	# Print debug data
	my @table=();			# Data returned to caller
	my $error="None";		# Error text
	my $t={
		error => 0,
		stime => 0,
		etime => 0,
		title => "Untitled",
		name => 0,
	};



	if ($debug) {
		print "DEBUG: getctxsummary \n" .
			"     : DB Name = $dbname \n" .
			"     : DB User = $dbuser \n" .
			"     : DB Pass = $dbpass \n" .
			"     : Table = $type \n" .
			"     : Start time = $stime (" . localtime($stime) . ")\n" .
			"     : End time   = $stime (" . localtime($etime) . ")\n" ;
	}

	# If stime/etime are not specified, use a default value of one hour
	unless ($stime and $etime) {
		print "DEBUG: No time set, instead using default time window of 1 hour\n" if ($debug);
		$etime = time();
		$stime = $etime-3600;
		print "     : Start time: $stime (" . localtime($stime) . ")\n" if $debug;
		print "     : End time  : $etime (" . localtime($etime) . ")\n" if $debug;
	}

	lc $type;
	switch ($type) {
		case "top_source_ip_by_connection" {
			($t)=getresults(
				$dbname,
				$dbuser,
				$dbpass, 
				"SELECT inet_ntoa(src_ip) AS source, COUNT(src_ip) AS count FROM session \
					where unix_timestamp(start_time) between $stime and $etime \
					GROUP BY src_ip ORDER BY count DESC LIMIT $limit");
			unshift(@table, [ "Source IP", "Session Count" ]);
			my @cols = ("Source IP", "Sessions"); 
			$t->{'title'} = "Top Source IPs by Session Count";
			$t->{'type'} = $type;
			$t->{'cols'} = [ @cols ];
			$t->{'len'} = 15;
		}
		# THIS ONE
		case "top_source_ip_by_volume" {
			($t)=getresults(
				$dbname,
				$dbuser,
				$dbpass, 
				"SELECT inet_ntoa(src_ip) AS source_ip, SUM(dst_bytes+src_bytes) AS bytes FROM session \
					where unix_timestamp(start_time) between $stime and $etime \
					GROUP BY source_ip ORDER BY bytes DESC LIMIT $limit");
			my @cols = ("Source IP", "Bytes"); 
			$t->{'title'} = "Top Source IPs by Traffic Volume";
			$t->{'type'} = $type;
			$t->{'cols'} = [ @cols ];
			$t->{'len'} = 15;
		} 
		case "top_destination_ip_by_connection" {
			($t)=getresults(
				$dbname,
				$dbuser,
				$dbpass, 
				"SELECT inet_ntoa(dst_ip) AS source, COUNT(dst_ip) AS count FROM session \
					where unix_timestamp(start_time) between $stime and $etime \
					GROUP BY dst_ip ORDER BY count DESC LIMIT $limit");
			my @cols = ("Source IP", "Sessions"); 
			$t->{'title'} = "Top Destiation IPs by Session Count";
			$t->{'type'} = $type;
			$t->{'cols'} = [ @cols ];
			$t->{'len'} = 15;
		}
		case "top_destination_ip_by_volume" {
			($t)=getresults(
				$dbname,
				$dbuser,
				$dbpass, 
				"SELECT inet_ntoa(dst_ip) AS dest_ip, SUM(dst_bytes+src_bytes) AS bytes FROM session \
					where unix_timestamp(start_time) between $stime and $etime \
					GROUP BY dest_ip ORDER BY bytes DESC LIMIT $limit");
			my @cols = ("Destination IP", "Volume"); 
			$t->{'title'} = "Top Destiation IPs by Traffic Volume ";
			$t->{'type'} = $type;
			$t->{'cols'} = [ @cols ];
			$t->{'len'} = 15;
		}
		case "top_source_tcp_by_connection"{
			($t)=getresults(
				$dbname,
				$dbuser,
				$dbpass, 
        			"SELECT src_port AS spt, COUNT(src_port) AS count FROM session \
					WHERE ip_proto=6 \
					AND unix_timestamp(start_time) between $stime and $etime \
					GROUP BY src_port ORDER BY count DESC LIMIT $limit");
			my @cols = ("Source TCP Port", "Sessions"); 
			$t->{'title'} = "Top Destiation IPs by Traffic Volume ";
			$t->{'type'} = $type;
			$t->{'cols'} = [ @cols ];
			$t->{'len'} = 15;
		}
		case "top_source_tcp_by_volume" {
			($t)=getresults(
				$dbname,
				$dbuser,
				$dbpass, 
				"SELECT src_port AS spt, SUM(dst_bytes+src_bytes) as bytes from session \
					WHERE ip_proto=6 \
					AND unix_timestamp(start_time) between $stime and $etime \
					GROUP BY src_port ORDER BY bytes DESC limit 20");
			unshift(@table, [ "Source TCP Port", "Bytes" ]);
			my @cols = ("Source TCP Port", "Bytes"); 
			$t->{'title'} = "Top Source TCP ports by Traffic Volume ";
			$t->{'type'} = $type;
			$t->{'cols'} = [ @cols ];
			$t->{'len'} = 15;
		}
		case "top_destination_tcp_by_connection" {
			($t)=getresults(
				$dbname,
				$dbuser,
				$dbpass, 
        			"SELECT dst_port AS dpt, COUNT(dst_port) AS count FROM session \
					WHERE ip_proto=6 \
					AND unix_timestamp(start_time) between $stime and $etime \
					GROUP BY dst_port ORDER BY count DESC LIMIT $limit");

			my @cols = ("Dest TCP Port", "Sessions"); 
			$t->{'title'} = "Top destination TCP ports by Volume";
			$t->{'type'} = $type;
			$t->{'cols'} = [ @cols ];
			$t->{'len'} = 15;
		}
		case "top_destination_tcp_by_volume" {
			($t)=getresults(
				$dbname,
				$dbuser,
				$dbpass, 
				"SELECT dst_port AS dpt, SUM(dst_bytes+src_bytes) as bytes from session \
					WHERE ip_proto=6 \
					AND unix_timestamp(start_time) between $stime and $etime \
					GROUP BY dst_port ORDER BY bytes DESC limit 20");
			my @cols = ("Dest TCP Port", "Bytes"); 
			$t->{'title'} = "Top destination TCP ports by Volume";
			$t->{'type'} = $type;
			$t->{'cols'} = [ @cols ];
			$t->{'len'} = 15;
		}
		case "top_destination_udp_by_connection" {
			($t)=getresults(
				$dbname,
				$dbuser,
				$dbpass, 
        			"SELECT dst_port AS dpt, COUNT(dst_port) AS count FROM session \
					WHERE ip_proto=17 \
					AND unix_timestamp(start_time) between $stime and $etime \
					GROUP BY dst_port ORDER BY count DESC LIMIT $limit");
			my @cols = ("Dest UDP Port", "Sessions"); 
			$t->{'title'} = "Top destination UDP ports by connection";
			$t->{'type'} = $type;
			$t->{'cols'} = [ @cols ];
			$t->{'len'} = 15;
		}
		case "top_destination_udp_by_volume" {
			($t)=getresults(
				$dbname,
				$dbuser,
				$dbpass, 
				"SELECT dst_port AS dpt, SUM(dst_bytes+src_bytes) as bytes from session \
					WHERE ip_proto=17 \
					AND unix_timestamp(start_time) between $stime and $etime \
					GROUP BY dst_port ORDER BY bytes DESC limit 20");
			my @cols = ("Dest UDP Port", "Bytes"); 
			$t->{'title'} = "Top destination UDP ports by Volume";
			$t->{'type'} = $type;
			$t->{'cols'} = [ @cols ];
			$t->{'len'} = 15;
		}
		case "top_source_udp_by_connection" {
			($t)=getresults(
				$dbname,
				$dbuser,
				$dbpass, 
        			"SELECT src_port AS spt, COUNT(src_port) AS count FROM session \
					WHERE ip_proto=17 \
					AND unix_timestamp(start_time) between $stime and $etime \
					GROUP BY src_port ORDER BY count DESC LIMIT $limit");
			my @cols = ("Source UDP Port", "Sessions"); 
			$t->{'title'} = "Top Source UDP ports by session count";
			$t->{'type'} = $type;
			$t->{'cols'} = [ @cols ];
			$t->{'len'} = 15;

		}
		case "top_source_udp_by_volume" {
			($t)=getresults(
				$dbname,
				$dbuser,
				$dbpass, 
				"SELECT src_port AS spt, SUM(dst_bytes+src_bytes) as bytes from session \
					WHERE ip_proto=17 \
					AND unix_timestamp(start_time) between $stime and $etime \
					GROUP BY src_port ORDER BY bytes DESC limit 20");
			my @cols = ("Source UDP Port", "Bytes"); 
			$t->{'title'} = "Top Source UDP ports by volume";
			$t->{'type'} = $type;
			$t->{'cols'} = [ @cols ];
			$t->{'len'} = 15;


		}
		else {
			$t->{'error'}="Invalid table type: $type\n";
			print "ERROR: Invalid table type $type\n" if ($debug);
		}	
	}


	# Add time details to the table hash that is sent to the client
	$t->{'stime'} = $stime;
	$t->{'etime'} = $etime;
	$t->{'slocaltime'} = localtime($stime);
	$t->{'elocaltime'} = localtime($etime);

	#if ($debug){
	#	print "DEBUG: getctxsummary results\n";
	#	print Dumper $t;
	#	print "-----------------------------\n";
	#}

	return($t);

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
	my $debug=wantdebug();
	my @results=();
	my $error=0;

	my %t=(
		size => 0,
		table => {},
		error => 0,
		);


	if ($debug) {
		print "DEBUG getresults \n" .
			"     : DB Name = $dbname \n" .
			"     : DB User = $dbuser \n" .
			"     : DB Pass = $dbpass \n" .
			"     : Query = $query\n";
	}

	if (my $dbh= DBI->connect("dbi:mysql:database=$dbname;host=localhost",$dbuser,$dbpass)) {
		print "DEBUG: Connected to DB\n" if ($debug);
		if (my $query=$dbh->prepare($query)) {
            if ($query->execute()) {
           		my @row;
           		my $rnum=0;
             	while ( @row = $query->fetchrow_array ) {
	           		$t{'table'}{$rnum} = [ @row ];			# Add row to hash
             		$rnum++;
					if ($debug){
						foreach (@row) {
							printf '%20s', "$_";
							print " | ";
						}

					print "\n";
					print "Row $rnum";
					#%t{$rnum} = @row;
					}
					push @results, [@row];		# Add this row to the Results AoA
				}
				$t{'size'}=$rnum;
            } else {
				$error="Unable to exec query\n"; #XXX delete
				$t{'error'}="Unable to exec query\n";
			}
	   	} else {
			$error="Unable to prep query $DBI::errstr\n"; # XXX
			$t{'error'}="Unable to prep query\n";	
		}
		$dbh->disconnect or print "Unable to disconnect from DB $DBI::errstr";
	} else {
		print "DEBUG: Error: Unable to connect to DB - $dbname, $dbuser, $dbpass\n" if ($debug);	
		$t{'error'}="Unable to connect to database\n";	
	}

	return(\%t);

}




1;
