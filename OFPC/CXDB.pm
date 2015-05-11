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
use POSIX qw(strftime);
use JSON::PP;
use Socket qw(inet_aton inet_ntoa);

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

my $dbhost=$config{'SESSION_DB_HOST'};

sub cx_search{
	# Expects $config to be a global - read from the openfpc config file
	my $r=shift;
	my $dbname=$config{'SESSION_DB_NAME'};
	my $dbuser=$config{'SESSION_DB_USER'};
	my $dbpass=$config{'SESSION_DB_PASS'};
	my $debug=wantdebug();
	my $t;
	my $sc;	# Search container
	my $ltz=DateTime::TimeZone->new( name => 'local' )->name();

	unless ($r->{'stime'}{'val'} and $r->{'etime'}{'val'}) {
		print "DEBUG: No time set, instead using default time window of 1 hour\n" if ($debug);
		$r->{'etime'}{'val'} = time();
		$r->{'stime'}{'val'} = $r->{'etime'}{'val'}-3600;
		print "     : Start time: $r->{'stime'}{'val'} (" . localtime($r->{'stime'}{'val'}) . ")\n" if $debug;
		print "     : End time  : $r->{'etime'}{'val'} (" . localtime($r->{'etime'}{'val'}) . ")\n" if $debug;
	}

	unless ($config{'PROXY'}) {

		my $q=buildQuery($r);
		print "DEBUG: Query is $q\n" if $debug;

		($t)=getresults($dbname, $dbhost, $dbuser, $dbpass, $q);
		#print Dumper $t;
		# Format data types (@dtype)
		# "port" = Port number
		# "ip" = IP address
		# 'udt'	 = UTC date/time timestamp from mysql - will need to be converted into users local tz to make sense
		# 'bytes' = volume of data in bytes
		# 'protocol' = Protocol number, e.g. 17

		my @cols = ("Start Time", "Source IP", "sPort", "Destination", "dPort", "Proto", "Src Bytes", "Dst Bytes", "Total Bytes", "Node Name"); 
		my @format = (22,          18,          8,       18,            8,       8,       14,          14,          14,            20);
		my @dtype = ("udt", "ip", "port", "ip", "port","protocol","bytes", "bytes","bytes","text");
		$t->{'title'} = "Custom Search";
		$t->{'sql'} = $q;	# Save query made
		$t->{'type'} = "search";
		$t->{'cols'} = [ @cols ];
		$t->{'format'} = [ @format ];
		$t->{'dtype'} = [ @dtype ];
		$t->{'stime'} = $r->{'stime'}{'val'};
		$t->{'etime'} = $r->{'etime'}{'val'};
		$t->{'nodename'} = $config{'NODENAME'};
		# Put the search results hash into a container that can contain multiple results 
		push (@{$t->{'nodelist'}},$config{'NODENAME'});

	} else {

		wlog("Proxy session search");
		my $se;			# Search errors, to capture problems run on each node
		my $rc=0; 		# Total record count back from all Nodes
		# Grab some details about the query SQL made
		my $q=buildQuery($r);
		wlog("DEBUG: Query is $q") if $debug;
	    
	    my $dsn = "DBI:mysql:database=$config{'PROXY_DB_NAME'};
	    					host=$config{'PROXY_DB_HOST'}";

	    if (my $dbh = DBI->connect($dsn, $config{'PROXY_DB_USER'}, $config{'PROXY_DB_PASS'})) {
	    	wlog("SEARCH: DEBUG: Proxy connected to DB $config{'PROXY_DB_NAME'}");
			my $rt=OFPC::Common::readroutes();

			# Connect to DB and save the details of the proxied search
			my $now = strftime "%Y-%m-%d %H:%M:%S", localtime;
			my $sql = "INSERT INTO search 
				( timestamp, username, comment, search
					) values (?,?,?,?)";
  			my $sth = $dbh->prepare_cached($sql);
      		$sth->execute($now, $r->{'user'}{'val'},$r->{'comment'}{'val'},$q);


      		# Get last insert ID
      		$sql = "SELECT id from search order by id desc limit 1";
  			my $sth = $dbh->prepare_cached($sql);
      		$sth->execute();
      		my @row = $sth->fetchrow_array;
      		my $sid=@row[0];
      		wlog("PROXY: SEARCH: Saving search: Search_id: $sid, User: $r->{'user'}{'val'}, Timestamp: $now, Comment: $r->{'comment'}{'val'}");

			my $sc;
			foreach (keys %$rt) {

				# Connect to each node to search

				my $rn=$rt->{$_}{'name'};
				wlog("PROXY: SEARCH: $rn: Searching node $rn");

				#push (@{$sc{'nodelist'}},$config{'NODENAME'});
				push (@{$t->{'nodelist'}},$rt->{$_}{'name'});

				my $r2=OFPC::Request::mkreqv2();
				$r2=$r;
    			my $nodesock = IO::Socket::INET->new(
                                PeerAddr => $rt->{$_}{'ip'}, 
                                PeerPort => $rt->{$_}{'port'}, 
                                Proto => 'tcp',
                                );
    			if ($nodesock) {
    				wlog("PROXY: SEARCH: $rn: Connected to node $rt->{$_}{'name'}");
    				# Now passing the same user/passhash that was used to connect to this OpenFPC_Proxy
    				$r2->{'action'}{'val'} = "search";
    				my %result=OFPC::Request::request($nodesock,$r2);

    				unless ($result{'error'}) {

						my $tj=$result{'table'};
						if ($tj) {
							my $t=decode_json($tj);
	    					wlog("PROXY: SEARCH: $rn: DEBUG: Table size back from search is $t->{'size'} rows\n");
	    					$rc=$rc+$t->{'size'};
							my $i=0;
							while ($i < $t->{'size'}) {
								my @f = @{$t->{'table'}{$i}};  	# Assign table array to f to make this easier to read.
								$i++;
								# Change Sip / Dip into numbers for storage.
								# Socket aton returns a packed number. Need to unpack before saving to DB.
								$f[1] = inet_aton($f[1]);
								$f[1] = unpack('N', $f[1]);
								$f[3] = inet_aton($f[3]);
								$f[3] = unpack('N', $f[3]);
								# Save this session from the node to the proxy search database
								my $sql = "INSERT INTO session 
									( search_id, start_time, src_ip, src_port, dst_ip, dst_port, ip_proto, src_bytes, dst_bytes, total_bytes, node_name     
									) values (?,?,?,?,?,?,?,?,?,?,?)";
 								my $sth = $dbh->prepare_cached($sql);
    							$sth->execute($sid, $f[0], $f[1], $f[2], $f[3], $f[4], $f[5], $f[6], $f[7], $f[8], $f[9]);
							}	
							wlog("PROXY: SEARCH: $rn: Wrote $i results to db from node $rn");

    					} else {
    						my $e="$rn: Error, no json back from node. ";
    						wlog("PROXY: SEARCH: $e");
    						$se = $se . $e;
    					}
    				} else {
   						my $e="$rn: Error $result{'error'}";
   						wlog("PROXY: SEARCH: ERROR: $e. ");
   						$se = $se . $e;
    				}
	    		} else {
    				my $e="$rn: Error, unable to Connect to remote node. ";
    				wlog("PROXY: SEARCH: $e");
					$se = $se . $e;
    			}
    			wlog("PROXY: SEARCH: TOTAL: results from all nodes: $rc");
    		} 

    		# Now that the data is in the DB, we need to re-search this data set to build a json to send back 
    		# to the original client
	    	# Disconnect from  DB
    		$sth->finish;
			$dbh->disconnect;
			# CLEAN THIS UP

    		my $sql="SELECT start_time, inet_ntoa(src_ip), src_port, inet_ntoa(dst_ip), dst_port, ip_proto, src_bytes, dst_bytes, total_bytes, node_name, search_id from session where search_id=$sid order by start_time desc";
			(my $t)=getresults($config{'PROXY_DB_NAME'}, $config{'PROXY_DB_USER'}, $config{'PROXY_DB_PASS'}, $sql);
			#my @cols = ("Start Time", "Source IP", "sPort", "Destination", "dPort", "Proto", "Src Bytes", "Dst Bytes", "Total Bytes", "Node Name", "Search", "Proxy"); 
			#my @format = (22,         8,           8,       18,            8,        8,       14,          14,          14,            13,         5,         13);
			my @cols = ("Start Time", "Source IP", "sPort", "Destination", "dPort", "Proto", "S Bytes", "D Bytes", "Total", "Node Name", "Sid", "Proxy"); 
		    my @format = (20,          17,          6,       17,            6,       6,       10,          10,          10,            18,         5,         18);
			my @dtype = ("udt", "ip", "port", "ip", "port","protocol","bytes", "bytes","bytes","text","text");
			$t->{'title'} = "Proxy search over multiple nodes";
			$t->{'type'} = "search";
			$t->{'cols'} = [ @cols ];
			$t->{'format'} = [ @format ];
			$t->{'dtype'} = [ @dtype ];
			$t->{'stime'} = $r->{'stime'}{'val'};
			$t->{'etime'} = $r->{'etime'}{'val'};
			$t->{'nodename'} = $config{'NODENAME'};
			$t->{'sql'} = buildQuery($r);
			$t->{'warning'} = $se;
			return($t);
		} else {
			wlog("PROXY: ERROR: Unable to connect to local proxy DB to save results $DBI::errstr\n");
			$t->{'error'} = "Unable to connect to local proxy DB to save results. Check error log on $config{'NODENAME'} for more information.";
			wlog("-----\n");
			return($t);
		}
	}
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
	my $SRC_IP = $r->{'sip'}{'val'} if $r->{'sip'}{'val'};
	my $DST_IP = $r->{'dip'}{'val'} if $r->{'dip'}{'val'};
	my $SRC_PORT = $r->{'spt'}{'val'} if $r->{'spt'}{'val'};
	my $DST_PORT = $r->{'dpt'}{'val'} if $r->{'dpt'}{'val'};
	my $PROTO = $r->{'proto'}{'val'} if $r->{'proto'}{'val'};
	my $LIMIT = $r->{'limit'}{'val'} if $r->{'limit'}{'val'};	
	my $QUERY = q();
	wlog("QUERY: DEBUG: Building query") if $debug;
	$QUERY = qq[SELECT start_time,INET_NTOA(src_ip),src_port,INET_NTOA(dst_ip),dst_port,ip_proto,src_bytes, dst_bytes,(src_bytes+dst_bytes) as total_bytes\
	FROM session IGNORE INDEX (p_key) WHERE ];

	if ( $r->{'stime'}{'val'} =~ /^\d+$/) {
		# Note: Remember that sessions are stored in UTC, regardless of what TZ the local system is in
	   $QUERY = $QUERY . "unix_timestamp(CONVERT_TZ(`start_time`, '+00:00', \@\@session.time_zone))  
	between $r->{'stime'}{'val'} and $r->{'etime'}{'val'} ";

	}

	if (defined $SRC_IP && $SRC_IP =~ /^([\d]{1,3}\.){3}[\d]{1,3}$/) {
	  wlog("QUERY: DEBUG: Adding Source IP is: $SRC_IP") if $debug;
	  $QUERY = $QUERY . qq[AND INET_NTOA(src_ip)='$SRC_IP' ];
	}

	if (defined $SRC_PORT && $SRC_PORT =~ /^([\d]){1,5}$/) {
	  wlog("QUEDY: DEBUG: Source Port is: $SRC_PORT\n") if $debug;
	  $QUERY = $QUERY . qq[AND src_port='$SRC_PORT' ];
	}

	if (defined $DST_IP && $DST_IP =~ /^([\d]{1,3}\.){3}[\d]{1,3}$/) {
	  wlog("QUERY: DEBUG: Adding Destination IP: $DST_IP") if $debug;
	  $QUERY = $QUERY . qq[AND INET_NTOA(dst_ip)='$DST_IP' ];
	}

	if (defined $DST_PORT && $DST_PORT =~ /^([\d]){1,5}$/) {
	  wlog("QUERY: DEBUG: Adding Destination Port: $DST_PORT") if $debug;
	  $QUERY = $QUERY . qq[AND dst_port='$DST_PORT' ];
	}

	if (defined $PROTO && $PROTO =~ /^([\d]){1,3}$/) {
	  wlog("QUERY: DEBUG: Protocol is: $PROTO") if $debug;
	  $QUERY = $QUERY . qq[AND ip_proto='$PROTO' ];
	}

	if (defined $LIMIT && $LIMIT =~ /^([\d])+$/) {
	  wlog("QUERY: DEBUG: Result Limit: $LIMIT") if $debug;
	  $QUERY = $QUERY . qq[ORDER BY start_time DESC LIMIT $LIMIT];
	} else {
	  wlog("QUERY: DEBUG: No limit specified. Using a default value of $DLIMIT") if $debug;
	  $QUERY = $QUERY . qq[ORDER BY start_time DESC LIMIT $DLIMIT];
	}

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

=head2 getresults
	Get results from a query.
	Takes $dbname, $dbuser, $dbpass, SQL qeery
	Returns ($table, $error) 
=cut

sub getresults{
	my $dbname = shift;
	my $dbhost = shift;
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

	if (my $dbh= DBI->connect("dbi:mysql:database=$dbname:host=$dbhost",$dbuser,$dbpass)) {
		print "DEBUG: Connected to DB\n" if ($debug);
		if (my $query=$dbh->prepare($query)) {
            if ($query->execute()) {
           		my @row;
           		my $rnum=0;
             	while ( @row = $query->fetchrow_array ) {
					push @row, $config{'NODENAME'};
	           		$t{'table'}{$rnum} = [ @row ];			# Add row to hash
             		$rnum++;
					if ($debug){
						printf "%5s |", "$rnum";
						my $drc=0;
						while ($drc <= 5) {
							printf '%15s', "$row[$drc]";
							print " | ";
							$drc++;
						}
						print "<SNIP to $drc fields>\n";
						#%t{$rnum} = @row;
					}
					# Add the nodename to the row
					push @results, [@row];		# Add this row to the Results AoA
				}
				$t{'size'}=$rnum;
            } else {
				$t{'error'}="Unable to exec query\n";
			}
	   	} else {
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
