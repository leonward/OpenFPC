package OpenFPC::CXDB;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);
use Date::Simple ('date', 'today');
use Getopt::Long qw/:config auto_version auto_help/;
use DBI;
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

=head2 ctxupdate
	Update connection summary data in DB
	Takes ($dbname, $dbuser, $dbpass)
=cut

sub ctxupdate{
	my $dbname = shift;
	my $dbuser = shift;
	my $dbpass = shift;
	my $limit = shift;
	my $debug=1;
	if ($debug) {
		print "DEBUG: DB Name = $dbname \n" .
			"DEBUG: DB User = $dbuser \n" .
			"DEBUG: DB Pass = $dbpass \n" ;
	}

        # This is a hash of the SQL we want to run to generate our simple reports.
        my %queries=(
                "Top Source IPs" => "SELECT inet_ntoa(src_ip) AS source, COUNT(src_ip) AS count FROM session GROUP BY src_ip ORDER BY count DESC LIMIT $limit",
                "Top Destination IPs" => "SELECT inet_ntoa(dst_ip) AS destination, COUNT(dst_ip) AS count FROM session GROUP BY dst_ip ORDER BY count DESC LIMIT $limit",
                "Top Source Ports - UDP" => "SELECT src_port AS spt, COUNT(src_port) AS count FROM session WHERE ip_proto='17' GROUP BY src_port ORDER BY count DESC LIMIT $limit",
                "Top Source Ports - TCP" => "SELECT src_port AS spt, COUNT(src_port) AS count FROM session WHERE ip_proto='6' GROUP BY src_port ORDER BY count DESC LIMIT $limit",
                "Top Destination Ports - UDP" => "SELECT dst_port AS dpt, COUNT(dst_port) AS count FROM session WHERE ip_proto='17' GROUP BY dst_port ORDER BY count DESC LIMIT $limit",
                "Top Destination Ports - TCP" => "SELECT dst_port AS dpt, COUNT(dst_port) AS count FROM session WHERE ip_proto='6' GROUP BY dst_port ORDER BY count DESC LIMIT $limit",
        );   
        my %report=();

        print "DEBUG: Generating session summary\n" if $debug;
 
        if (my $dbh= DBI->connect("dbi:mysql:database=$dbname;host=localhost",$dbuser,$dbpass)) {
                my $query=$dbh->prepare("SELECT COUNT(*) FROM session") or print "ERROR: Unable to prep query $DBI::errstr";
                foreach my $table (keys %queries) {
                        my $query=$dbh->prepare($queries{$table}) or print "ERROR: Unable to prep query $DBI::errstr";
                        print "Table $table\n-----------------------------------\n" if ($debug);
                        $query->execute() or print "STATUS: ERROR: Unable to exec SQL query";

                        my @row;
                        while ( @row = $query->fetchrow_array ) {
				printf '%20s | %20s', "$row[0]",$row[1];
				print "\n";
                                $report{$table}{$row[0]}= $row[1];
                        }    
                }    
                $dbh->disconnect or print "Unable to disconnect from DB $DBI::errstr";
        } else {
 		print "DEBUG: Unable to connect to DB";
        }    
}

1;
