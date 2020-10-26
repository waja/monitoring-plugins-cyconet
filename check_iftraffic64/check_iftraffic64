#!/usr/bin/perl -w
#
# check_iftraffic.pl - Nagios(r) network traffic monitor plugin
# Copyright (C) 2004 Gerd Mueller / Netways GmbH
# $Id: check_iftraffic.pl 1119 2006-02-09 10:30:09Z gmueller $
# Version: .77
#
# mw = Markus Werner mw+nagios@wobcom.de
# Remarks (mw):
#
#	I adopted as much as possible the programming style of the origin code.
#
#	There should be a function to exit this program,
#	instead of calling print and exit statements all over the place.
#
# minor changes by mw
# 	The snmp if_counters on net devices can have overflows.
#	I wrote this code to address this situation.
#	It has no automatic detection and which point the overflow
#	occurs but it will generate a warning state and you
#	can set the max value by calling this script with an additional
#	arg.
#
# minor cosmetic changes by mw
#	Sorry but I couldn't sustain to clean up some things.
#
# gj = Greg Frater gregATfraterfactory.com
# Remarks (gj):
# minor (gj):
# 
#	* fixed the performance data, formating was not to spec
# 	* Added a check of the interfaces status (up/down).
#	  If interface is down the check returns a critical status.
# 	* Support both textual or the numeric index values.
#	* If the interface speed is not specified on the command line
#	  it gets it automatically from IfHighSpeed (or ifSpeed if IfHighSpeed
#	  counter is not available)
#	* Added option to specify a second Speed parameter to allow for 
#	  asymetrcal links such as a DSL line or cable modem where the 
#	  download and upload speeds are different
#	* Added -B option to display results in bits/sec instead of Bytes/sec
#	* Added the current usage in Bytes/s (or bit/s) to the perfdata output
#	* Added ability for plugin to determine interface to query by matching IP 
#	  address of host with entry in ipAdEntIfIndex (.1.3.6.1.2.1.4.20.1.2) 
#	* Added -L flag to list entries found in the ipAdEntIfIndex table
#	  Otherwise, it works as before.
#	* resorted options in help 
#	* Added auto detection mode (now the default), tries 64 bit counters first then uses 32 
#	  bit if 64 bit values are not available
#	* Added force flag to force 64 or 32 bit only mode (disables auto detection)
#	* Reworked the status output, tried to make it a little more readable
#	* Cleaned up logic of Units designator inside script
#	* Added checks for bad interface speed values (zero, error, etc.)
#	* 12_09_2014 Fixed unit label issue (thanks Gerhard Mourani for catching it)
#	* 12_09_2014 Changed labels from index -> interface on output when interface is not up
#	* 12_09_2014 Removed spurious '<br>' from output
#	* 12_09_2014 Changed the $suffix from 'Bs' or 'bs' to 'B' or 'b'
#	* 12_10_2014 Fixed issue when using string description for interface printing extra line with interface name and OID
#	* 07_06_2015 Added SNMP v3 support, base code provided by Rogerio Tomassoni de Araujo Junio <rogerio.tomassoni (at) cnpem.br>
#	* 12_02_2015 Set the inbandwidth and outbandwidth of the perfdata to a fixed base unit (bits or Bytes depending on switches used).
#	* 	     Thanks to Philip Ho <pcbho (at) hku.hk> and Fai Wong <fai.wong (at) masterson-tech.com> for pointing this out. 
#	* 12_08_2015 Fixed 'Return code of 25 is out of bounds' errors with an internal timeout setting.  Thanks to Philip Ho
#		     <pcbho (at) hku.hk> for directing me to the underlying problem
# 		     based on check_traffic from Adrian Wieczorek, <ads (at) irc.pila.pl>
#	* 05_13_2016 Changed perf data for in_ave and out_ave to always be in Bytes (no Bits allowed) to align with perf data output rules
#		     Thanks to Mark Rittinghaus <rittinghaus.mark (at) lumberg.com> for pointing this out and recommending a fix.
#	* 05_13_2016 Changed perf data for absolute Bytes ($in_bytes_abs/$out_bytes_abs) from Bytes units to 'c' for continuous
#		     Thanks to Mark Rittinghaus <rittinghaus.mark (at) lumberg.com> for suggesting this change.
#	* 03_27_2018 No functional changes, just some code comment cleanup.
#
# Send us bug reports, questions and comments about this plugin.
# Latest version of this software: http://exchange.nagios.org
#
#
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307


# Set Perl environ
use strict;
use Data::Dumper;
use Net::SNMP;
use Getopt::Long;
&Getopt::Long::config('bundling');

# Set script parameters
my $error;
my $host_address;
my $host_ip;
my $iface_descr;
my $iface_number;
my $iface_speed;
my $iface_speedOut;
my $ifspeed64;
my $ifspeed32;
my $inbytes64;
my $inbytes32;
my $outbytes64;
my $outbytes32;
my $in_ave 	= 0;
my $pin_ave 	= 0;
my $in_tot 	= 0;
my $index_list;
my $max_value; #added 20050614 by mw
my $max_bytes;
my $opt_h;
my $out_ave	= 0;
my $pout_ave	= 0;
my $port 	= 161;
my $out_tot 	= 0;
my $response;
my $session;
my @snmpoids;
my $units;

# SNMP OIDs for Traffic
my $snmpIfOperStatus 	= '1.3.6.1.2.1.2.2.1.8';	# Operational state of interface (i.e. 1-up, 2-down, etc.)
my $snmpIfInOctets32  	= '1.3.6.1.2.1.2.2.1.10';	# Total Octets entering interface (in) - 32 bit counter
my $snmpIfOutOctets32 	= '1.3.6.1.2.1.2.2.1.16';	# Total Octets leaving interface (out) - 32 bit counter
my $snmpIfInOctets  	= '1.3.6.1.2.1.31.1.1.1.6';	# Total Octets entering interface (in) - 64 bit counter
my $snmpIfOutOctets 	= '1.3.6.1.2.1.31.1.1.1.10';	# Total Octets leaving interface (out) - 64 bit counter
my $snmpIfDescr     	= '1.3.6.1.2.1.2.2.1.2';	# Textual string describing interface
my $snmpIfSpeed32     	= '1.3.6.1.2.1.2.2.1.5'; 	# bits per second
my $snmpIfSpeed    	= '1.3.6.1.2.1.31.1.1.1.15'; 	# Mbits per second
my $snmpIPAdEntIfIndex 	= '1.3.6.1.2.1.4.20.1.2'; 	# Index of interface using hosts IP addr



# Path to  tmp files
my $TRAFFIC_FILE = "/usr/local/nagios/libexec/traffic/";

# Create tmp file location if it does not exist
if ( ! -d $TRAFFIC_FILE ) {
	mkdir $TRAFFIC_FILE;
}

# changes sos 20090717 UNKNOWN must be 3
# Set status codes
my %STATUS_CODE =
  ( 'UNKNOWN' => '3', 'OK' => '0', 'WARNING' => '1', 'CRITICAL' => '2' );

#default values;
my $bits        = undef; 
my $COMMUNITY	= "public";
my $crit_usage	= 98;
my $debug       = 0;
my $force	= undef;
my $if_status	= '4';
my ( $in_bytes, $out_bytes, $in_bytes32, $out_bytes32 ) = 0;
my $label       = "";
my $output      = "";
my $snmp_version = 2;
my $state       = "UNKNOWN";
my $suffix      = "B";
my $thirtytwo   = undef;
my $use_reg     = undef;  # Use Regexp for name
my $warn_usage  = 85;
my $timeout   =  10;
my $username;
my $authpasswd;
my $authproto   = 'MD5';
my $privpasswd;
my $privproto   = 'DES';

#cosmetic changes 20050614 by mw, see old versions for detail
# Added options for bits and second max ifspeed 20100202 by gj
# Added options for specific IP addr to match 20100405 by gj
my $status = GetOptions(
	"h|help"        => \$opt_h,
	"authpassword=s"	=> \$authpasswd,
	"authprotocol=s"	=> \$authproto,
	'B'		=> \$bits,
	'bits'		=> \$bits,
	"C|community=s" => \$COMMUNITY,
	"w|warning=s"   => \$warn_usage,
	"c|critical=s"  => \$crit_usage,
	"b|bandwidth|I|inBandwidth=i" => \$iface_speed,
	"O|outBandwidth=i" => \$iface_speedOut,
	'f|force'	=> \$force, #added 20130429 by gjf
        'r'             => \$use_reg,           
        'noregexp'      => \$use_reg,
	"privpassword=s"	=> \$privpasswd,
	"privprotocol=s"	=> \$privproto,
	"p|port=i"      => \$port,
	"u|units=s"     => \$units,
	"i|interface=s" => \$iface_descr,
	"A|address=s"   => \$host_ip,
	"H|hostname=s"  => \$host_address,
	'L'	  	=> \$index_list,
	"d|debug=i"	=> \$debug,
	'list'	  	=> \$index_list,
	"user|username=s"	=> \$username,
	"v|Version=s"	=> \$snmp_version,
	"M|max=i"       => \$max_value, #added 20050614 by mw
	"32|32bit"	=> \$thirtytwo #added 20101104 by gjf
);

# Set internal timeout to address 'Return code of 25 is out of bounds' errors
eval {
	local %SIG;
	$SIG{ALRM}=
		sub{ 
			die "UKNOWN: script timeout\n"; 
			exit -1;
		};
	alarm 15;


# Print help if no options given
if ( $status == 0 ) {
	print_help();
	exit $STATUS_CODE{'OK'};
}

debugout ("DEBUG ENABLED at level: $debug", "1");
debugout ("INTERFACE DESCR: $iface_descr", "2"), if ( defined($iface_descr) );

# Changed 20091214 gj
# Check for missing options
if ( !$host_address )  {
	print  "\nMissing host address!\n\n";
	stop(print_usage(),"OK");
} elsif ( ( $iface_speed ) and ( !$units ) ){
	print "\nMissing units!\n\n";
	stop(print_usage(),"OK");
} elsif ( ( $units ) and ( ( !$iface_speed ) and  ( !$iface_speedOut ) ) ) {
	print "\nMissing (-I or -O) interface maximum speed!\n\n";
	stop(print_usage(),"OK");
} elsif ( ( $iface_speedOut ) and ( !$units ) ) {
	print "\nMissing units (-u) for Out maximum speed!\n\n";
	stop(print_usage(),"OK");
} elsif ( ( $max_value ) and ( !$units ) ) {
	print "\nMissing units (-u) for maximum counter!\n\n";
	stop(print_usage(),"OK");
} elsif ( ( $snmp_version == 3 ) and ( $authpasswd ) and ( !$username ) ) {
	print "\nMissing version 3 username!\n\n";
	stop(print_usage(),"OK");
} elsif ( ( $snmp_version == 3 ) and ( $privpasswd ) and ( !$authpasswd ) ) {
	print "\nMissing version 3 auth password!\n\n";
	stop(print_usage(),"OK");
}

# Set default units if undefined
if ( !defined($units) ){
	#bits
	$units = "b";
}

# Switch output from Bytes to bits if changed on command line
if ($bits) {
	$suffix = "b"
}

if ( $iface_speed ) {
	#change 20050414 by mw
	# Added iface_speedOut 20100202 by gj
	# Convert interface speed to Bytes
	debugout("UNIT: $units","3");
	$iface_speed = bits2bytes( $iface_speed, $units );
	if ( $iface_speedOut ) {
		$iface_speedOut = bits2bytes( $iface_speedOut, $units );
	}
}

if ( !$max_value ) {

	# If no -M Parameter was set, set it to 64Bit Overflow
	$max_bytes = 18446744073709600000;    # the value is (2^64)

	if ( defined($thirtytwo) ){
		# If using 32bit counters set to 32bit overflow
		$max_bytes = 4294967296;    # the value is (2^32)
	}
} else {
	# Max value specified, used given value, convert to Bytes
	$max_bytes = unit2bytes( $max_value, $units );
}

debugout ("BYTE COUNTER max_value: $max_bytes", "2");

####### Can only be set after interface 'speed in' and 'out' and 'max bytes' have all been converted to Bytes
# Bytes
$units = "B";

# Check snmp version, set snmp parameters
if ( $snmp_version =~ /[12]/ ) {
	( $session, $error ) = Net::SNMP->session(
		-hostname  => $host_address,
		-community => $COMMUNITY,
		-port      => $port,
		-version   => $snmp_version
	);

	if ( !defined($session) ) {
		stop("UNKNOWN: $error","UNKNOWN");
	}
} elsif ( $snmp_version =~ /3/ ) {
        #print "\nSNMP v3 \n\n";
	#authPriv
	if ( $username and $authpasswd and $privpasswd ) {
        ( $session, $error ) = Net::SNMP->session(
                -hostname  => $host_address,
                -version   => $snmp_version,
                -username  => $username,
                -authpassword => $authpasswd,
                -authprotocol => $authproto,
                -privpassword => $privpasswd,
                -privprotocol => $privproto,
                -port => $port,            
                -timeout =>$timeout
            
        );      
	#authNoPriv
	} elsif ( $username and $authpasswd ) {
        ( $session, $error ) = Net::SNMP->session(
                -hostname  => $host_address,
                -version   => $snmp_version,
                -username  => $username,
                -authpassword => $authpasswd,
                -authprotocol => $authproto,
                -port => $port,            
                -timeout =>$timeout
	);
	#NoauthNoPriv
	} else {
        ( $session, $error ) = Net::SNMP->session(
                -hostname  => $host_address,
                -version   => $snmp_version,
                -username  => $username,
                -port => $port,            
                -timeout =>$timeout
	);
	}            
        if ( !defined($session) ) {
            stop("UNKNOWN: $error","UNKNOWN");
        }
} else {
	$state = 'UNKNOWN';
	stop("$state: It appears you are missing one or more parameters necessary for v$snmp_version to function.\n",$state);
}

debugout("SNMP:\n\tver: $snmp_version\n\tcommunity: $COMMUNITY\n\tport: $port", "3");
if ( $username ) {
	debugout("\n\tuser: $username", "3");
}
if ( $authpasswd ) {
	debugout("\n\tauth password: $authpasswd\n\tauth protocol: $authproto", "3");
}
if ( $privpasswd ) {
	debugout("\n\tpriv password: $privpasswd\n\tpriv protocol: $privproto", "3");
}

# Neither Interface Index nor Host IP address were specified 
if ( !$iface_descr ) {
	if ( !$host_ip ){
		# Try to resolve host name and find index from ip addr
		debugout("DETECT INTERFACE start with hostname", "1");
		$iface_descr = fetch_Ip2IfIndex( $session, $host_address );
	} else {
		# Use ip addr to find index
		debugout("DETECT INTERFACE start with IP addr","1");
		$iface_descr = fetch_Ip2IfIndex( $session, $host_ip );
	}	
}

# Added 20091209 gj
# Detect if a string description was given or a numeric interface index number 
if ( $iface_descr =~ /[^0123456789]+/ ) {
	$iface_number = fetch_ifdescr( $session, $iface_descr );
	debugout("INTERFACE from text string","1"); 
} else {
	$iface_number = $iface_descr;
}

debugout("USING INT#: $iface_number", "2");
debugout("OID's:","2");
debugout("\tIfOperStatus: $snmpIfOperStatus.$iface_number","2");
debugout("\tIfSpeed: $snmpIfSpeed.$iface_number","2");
debugout("\tIfSpeed32: $snmpIfSpeed32.$iface_number","2");
debugout("\tInOctets: $snmpIfInOctets.$iface_number","2");
debugout("\tInOctets32: $snmpIfInOctets32.$iface_number","2");
debugout("\tOutOctets: $snmpIfOutOctets.$iface_number","2");
debugout("\tOutOctets32: $snmpIfOutOctets32.$iface_number","2");

# Get SNMP values, flag errors
debugout("RESULTS:","3");
my $res_status    = $session->get_request(-varbindlist => [ $snmpIfOperStatus . "." . $iface_number ],);
if ( defined $res_status ){
	$if_status  = $res_status->{ $snmpIfOperStatus . "." . $iface_number };
	debugout("\tOperational Status: $if_status","3");
} else {
	$if_status = "DNE - " . $session->error();	
	debugout("\tOperational Status not defined!: $if_status","2");
}
my $res_ifspeed64 = $session->get_request(-varbindlist => [ $snmpIfSpeed . "." . $iface_number ],);
if ( defined $res_ifspeed64 ){
	$ifspeed64  = $res_ifspeed64->{ $snmpIfSpeed . "." . $iface_number };
	debugout("\tInterface Speed (64bit): $ifspeed64 Mbits","3");
} else {
	$ifspeed64 = "DNE - " . $session->error();	
	debugout("\tInterface Speed (64bit) not defined or bad value!: $ifspeed64","2");
}
my $res_ifspeed32 = $session->get_request(-varbindlist => [ $snmpIfSpeed32 . "." . $iface_number ],);
if ( defined $res_ifspeed32 ){
	$ifspeed32  = $res_ifspeed32->{ $snmpIfSpeed32 . "." . $iface_number };
	debugout("\tInterface Speed (32bit): $ifspeed32 bits","3");
} else {
	$ifspeed32 = "DNE - " . $session->error();	
	debugout("\tInterface Speed (32bit) not defined!: $ifspeed32","2");
}
my $res_inbytes64 = $session->get_request(-varbindlist => [ $snmpIfInOctets . "." . $iface_number ],);
if ( defined $res_inbytes64 ){
	$inbytes64  = $res_inbytes64->{ $snmpIfInOctets . "." . $iface_number };
	debugout("\tIn Bytes (64bit): $inbytes64","2");
} else {
	$inbytes64 = "DNE - " . $session->error();	
	debugout("\tIn Bytes (64bit) not defined!: $inbytes64","2");
}
my $res_inbytes32  = $session->get_request(-varbindlist => [ $snmpIfInOctets32 . "." . $iface_number ],);
if ( defined $res_inbytes32 ){
	$inbytes32  = $res_inbytes32->{ $snmpIfInOctets32 . "." . $iface_number };
	debugout("\tIn Bytes (32bit): $inbytes32","3");
} else {
	$inbytes32 = "DNE - " . $session->error();	
	debugout("\tIn Bytes (32bit) not defined!: $inbytes32","2");
}
my $res_outbytes64 = $session->get_request(-varbindlist => [ $snmpIfOutOctets . "." . $iface_number ],);
if ( defined $res_outbytes64 ){
	$outbytes64  = $res_outbytes64->{ $snmpIfOutOctets . "." . $iface_number };
	debugout("\tOut Bytes (64bit): $outbytes64","3");
} else {
	$outbytes64 = "DNE - " . $session->error();	
	debugout("\tOut Bytes (64bit) not defined!: $outbytes64","2");
}
my $res_outbytes32 = $session->get_request(-varbindlist => [ $snmpIfOutOctets32 . "." . $iface_number ],);
if ( defined $res_outbytes32 ){
	$outbytes32  = $res_outbytes32->{ $snmpIfOutOctets32 . "." . $iface_number };
	debugout("\tOut Bytes (32bit): $outbytes32","3");
} else {
	$outbytes32 = "DNE - " . $session->error();	
	debugout("\tOut Bytes (32bit) not defined!: $outbytes32","2");
}

# Check interface status, quit check if interface status is error or not '1'.
if ( defined $res_status ){
	if ( $if_status =~ /^DNE -|error|noSuchObject|noSuchInstance/i ) {
		debugout("if_status is not a number\n","4");
		$state = 'UNKNOWN';
		stop("$state: Improper interface status, status received: " . $if_status . "\n",$state);
	} elsif ( $if_status == 1 ) {
		# No action necessary, continue on!
	} elsif ($if_status == 2 ) {
		# Quit, interface is down
		$state = 'CRITICAL';
		stop("$state: Interface is \'down\' (interface: " . $iface_number . " status: " . $if_status . ")\n",$state);
	} elsif ($if_status == 3 ) {
		# Quit, interface is testing
		$state = 'CRITICAL';
		stop("$state: Interface is reporting \'testing\' (interface: " . $iface_number . " status: " . $if_status . ")\n",$state);
	} elsif ($if_status == 4 ) {
		# Quit, interface is unknown
		$state = 'CRITICAL';
		stop("$state: Interface is reporting \'unknown\' (interface: " . $iface_number . " status: " . $if_status . ")\n",$state);
	} elsif ($if_status == 5 ) {
		# Quit, interface is dormant
		$state = 'CRITICAL';
		stop("$state: Interface is reporting \'dormant\' (interface: " . $iface_number . " status: " . $if_status . ")\n",$state);
	} elsif ($if_status == 6 ) {
		# Quit, interface is notPresent
		$state = 'CRITICAL';
		stop("$state: Interface is reporting \'notPresent\' (interface: " . $iface_number . " status: " . $if_status . ")\n",$state);
	} elsif ($if_status == 7 ) {
		# Quit, interface is lowerLayerDown
		$state = 'CRITICAL';
		stop("$state: Interface is reporting \'lowerLayerDown\' (interface: " . $iface_number . " status: " . $if_status . ")\n",$state);
	} else {
		# Interface is in an unknown state
		$state = 'UNKNOWN';
		stop("$state: Interface is reporting unknown status (interface: " . $iface_number . " status: " . $if_status . ")\n",$state);
	}
} else {
	$state = 'UNKNOWN';
	stop("$state: Improper interface status, status received: " . $if_status . "\n",$state);
}

# Determine which values to use
if ( !defined($force) and !defined($thirtytwo) ){
	#default - use 64 then 32 bit values 
	debugout("USING 64 THEN 32 bit VALUES:","4");

	# Speed test
	if ( !$iface_speed ) {
		debugout("\t(Interface speed not provided on command line, determine from host)","4");
		if ( $ifspeed64 =~ /^DNE -|error|noSuchObject|noSuchInstance/i or $ifspeed64 < 1 ){
			debugout("\t\tBad 64bit speed value: $ifspeed64","3");
			if ( $ifspeed32 =~ /^DNE -|error|noSuchObject|noSuchInstance/i or $ifspeed32 < 1 or $ifspeed32 > 4294967295 ){
				debugout("\t\tBad 32bit speed value: $ifspeed32","3");
				$state = 'UNKNOWN';
				stop("$state: No usable interface speed available 64: $ifspeed64 32: $ifspeed32\n",$state);
			} else {
				debugout("\tUsing 32bit speed value: $ifspeed32","3");
				$iface_speed = bits2bytes( $ifspeed32, "b" );
			}
		} else {
			debugout("\tUsing 64bit speed value: $ifspeed64","3");
			# Convert Mbits to bits, bits to Bytes
			$iface_speed = $ifspeed64 * 1000 * 1000;
			$iface_speed = bits2bytes( $iface_speed, "b" );
		}
	}

	# InBytes test
	if ( $inbytes64 =~ /^DNE -|error|noSuchObject|noSuchInstance/i ){
		debugout("\t\tBad 64bit in bytes value: $inbytes64","3");
		if ( $inbytes32 =~ /^DNE -|error|noSuchObject|noSuchInstance/i ){
			debugout("\t\tBad 32bit in bytes value: $inbytes32","3");
			$state = 'UNKNOWN';
			stop("$state: No in bytes available 64: $inbytes64 32: $inbytes32\n",$state);
		} else {
			debugout("\tUsing 32bit in bytes value: $inbytes32","3");
			$in_bytes = $inbytes32;
		}
	} else {
		debugout("\tUsing 64bit in bytes value: $inbytes64","3");
		$in_bytes = $inbytes64;
	}	

	# OutBytes test
	if ( $outbytes64 =~ /^DNE -|error|noSuchObject|noSuchInstance/i ){
		debugout("\t\tBad 64bit out bytes value: $outbytes64","3");
		if ( $outbytes32 =~ /^DNE -|error|noSuchObject|noSuchInstance/i ){
			debugout("\t\tBad 32bit out bytes value: $outbytes32","3");
			$state = 'UNKNOWN';
			stop("$state: No out bytes available 64: $outbytes64 32: $outbytes32\n",$state);
		} else {
			debugout("\tUsing 32bit out bytes value: $outbytes32","3");
			$out_bytes = $outbytes32;
		}
	} else {
		debugout("\tUsing 64bit out bytes value: $outbytes64","3");
		$out_bytes = $outbytes64;
	}	

} elsif ( !defined($force) and defined($thirtytwo) ){
	debugout("USING 32 THEN 64 bit VALUES:","4");

	# Speed test
	if ( !$iface_speed ) {
		debugout("\t(Interface speed not provided on command line, determine from host)","4");
		if ( $ifspeed32 =~ /^DNE -|error|noSuchObject|noSuchInstance/i or $ifspeed32 < 1 or $ifspeed32 >= 4294967295 ){
			debugout("\t\tBad 32bit speed value: $ifspeed32","3");
			if ( $ifspeed64 =~ /^DNE -|error|noSuchObject|noSuchInstance/i or $ifspeed64 < 1 ){
				debugout("\t\tBad 64bit speed value: $ifspeed64","3");
				$state = 'UNKNOWN';
				stop("$state: No usable interface speed available 64: $ifspeed64 32: $ifspeed32\n",$state);
			} else {
				debugout("\tUsing 64bit speed value: $ifspeed64","3");
				# Convert Mbits to bits, bits to Bytes
				$iface_speed = $ifspeed64 * 1000 * 1000;
				$iface_speed = bits2bytes( $iface_speed, "b" );
			}
		} else {
			debugout("\tUsing 32bit speed value: $ifspeed32","3");
			$iface_speed = bits2bytes( $ifspeed32, "b" );
		}
	}

	# InBytes test
	if ( $inbytes32 =~ /^DNE -|error|noSuchObject|noSuchInstance/i ){
		debugout("\t\tBad 32bit in bytes value: $inbytes32","3");
		if ( $inbytes64 =~ /^DNE -|error|noSuchObject|noSuchInstance/i ){
			debugout("\t\tBad 64bit in bytes value: $inbytes64","3");
			$state = 'UNKNOWN';
			stop("$state: No in bytes available 64: $inbytes64 32: $inbytes32\n",$state);
		} else {
			debugout("\tUsing 64bit in bytes value: $inbytes64","3");
			$in_bytes = $inbytes64;
		}
	} else {
		debugout("\tUsing 32bit in bytes value: $inbytes32","3");
		$in_bytes = $inbytes32;
	}	

	# OutBytes test
	if ( $outbytes32 =~ /^DNE -|error|noSuchObject|noSuchInstance/i ){
		debugout("\t\tBad 32bit out bytes value: $outbytes32","3");
		if ( $outbytes64 =~ /^DNE -|error|noSuchObject|noSuchInstance/i ){
			debugout("\t\tBad 64bit out bytes value: $outbytes64","3");
			$state = 'UNKNOWN';
			stop("$state: No out bytes available 64: $outbytes64 32: $outbytes32\n",$state);
		} else {
			debugout("\tUsing 64bit out bytes value: $outbytes64","3");
			$out_bytes = $outbytes64;
		}
	} else {
		debugout("\tUsing 32bit out bytes value: $outbytes32","3");
		$out_bytes = $outbytes32;
	}	

} elsif ( defined($force) and defined($thirtytwo) ){
	debugout("USING 32 bit VALUES ONLY:","4");

	# Speed test
	if ( !$iface_speed ) {
		debugout("\t(Interface speed not provided on command line, determine from host)","4");
		if ( $ifspeed32 =~ /^DNE -|error|noSuchObject|noSuchInstance/i or $ifspeed32 < 1 or $ifspeed32 > 4294967295 ){
			debugout("\t\tBad 32bit speed value: $ifspeed32","3");
			$state = 'UNKNOWN';
			stop("$state: No usable interface speed available: $ifspeed32\n",$state);
		} else {
			debugout("\tUsing 32bit speed value: $ifspeed32","3");
			$iface_speed = bits2bytes( $ifspeed32, "b" );
		}
	}

	# InBytes test
	if ( $inbytes32 =~ /^DNE -|error|noSuchObject|noSuchInstance/i ){
		debugout("\t\tBad 32bit in bytes value: $inbytes32","3");
		$state = 'UNKNOWN';
		stop("$state: No in bytes available: $inbytes32\n",$state);
	} else {
		debugout("\tUsing 32bit in bytes value: $inbytes32","3");
		$in_bytes = $inbytes32;
	}	

	# OutBytes test
	if ( $outbytes32 =~ /^DNE -|error|noSuchObject|noSuchInstance/i ){
		debugout("\t\tBad 32bit out bytes value: $outbytes32","3");
		$state = 'UNKNOWN';
		stop("$state: No out bytes available: $outbytes32\n",$state);
	} else {
		debugout("\tUsing 32bit out bytes value: $outbytes32","3");
		$out_bytes = $outbytes32;
	}

} elsif ( defined($force) and !defined($thirtytwo) ){
	debugout("USING 64 bit ONLY:","4");

	# Speed test
	if ( !$iface_speed ) {
		debugout("\t(Interface speed not provided on command line, determine from host)","4");
		if ( $ifspeed64 =~ /^DNE -|error|noSuchObject|noSuchInstance/i or $ifspeed64 < 1 ){
			debugout("\t\tBad 64bit speed value: $ifspeed64","3");
			$state = 'UNKNOWN';
			stop("$state: No usable interface speed available: $ifspeed64\n",$state);
		} else {
			debugout("\tUsing 64bit speed value: $ifspeed64","3");
			# Convert Mbits to bits, bits to Bytes
			$iface_speed = $ifspeed64 * 1000 * 1000;
			$iface_speed = bits2bytes( $iface_speed, "b" );
		}
	}

	# InBytes test
	if ( $inbytes64 =~ /^DNE -|error|noSuchObject|noSuchInstance/i ){
		debugout("\t\tBad 64bit in bytes value: $inbytes64","3");
		$state = 'UNKNOWN';
		stop("$state: No in bytes available: $inbytes64\n",$state);
	} else {
		debugout("\tUsing 64bit in bytes value: $inbytes64","3");
		$in_bytes = $inbytes64;
	}	

	# OutBytes test
	if ( $outbytes64 =~ /^DNE -|error|noSuchObject|noSuchInstance/i ){
		debugout("\t\tBad 64bit out bytes value: $outbytes64","3");
		$state = 'UNKNOWN';
		stop("$state: No out bytes available: $outbytes64\n",$state);
	} else {
		debugout("\tUsing 64bit out bytes value: $outbytes64","3");
		$out_bytes = $outbytes64;
	}

}

# Added 20100201 gj
# Check if Out max speed was provided, use same IF speed for both if not
if (!$iface_speedOut) {
	$iface_speedOut = $iface_speed;
}

debugout ("UNITS: $units", "2");
debugout ("Interface speed calculated as: $iface_speed $units", "1");
debugout ("Interface speed OUT: $iface_speedOut $units", "4");

# close SNMP
$session->close;

my $row;
my $last_check_time = time - 1;
my $last_in_bytes   = $in_bytes;
my $last_out_bytes  = $out_bytes;

if (
	open( FILE,
		"<" . $TRAFFIC_FILE . $host_address . "_if-" . $iface_number )
  )
{
	while ( $row = <FILE> ) {

		( $last_check_time, $last_in_bytes, $last_out_bytes ) =
		  split( ":", $row );

		### by sos 17.07.2009 check for last_bytes
		if ( ! $last_in_bytes  ) { $last_in_bytes=$in_bytes;  }
		if ( ! $last_out_bytes ) { $last_out_bytes=$out_bytes; }

		if ($last_in_bytes !~ m/\d/) { $last_in_bytes=$in_bytes; }
		if ($last_out_bytes !~ m/\d/) { $last_out_bytes=$out_bytes; }
	}
	close(FILE);
}

my $update_time = time;
debugout ("CURRENT timestamp: $update_time", "1");
debugout ("FILE PATH: $TRAFFIC_FILE" . $host_address . "_if-" . $iface_number, "1");
debugout("READ FROM FILE:\n\tlast time: $last_check_time\n\tlast in bytes: $last_in_bytes\n\tlast out bytes: $last_out_bytes","4");

open( FILE, ">" . $TRAFFIC_FILE . $host_address . "_if-" . $iface_number )
  or die "Can't open $TRAFFIC_FILE for writing: $!";

printf FILE ( "%s:%.0ld:%.0ld\n", $update_time, $in_bytes, $out_bytes );
close(FILE);

debugout("WRITTEN TO FILE:\n\ttime: $update_time\n\tin_bytes: $in_bytes\n\tout bytes: $out_bytes","4");

#added 20050614 by mw
#Check for and correct counter overflow (if possible).
#See function counter_overflow.
$in_bytes  = counter_overflow( $in_bytes,  $last_in_bytes,  $max_bytes );
$out_bytes = counter_overflow( $out_bytes, $last_out_bytes, $max_bytes );

# Calculate traffic since last check (RX\TX) 
my $in_traffic = sprintf( "%.2lf",
	( $in_bytes - $last_in_bytes ) / ( time - $last_check_time ) );
my $out_traffic = sprintf( "%.2lf",
	( $out_bytes - $last_out_bytes ) / ( time - $last_check_time ) );

debugout("in_traffic: $in_traffic\nout_traffic: $out_traffic","1");
# sos 20090717 changed because rrdtool needs bytes
my $in_bytes_abs  = $in_bytes;
my $out_bytes_abs = $out_bytes;

debugout("iface_speed: $iface_speed $units\nin_traffic: $in_traffic\nout_traffic: $out_traffic", "1");

# Calculate usage percentages
my $in_ave_pct  = sprintf( "%.2f", ( 1.0 * $in_traffic * 100 ) / $iface_speed );
my $out_ave_pct = sprintf( "%.2f", ( 1.0 * $out_traffic * 100 ) / $iface_speedOut );

# Don't scale perf data or change it to bits from bytes
$pin_ave = $in_traffic;
$pout_ave = $out_traffic;

if ($bits) {
	# Convert output from Bytes to bits
	$label = "bits";
	$in_tot = $in_bytes * 8;
	$out_tot = $out_bytes * 8;
	$in_ave = $in_traffic * 8;
	$out_ave = $out_traffic * 8;	
} else {
	$label = "Bytes";
	$in_tot = $in_bytes;
	$out_tot = $out_bytes;
	$in_ave = $in_traffic;
	$out_ave = $out_traffic;
}

debugout("OUTPUT:\n\tlabel: $label", "4");
debugout("\tin_tot: $in_tot\n\tout_tot: $out_tot\n\tin_ave: $in_ave\n\tout_ave: $out_ave", "4");
debugout("\tin_ave_pct: $in_ave_pct\n\tout_ave_pct: $out_ave_pct\n\tin_bytes_abs: $in_bytes_abs\n\tout_bytes_abs: $out_bytes_abs", "4");

# Scale ave and tot for output
$in_tot = unit2scale($in_tot);
$out_tot = unit2scale($out_tot);
$in_ave = unit2scale($in_ave);
$out_ave = unit2scale($out_ave);

# Convert from Bytes/bits to megaBytes/bits
$in_bytes  = sprintf( "%.2f", $in_bytes / (1024 * 1000) );
$out_bytes = sprintf( "%.2f", $out_bytes / (1024 * 1000) );

# Changed 20091209 gj, updated 20130424 gj
# Check/Set state of service check
if ( ( $in_ave_pct < $warn_usage ) and ( $out_ave_pct < $warn_usage ) ) {
	$state = 'OK';
	$output =
	"$state - Average IN: "
	  . $in_ave . $suffix . " (" . $in_ave_pct . "%), " 
	  . "Average OUT: " . $out_ave . $suffix . " (" . $out_ave_pct . "%)";
	$output .= "Total RX: $in_tot" . "$label, Total TX: $out_tot" . "$label";
} elsif ( $in_ave_pct > $crit_usage ) {
	$state = 'CRITICAL';
	$output = "$state - IN bandwidth ($in_ave_pct%) too high";
} elsif ( $out_ave_pct > $crit_usage ) {
	$state = 'CRITICAL';
	$output = "$state - OUT bandwidth ($out_ave_pct%) too high";
} elsif ( $in_ave_pct > $warn_usage ) {
	$state = 'WARNING';
	$output = "$state - IN bandwidth ($in_ave_pct%) too high";
} elsif ( $out_ave_pct > $warn_usage ) {
	$state = 'WARNING';
	$output = "$state - OUT bandwidth ($out_ave_pct%) too high";
}

# Changed 20091214 gj - commas should have been semicolons
$output .=
"|inUsage=$in_ave_pct%;$warn_usage;$crit_usage outUsage=$out_ave_pct%;$warn_usage;$crit_usage"
  . " inBandwidth=" . $pin_ave . "B outBandwidth=" . $pout_ave . "B"
  . " inAbsolut=$in_bytes_abs" . "c" . " outAbsolut=$out_bytes_abs" . "c";
debugout ("",1);
stop($output, $state);


# end of internal timeout eval group
alarm 0;
};

sub fetch_Ip2IfIndex {
	my $state;
	my $response;

	my $snmpkey;
	my $answer;
	my $key;

	my ( $session, $host ) = @_;

	# Determine if we have a host name or IP addr
	if ( $host =~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ ){
		debugout("I found an IP address: $host","3");
	} else {
		debugout("RESOLVING hostname $host","3");
		$host = get_ip ( $host );
		debugout("HOSTNAME RESOLVED to IP addr: $host","3");
	}

	# Quit if results not found
	if ( !defined( $response = $session->get_table($snmpIPAdEntIfIndex) ) ) {
		$answer = $session->error;
		$session->close;
		$state = 'CRITICAL';
		stop ("$state: Interface index not detected ERROR: $answer",$state);
	}

	my %resp = %{$response};

	if ( $index_list ){
		print ("\nInterfaces found:\n");
		print ("  IP Addr\tIndex\n");
		print ("------------------------\n");
	}		
	# Check each returned value
	foreach $key ( keys %resp ) {

		if ( $index_list ){
			my $index_addr = substr $key, 21;
			print ($index_addr,"\t ",$resp{$key},"\n");
		}

		# Check for ip address match in returned index results
		if ( $key =~ /$host$/ ) {
			$snmpkey = $resp{$key};
		}
	}
	unless ( defined $snmpkey ) {
		$session->close;
		$state = 'CRITICAL';
		stop("$state: Could not find index matching $host",$state);
	}
	return $snmpkey;
}

sub fetch_ifdescr {
	my $state;
	my $response;

	my $snmpkey;
	my $answer;
	my $key;

	my ( $session, $ifdescr ) = @_;

	if ( !defined( $response = $session->get_table($snmpIfDescr) ) ) {
		$answer = $session->error;
		$session->close;
		$state = 'CRITICAL';
		exit $STATUS_CODE{$state};
	}

	foreach $key ( keys %{$response} ) {

		# added 20070816 by oer: remove trailing 0 Byte for Windows :-(
		my $resp=$response->{$key};
		$resp =~ s/\x00//;


                my $test = defined($use_reg) 
                      ? $resp =~ /$ifdescr/
                      : $resp eq $ifdescr;

                if ($test) {

			$key =~ /.*\.(\d+)$/;
			$snmpkey = $1;

			debugout("\t$ifdescr = $key / $snmpkey","2");	
		}
	}
	unless ( defined $snmpkey ) {
		$session->close;
		$state = 'CRITICAL';
		printf "$state: Could not match $ifdescr \n";
		exit $STATUS_CODE{$state};
	}
	return $snmpkey;
}

#added 20050416 by mw
#Converts an input value to value in bits
sub bits2bytes {
	return unit2bytes(@_) / 8;
}

#added 20050416 by mw
#Converts an input value to value in bytes
sub unit2bytes {
	my ( $value, $unit ) = @_;

	if ( $unit eq "g" ) {
		return $value * 1000 * 1000 * 1000;
	}
	elsif ( $unit eq "m" ) {
		return $value * 1000 * 1000;
	}
	elsif ( $unit eq "k" ) {
		return $value * 1000;
	}
	elsif ( $unit eq "b" ) {
		return $value * 1;
	}
	else {
		print "You have to supply a supported unit (g,m,k,b)\n";
		exit $STATUS_CODE{'UNKNOWN'};
	}
}

sub unit2scale {
	# Scale output, expecting Bits\Bytes input
	my ($val) = @_;
	my $prefix = "";

	# I'm not sure which should be used here 1024 or 1000 but 1000 is easier on the
	# eye when looking at the plug-in output
	#if ( $val > 1024 ) {
	if ( $val > 1000 ) {
	#	$val = sprintf( "%.2f", $val / 1024 );
		$val = sprintf( "%.2f", $val / 1000 );
		$prefix = "K";
	}
	if ( $val > 1000 ) {
		$val = sprintf( "%.2f", $val / 1000 );
		$prefix = "M";
	}
	if ( $val > 1000 ) {
		$val = sprintf( "%.2f", $val / 1000 );
		$prefix = "G";
	}
	return $val . $prefix;
}

# Convert from Bytes/bits to megaBytes/bits
# added 20050414 by mw
# This function detects if an overflow occurs. If so, it returns
# a computed value for $bytes.
# If there is no counter overflow it simply returns the original value of $bytes.
# IF there is a Counter reboot wrap, just use previous output.
sub counter_overflow {
	my ( $bytes, $last_bytes, $max_bytes ) = @_;

	$bytes += $max_bytes if ( $bytes < $last_bytes );
	$bytes = $last_bytes  if ( $bytes < $last_bytes );
	return $bytes;
}

# Added 20100202 by gj
# Print results and exit script
sub stop {
	my $result = shift;
	my $exit_code = shift;
	print $result . "\n";
	exit ( $STATUS_CODE{$exit_code} );
}

# Added 20100405 by gj
# Lookup hosts ip address
sub get_ip {
	use Net::DNS;

	my ( $host_name ) = @_;

	my $res = Net::DNS::Resolver->new;
	my $query = $res->search($host_name);

	if ($query) {
		foreach my $rr ($query->answer) {
			next unless $rr->type eq "A";
			return $rr->address;
		}
	} else {
		
		stop("Error: IP address not resolved","UNKNOWN");
	}
}

sub debugout {

	my ( $text, $level ) = @_;

	if ( $level <= $debug) {
		print "$text\n";
	}
}

#cosmetic changes 20050614 by mw
#Couldn't sustain "HERE";-), either.
sub print_usage {
	print <<EOU;
    Usage: check_iftraffic64.pl -H host [ -C community_string ] [ -i if_index|if_descr ] [ -r ] [ -b if_max_speed_in | -I if_max_speed_in ] [ -O if_max_speed_out ] [ -u ] [ -B ] [ --32bit ] [ -f ] [ -A IP Address ] [ -L ] [ -M ] [ -w warn ] [ -c crit ] [ -v 1|2|3 ] [ --username <username> ] [ --authpassword <authpassword> ] [ --authprotocol MD5|SHA ] [ --privpassword <privpassword> ] [ --privprotocol DES|AES|3DES ]

    Example 1: check_iftraffic64.pl -H host1 -C sneaky
    Example 2: check_iftraffic64.pl -H host1 -C sneaky -i "Intel Pro" -r -B  
    Example 3: check_iftraffic64.pl -H host1 -C sneaky -i 5
    Example 4: check_iftraffic64.pl -H host1 -C sneaky -i 5 -B -b 100 -u m --32bit
    Example 5: check_iftraffic64.pl -H host1 -C sneaky -i 5 -B -I 20 -O 5 -u m 
    Example 6: check_iftraffic64.pl -H host1 -C sneaky -A 192.168.1.1 -B -b 100 -u m 
    Example 7: check_iftraffic64.pl -H host1 -C sneaky -A 192.168.1.1 --force --32bit 
    Example 8: check_iftraffic64.pl -H host1 --username admin --authpassword sneaky  
    Example 9: check_iftraffic64.pl -H host1 --username admin --authpassword sneaky123 --privpassword reallysneaky --privprotocol 3DES  

    Options:


    -b, --bandwidth INTEGER
    -I, --inBandwidth INTEGER
        Interface maximum speed in kilo/mega/giga/bits per second. Applied to 
	both IN and OUT if out (-O) max speed is not provided. Requires -u.
    -O, --outBandwidth INTEGER
        Interface maximum speed in kilo/mega/giga/bits per second. Applied to
	OUT traffic.  Uses the same units value given for -b. Requires -u. 
    -i, --interface STRING
        Interface Name
    -M, --max INTEGER
	Max Counter Value (in bits) of net devices in giga/mega/kilo/bits. Requires -u.
    -r, --regexp
        Use regexp to match NAME in description OID
    -u, --units STRING
        g=gigabits/s,m=megabits/s,k=kilobits/s,b=bits/s. Required if -b, -I, -M,
	or -O are used.

    -A, --address STRING (IP Address)
	IP Address to use when determining the interface index to use. Can be 
	used when the index changes frequently or as in the case of Windows 
	servers the index is different depending on the NIC installed.
    -C, --community STRING 
        SNMP Community.
    -H, --host STRING or IPADDRESS
        Check interface on the indicated host.
    -c, --critical INTEGER
        % of bandwidth usage necessary to result in critical status (default: 98%)
    -w, --warning INTEGER
        % of bandwidth usage necessary to result in warning status (default: 85%)

    --32bit FLAG
	Set to use 32 bit counters instead of 64 bit (default: 64 bit).
    -B, --bits FLAG
	Display results in bits per second b/s (default: Bytes/s)
    -f, --force FLAG
	Set to force either 64 bit or 32 bit only checking (32 bit requires --32bit flag).
    -d, --debug INTEGER
	Output some debug info, not supported inside of Nagios but may be useful
	from the command line.  Levels 1-4 can be specified, 4 being the most information.
    -h, --help
	Displays this help text
    -L, --list FLAG (on/off)
	Tell plugin to list available interfaces. This is not supported inside 
	of Nagios but may be useful from the command line.
    -v, --Version STRING
	Set SNMP version (defaults to 2).  Version 2 or 3 required for 64 bit counters.

    --authpassword STRING
	Set v3 authorization password.
    --authprotocol STRING
	Set v3 authorization protocol (default: MD5).
    --privpassword STRING
	Set v3 privilege (encryption) string.
    --privprotocol STRING
	Set v3 privilege (encryption) protocol (default: DES).
EOU

}

