#!/usr/local/bin/perl

###########################################################################
# $Id: check_sieve.pl 214 2014-01-08 09:37:22Z alan $
#
# check SIEVE connections as per rfc 5804
#
# Copyright (c) 2013 Persistent Objects Ltd - http://p-o.co.uk
#
# Dual licence AL/GPL
#
# Artistic License 2.0 (http://www.perlfoundation.org/artistic_license_2_0)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
###########################################################################
# Inspired by check_stuff.pl, originally by Nathan Vonnahme, n8v at users
# dot sourceforge dot net, July 19 2006
###########################################################################

###########################################################################
# prologue
use strict;
use warnings;
use IO::Socket::INET6;
use Time::HiRes;
use Nagios::Plugin;

use vars qw($VERSION $PROGNAME);
use vars qw($start $duration $sock $family $code $line $implementation);
use vars qw($capability $message $peer_address);
$VERSION = '1.02';

# get the base name of this script for use in the examples
use File::Basename;
$PROGNAME = basename($0);


# Instantiate Nagios::Plugin object (the 'usage' parameter is mandatory)
my $p = Nagios::Plugin->new(
    usage => "Usage: %s
    [ -v|--verbose ]
    [ -H|--host <host>]
    [ -P|--port <port>]
    [ -4|--ipv4]
    [ -6|--ipv6]
    [ -t|--timeout <timeout>]
    [ -c|--critical=<critical threshold> ] 
    [ -w|--warning=<warning threshold> ]  
    [ -r|--result = <INTEGER> ]",
    version => $VERSION,
    blurb => 'This plugin checks for a running Sieve daemon.', 

	extra => "

  Examples:

  $PROGNAME -H localhost -P 4190 -w 5 -c 10
  Returns a warning if the response is greater than 5 seconds,
  or a critical error if it is greater than 10.

  "
);

###########################################################################
# define, document and get the command line options.
#   see the command line option guidelines at 
#   http://nagiosplug.sourceforge.net/developer-guidelines.html#PLUGOPTIONS
# usage, help, version, timeout and verbose are defined by default.

$p->add_arg(
	spec => 'host|H=s',
	help => 
qq{-H, --host=STRING
   Host where the running daemon can be found, defaults to localhost.},
	required => 0,
	default => 'localhost',
);

$p->add_arg(
	spec => 'port|P=i',
	help => 
qq{-P, --port=INTEGER
   Port number for the running daemon, default 4190.},
	required => 0,
	default => 4190,
);

$p->add_arg(
	spec => 'warning|w=i',
	help => 
qq{-w, --warning=INTEGER:INTEGER
   Minimum and maximum number of allowable result, outside of which a
   warning will be generated.  If omitted, no warning is generated.},

	required => 0,
	default => 5,
);

$p->add_arg(
	spec => 'critical|c=i',
	help => 
qq{-c, --critical=INTEGER:INTEGER
   Minimum and maximum number of the generated result, outside of
   which a critical will be generated. },
	required => 0,
	default => 10,
);

$p->add_arg(
	spec => 'ipv6|6',
	help => 
qq{-6, --ipv6
   Use ipv6. },
);
$p->add_arg(
	spec => 'ipv4|4',
	help => 
qq{-4, --ipv4
   Use ipv4. },
);

$p->add_arg(
	spec => 'result|r=i',
	help => 
qq{-r, --result=INTEGER
   Supplied result for testing.},
	required => 0,
);

###########################################################################
# Parse arguments and process standard ones (e.g. usage, help, version)
$p->getopts;

###########################################################################
# perform sanity checking on command line options
if ( (defined $p->opts->result) && ($p->opts->result < 0 || $p->opts->result > 20) )  {
    $p->nagios_die( ' invalid number supplied for the -r option ' );
}
unless ( defined $p->opts->warning || defined $p->opts->critical ) {
	$p->nagios_die('Please supply a warning or critical threshold argument', UNKNOWN);
}
if ( $p->opts->warning == $p->opts->critical ) {
	$p->nagios_die('Critical is equal to Warning', UNKNOWN);
}
if ( $p->opts->warning > $p->opts->critical ) {
	$p->nagios_die('Critical is longer than Warning', UNKNOWN);
}


###########################################################################
# Set the protocol family
if ( $p->opts->ipv6) {
	$family = AF_INET6;
}elsif ( $p->opts->ipv4) {
	$family = AF_INET;
}


###########################################################################
# Set the timeout
#$SIG{'ALRM'} = sub { $p->nagios_die("Timeout", CRITICAL); };
alarm $p->opts->timeout;


###########################################################################
# Check Sieve daemon is running

$start = Time::HiRes::time;

$sock = IO::Socket::INET6->new(
	PeerAddr => $p->opts->host,
	PeerPort => $p->opts->port,
	Domain   => $family,
	Proto    => 'tcp',
	Timeout  => $p->opts->timeout
) or $p->nagios_exit(UNKNOWN, 'Unable to connect to: '. $p->opts->host .':'.$p->opts->port);
$peer_address = $sock->peerhost() . ':' . $sock->peerport();

SOCKETLOOP:
while (defined($line = <$sock>)) {
	#print $line;
	if ($line =~ /SIEVE/) {
		$capability = $line;
	}
	if ($line =~ /implementation/i) {
		$implementation = $line;
	}
	
	last SOCKETLOOP if $line =~ /^OK/;
}
close($sock);

# Get rid of quotes if they have been used
$implementation =~ tr/0-9a-zA-Z. //csd;
$implementation = substr $implementation, 15;
$capability =~ tr/0-9a-zA-Z. //cd;
$capability = substr $capability, 6;

$duration = sprintf("%.4f",Time::HiRes::time - $start);

###########################################################################
# check the result against the defined warning and critical thresholds,
# output the result and exit
if ($p->opts->result) {
	# We are testing
	$duration = $p->opts->result;
}
$code = $p->check_threshold(
	check => $duration,
	warning => $p->opts->warning,
	critical => $p->opts->critical,
);
$message .= $duration . ' second response time;';

if ($p->opts->verbose) {
	$message .= ' connected to ' . $peer_address . ';';
	if ($implementation) {
		$message .= ' ' . $implementation . ';';
	}
	$message .= ' [' . $capability . '];';
}

# Output the result
$p->nagios_exit($code, $message);
