#!/usr/bin/perl  
###########################################################################
# Invite other party, recv RTP data for some seconds or until other side
# hangs up, then BYE
# optional registration
#
# Most of the code is option parsing and usage, the Net::SIP related code
# is at the end
###########################################################################

use lib "/usr/local/nagios/libexec";
use lib "/usr/lib/nagios/plugins";
use lib "/usr/lib64/nagios/plugins";

use utils qw(%ERRORS);
use strict;
use warnings;
use IO::Socket::INET;
use Sys::Hostname;
use Getopt::Long qw(:config no_ignore_case posix_default bundling);

use Net::SIP;
use Net::SIP::Util 'create_socket_to';
use Net::SIP::Debug;

# Make the Nagios devs happy
$SIG{'ALRM'} = sub {
  print "Something has gone wrong and the check has timed out after 30 secons. This should be looked into\n";
  exit $ERRORS{'UNKNOWN'};
};
alarm 30;


sub usage {
    print STDERR "ERROR: @_\n" if @_;
    print STDERR <<EOS;
usage: $0 [ options ] FROM TO
Makes SIP call from FROM to TO, optional record data
and optional hang up after some time
Options:
  -d|--debug [level]           Enable debugging
  -h|--help                    Help (this info)
  -P|--proxy host[:port]       use outgoing proxy, register there unless registrar given
  -R|--registrar host[:port]   register at given address
  -O|--outfile filename        write received RTP data to file
  -t|--time interval           hang up after interval seconds
  -L|--leg ip[:port]           use given local ip[:port] for outgoing leg
  -C|--contact sipaddr         use given contact address for contact in register and invite
  -T|--to		       phone number to call
  -B|--backup		       second phone number to call if the first check fails
  --username name              username for authorization
  --password pass              password for authorization
  --route host[:port]          add SIP route, can be specified multiple times

Examples:

  $0 -P 172.16.100.1:5060  --username TestUser --password TestPassword -T 12127773456 -B 12017773456 -t 10;

Original Script created by Steffen Ullrich 
Script modified by Noah Guttman

EOS
    exit($ERRORS{'OK'});
}


###################################################
# Get options
###################################################

my ($proxy,$outfile,$registrar,$username,$password,$hangup,$local_leg,$contact);
my (@routes,$debug,$tonumber,$backupnumber);

my $callerror;
my $mediaoutputsize;

my $exitcode;
my $checkresponse;
my $hostname=hostname(); #change this to your hostname
my($addr)=inet_ntoa((gethostbyname($hostname))[4]);


GetOptions(
    'd|debug:i' => \$debug,
    'h|help' => sub { usage() },
    'P|proxy=s' => \$proxy,
    'R|registrar=s' => \$registrar,
    'O|outfile=s' => \$outfile,
    'T|time=i' => \$hangup,
    'L|leg=s' => \$local_leg,
    'C|contact=s' => \$contact,
    'username=s' =>\$username,
    'password=s' =>\$password,
    'route=s' => \@routes,
    'T|to=s' =>\$tonumber,
    'B|backup=s' =>\$backupnumber,
) || usage( "bad option" );


Net::SIP::Debug->level( $debug || 1 ) if defined $debug;

#my ($from,$to) = @ARGV;
#$to || usage( "no target" );

my $from;
my $to;
my $Bto;

if ((($from) && ($to)) && ($Bto)){
  $from = "sip:opsview\@$addr:5060";
  $to = "sip:$tonumber\@$proxy";
  $Bto = "sip:$backupnumber\@$proxy";
}else{
  usage( "bad option" );
}


if (!$outfile){
  my $random = rand();
  $outfile = "/tmp/$random.mediaOUT";
}



# register at proxy if proxy given and no registrar
$registrar ||= $proxy;

###################################################
# find local leg
###################################################
my ($local_host,$local_port);
if ( $local_leg ) {
    ($local_host,$local_port) = split( m/:/,$local_leg,2 );
} elsif ( ! $proxy ) {
    # if no proxy is given we need to find out
    # about the leg using the IP given from FROM
    ($local_host,$local_port) = $from =~m{\@([\w\-\.]+)(?::(\d+))?}
	or die "cannot find SIP domain in '$from'";
}

my $leg;
if ( $local_host ) {
    my $addr = gethostbyname( $local_host )
	|| die "cannot get IP from SIP domain '$local_host'";
    $addr = inet_ntoa( $addr );

    $leg = IO::Socket::INET->new(
	Proto => 'udp',
	LocalAddr => $addr,
	LocalPort => $local_port || 5060,
    );

    # if no port given and port 5060 is already used try another one
    if ( !$leg && !$local_port ) {
	$leg = IO::Socket::INET->new(
	    Proto => 'udp',
	    LocalAddr => $addr,
	    LocalPort => 0
	) || die "cannot create leg at $addr: $!";
    }

    $leg = Net::SIP::Leg->new( sock => $leg );
}

###################################################
# SIP code starts here
###################################################

# create necessary legs
# If I have an only outgoing proxy I could skip this step because constructor
# can make leg to outgoing_proxy itself
#my @legs;
#push @legs,$leg if $leg;
#foreach my $addr ( $proxy,$registrar) {
#    $addr || next;
#    if ( ! grep { $_->can_deliver_to( $addr ) } @legs ) {
#	my $sock = create_socket_to($addr) || die "cannot create socket to $addr";
#	push @legs, Net::SIP::Leg->new( sock => $sock );
#    }
#}

# create user agent
my $ua = Net::SIP::Simple->new(
    from => $from,
    outgoing_proxy => $proxy,
    route => \@routes,
#    legs => \@legs,
    $contact ? ( contact => $contact ):(),
    $username ? ( auth => [ $username,$password ] ):(),
);

# optional registration
if ( $registrar && $registrar ne '-' ) {
    $ua->register( registrar => $registrar );
    die "registration failed: ".$ua->error if $ua->error
}

# invite peer
my $peer_hangup; # did peer hang up?
my $call = $ua->invite( $to,
    # echo back, use -1 instead of 0 for not echoing back
    init_media => $ua->rtp( 'recv_echo', $outfile,0 ),
    recv_bye => \$peer_hangup,
) || die "invite failed: ".$ua->error;
#die "invite failed(call): ".$call->error if $call->error;
if (!($callerror =~ m/Failed/)){
  $checkresponse = "OK: Test call to number $tonumber via proxy $proxy successfull";
  $exitcode=0;
}elsif ($backupnumber){
  $call= $ua->invite( $Bto,
  # echo back, use -1 instead of 0 for not echoing back
                      init_media => $ua->rtp( 'recv_echo', $outfile,0 ),
                      recv_bye => \$peer_hangup,
	            ) || die $ua->error;
  $callerror = $call->error;
  if (!($callerror =~ m/Failed/)){
    $checkresponse = "WARNING: Test call to number primary number $tonumber failed. Test call to number secondary number $backupnumber via proxy $proxy successfull";
    $exitcode=1;
  }else{
    $checkresponse = "CRITICAL: Test call to number $tonumber and test call to number $backupnumber via proxy $proxy $callerror";
    $exitcode=2;
  }
}else{
  $checkresponse = "CRITICAL: Test call to number $tonumber via proxy $proxy $callerror";
  $exitcode=2;	
}



# mainloop until other party hangs up or we hang up after
# $hangup seconds
my $stopvar;
$ua->add_timer( $hangup, \$stopvar ) if $hangup;
$ua->loop( \$stopvar,\$peer_hangup );

# timeout, I need to hang up
if ( $stopvar ) {
  $stopvar = undef;
  #$call->bye( cb_final => \$stopvar );
  #$ua->loop( \$stopvar );
  if (!($callerror =~ m/Failed/)){
    $checkresponse = "$checkresponse with an A-side bye";
    $call->bye( cb_final => \$stopvar );
    $ua->loop( \$stopvar );
  }
}else{
  $checkresponse = "$checkresponse with an B-side bye";
}

if (-s $outfile){
  $checkresponse = "$checkresponse and good media\n";
}else{
  $checkresponse = "$checkresponse and no media\n";
  $exitcode=2;
}

###############
#We need to delete the medio outfile#
my $bashcommand = "rm -rf $outfile";
system($bashcommand);
###############

print "$checkresponse";

if ($exitcode==0){
  exit($ERRORS{'OK'});
}elsif ($exitcode==1){
  exit($ERRORS{'WARNING'});
}elsif ($exitcode==2){
  exit($ERRORS{'CRITICAL'});
}else{
  exit($ERRORS{'UNKNOWN'});
}
