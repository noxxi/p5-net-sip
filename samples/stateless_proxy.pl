###########################################################################
# Stateless proxy
# listens on multiple legs and forwards SIP packets between the legs
# TODO: do NAT
###########################################################################

use strict;
use warnings;
use IO::Socket::INET;
use Getopt::Long qw(:config posix_default bundling);
use List::Util 'first';

use Net::SIP;
use Net::SIP::Util ':all';
use Net::SIP::Debug;

sub usage {
	print STDERR "ERROR: @_\n" if @_;
	print STDERR <<EOS;
usage: $0 [ basic_options ] ( 
	--leg ip[:port] 
	[ --registrar ] 
	[ --domain domain ]* 
	[ --proxy host[:port] 
)+

Listens on given local addresses and forwards SIP packets between
the created legs. For each leg it can specify a number of domains,
which are used on this side of the leg, if none are specified everything
is accepted. If option --registrar is given it will work as a registrar
for the specified domains on this leg.

Basic options:
  -d|--debug [level]           Enable debugging
  -h|--help                    Help (this info)
Leg specific options:
  -L|--leg  ip[:port]          specify leg
  -D|--domain domain           specify domain on legs side
  -P|--proxy host[:port]       send all packets on leg via host as proxy
  -r|--registrar               work as registrar on this leg

Example:

  Listen on 192.168.0.2:5060 and accept requests from example.com and work
  as registrar for example.com. Forward SIP packets to 192.168.178.3:5060.
  On 192.168.178.3:5060 requests from everywhere, but only for example.com
  are accepted.

  $0 -d 50 \
  --leg 192.168.0.2:5060 --domain example.com -r \
  --leg 192.168.178.3:5060 --proxy 192.168.178.3

EOS
	exit( @_ ? 1:0 );
}

###################################################
# Get options
###################################################

my (%legs,$debug);
my (@domains,$be_registrar,$proxy,$leg);
my $check_leg = sub {
	my (undef,$val) = @_;
	if ( $leg ) {
		$legs{$leg} = {
			domains => @domains ? [ @domains ] : undef,
			registrar => $be_registrar,
			proxy => $proxy,
		};
		(@domains,$be_registrar,$proxy) = ();
	}
	$leg = $val;
};
GetOptions(
	'd|debug:i'   => \$debug,
	'h|help'      => sub { usage() },
	'L|leg=s'     => $check_leg,
	'r|registrar' => \$be_registrar,
	'D|domain=s'  => \@domains,
	'P|proxy=s'   => \$proxy,
) || usage( "bad option" );
Net::SIP::Debug->level( $debug || 1 ) if defined $debug;
%legs or usage( 'no addr to listen' );

###################################################
# ...
###################################################

my (%domain2leg,@leg2proxy);
while ( my ($addr,$opt) = each %legs ) {

	# each legs accepts all domains which are available
	# on all other legs
	my @accept_domains;
	foreach my $opt2 ( values %legs ) {
		next if $opt == $opt2;
		my $dom = $opt2->{domains};
		if ( $dom and ! first { $_ eq '*' } @$dom ) {
			push @accept_domains,@$dom
		} else {
			# accept all
			@accept_domains = ();
			last
		}
	}
	if ( my $dom = $opt->{domains} ) {
		map { $domain2leg{$_} = $leg } @$dom
	}
	if ( my $p = $opt->{proxy} ) {
		push @leg2proxy, [ $leg,$p ]
	}
	$opt->{leg} = myLeg->new( 
		addr => $addr,
		@accept_domains ? ( accept_domains => \@accept_domains ):(),
	);
}

my $disp = Net::SIP::Dispatcher->new( 
	legs => map { $_->{leg} } values(%legs),
	%domain2leg ? ( domain2leg => \%domain2leg ):(),
	leg2proxy => \@leg2proxy,
);

my %registrar;
foreach my $opt ( values %legs ) {
	$opt->{registrar} || next;
	$registrar{ $opt->{leg} } = Net::SIP::Registrar->new( 
		dispatcher => $disp,
		domains    => $opt->{domains},
	);
}

my $registrar = %registrar 
	? myRegistrar->new( %registrar ) 
	: undef;

Net::SIP::StatelessProxy->new( 
	dispatcher => $disp,
	registrar => $registrar
);
$disp->loop;

###################################################
# myRegistrar contains multiple registrars
# the receive method checks based on the incoming
# leg, if one of the registrars is responsable
###################################################

package myRegistrar;
sub new {
	my ($class,%hash) = @_;
	# Net::SIP::Registrar objects indexed by string
	# representation of leg
	return bless \%hash,$class
}

sub receive {
	my myRegistrar $self = shift;
	my ($packet,$leg,$addr) = @_;
	# return undef if not registrar for leg, otherwise
	# let it handle by the registrar object
	my $reg = $self->{$leg} || return; 
	return $reg->receive( @_ );
}


###################################################
# myLeg restricts forwarding to specific domains
# in forward_incoming
###################################################

package myLeg;
use base 'Net::SIP::Leg';
use fields qw( accept_domains );
use Net::SIP::Util 'sip_uri2parts';

sub new {
	my ($class,%args) = @_;
	my $accept_domains = delete $args{accept_domains};
	my $self = $class->SUPER::new(%args);
	if ( $accept_domains ) {
		$self->{accept_domains} = map { $_ => 1 } @$accept_domains;
	}
	return $self;
}

sub forward_incoming {
	my myLeg $self = shift;
	my $packet = shift;
	if ( ( my $ad = $self->{accept_domains} )
		and $packet->is_request ) {
		my $domain = my $odomain = sip_uri2parts( $packet->uri );
		my $accept = 0;
		while ( $domain ) {
			if ( $ad->{$domain} || $ad->{ "*.$domain" } ) {
				$accept = 1;
				last;
			}
			$domain =~s{^[^\.]+\.?}{};
		}
		if ( !$accept ) {
			return [ 404,"forwarding for '$odomain' denied" ]
		}
	}
	return $self->SUPER::forward_incoming( $packet );
}
