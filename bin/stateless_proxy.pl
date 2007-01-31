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

$check_leg->(); final call
Net::SIP::Debug->level( $debug || 1 ) if defined $debug;
%legs or usage( 'no addr to listen' );

###################################################
# create Legs
###################################################

my (%domain2leg,%domain2proxy);
while ( my ($addr,$opt) = each %legs ) {
	my $leg = $opt->{leg} = Net::SIP::Leg->new( addr => $addr );
	foreach my $dom (@{ $opt->{domains} }) {
		$domain2leg{$dom}   = $leg;
		$domain2proxy{$dom} = $opt->{proxy} if $opt->{proxy};
	}
}

###################################################
# create Dispatcher
###################################################

my $loop = Net::SIP::Dispatcher::Eventloop->new;
my $disp = myDispatcher->new(
	[ map { $_->{leg} } values(%legs) ],
	$loop,
	domain2proxy => \%domain2proxy,
	domain2leg => \%domain2leg,
);

###################################################
# create Registrars on the legs and wraps them
# together into on object
###################################################

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
$disp->set_registrar( $registrar );

###################################################
# create StatelessProxy
###################################################

my $stateless_proxy = Net::SIP::StatelessProxy->new(
	dispatcher => $disp,
	registrar => $registrar
);
$disp->set_receiver( $stateless_proxy );

###################################################
# run..
###################################################
$loop->loop;


###################################################
###################################################
#
# myRegistrar contains multiple registrars
# the receive method checks based on the incoming
# leg, if one of the registrars is responsable
# asks the registrar if it can rewrite the URI
#
###################################################
###################################################

package myRegistrar;
use Net::SIP::Debug;

sub new {
	my ($class,%hash) = @_;
	# Net::SIP::Registrar objects indexed by string
	# representation of leg
	return bless \%hash,$class
}

sub receive {
	my myRegistrar $self = shift;
	my ($packet,$leg,$addr) = @_;
	DEBUG( "Registrar got ".$packet->dump );
	# return undef if not registrar for leg, otherwise
	# let it handle by the registrar object
	my $reg = $self->{$leg} || return;
	return $reg->receive( @_ );
}

sub query {
	my myRegistrar $self = shift;
	my ($uri,$allowed_legs) = @_;
	$allowed_legs ||= [ $self->{dispatcher}->get_legs ];
	return map { $self->{$_}->query( $uri ) } @$allowed_legs;
}

###################################################
###################################################
#
# myDispatcher handles domain2leg by restricting
# the legs which can deliver
#
###################################################
###################################################

package myDispatcher;
use base 'Net::SIP::Dispatcher';
use Net::SIP::Util 'sip_uri2parts';
use fields qw( domain2leg registrar );
use Errno qw(EHOSTUNREACH);
use Net::SIP::Debug;
use List::Util 'first';

sub new {
	my ($class,$legs,$loop,%args) = @_;
	my $d2l = delete $args{domain2leg};
	my $reg = delete $args{registrar};
	my $self = $class->SUPER::new( $legs,$loop,%args );
	$self->{domain2leg} = $d2l;
	$self->{registrar} = $reg;
	return $self;
}

sub set_registrar {
	my myDispatcher $self = shift;
	$self->{registrar} = shift;
}

sub resolve_uri {
	my myDispatcher $self = shift;
	my ($uri,$dst_addr,$legs,$callback,$allowed_proto,$allowed_legs) = @_;

	# restrict outgoing leg based on domain2leg
	my $d2l = $self->{domain2leg};
	my ($domain,$user,$proto) = sip_uri2parts( $uri ) or do {
		DEBUG( 50,"invalid URI: $uri" );
		invoke_callback( $callback, EHOSTUNREACH );
		return;
	};

	if ( $d2l && %$d2l ) {
		# find leg
		my $leg;
		while (1) {
			last if ( $leg = $d2l->{$domain} );
			$domain =~s{[^\.]+}{};
			last if ( $leg = $d2l->{'*'.$domain} );
			$domain =~s{^\.}{};
		}
		if ( $leg ) {
			$allowed_legs = [ $self->get_legs ] unless
				$allowed_legs && @$allowed_legs;
			if ( ! first { $leg == $_ } @$allowed_legs ) {
				DEBUG( 10,'outgoing leg not allowed' );
				invoke_callback( $callback, EHOSTUNREACH );
				return;
			} else {
				$allowed_legs = [ $leg ]
			}
		}
	}

	if ( my $reg = $self->{registrar} ) {
		my $addr = "$proto:$user\@$domain";
		DEBUG( "lookup $addr at $reg" );
		if ( my @contacts = $reg->query( $addr, $allowed_legs ) ) {
			# pick first, rewrite URI
			DEBUG( 10, "rewrite '$uri' to '$contacts[0]' from registrar" );
			$uri = $contacts[0];
		}
	}

	# continue with SUPER::resolve_uri
	return $self->SUPER::resolve_uri(
		$uri,$dst_addr,$legs,$callback,$allowed_proto,$allowed_legs );
}

