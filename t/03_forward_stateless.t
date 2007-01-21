use strict;
use warnings;
use Net::SIP;
use Test::More tests => 6;

################################################################
# test delivery of packets through stateless proxy
# works by defining domain2leg to specify leg for domain(s).
# the 'deliver' method of the legs are redefined so that no
# actual delivery gets done but that delivery only gets simulated.
# TODO: 
# - check with requests which have route header
# - check with responses (routing based on via header)
# - check that route and via header gets stripped and contact
#   header rewritten
# - check strict routes vs. loose routers (manipulate URI
#   and route header to simulate behavior)
# - more tests for Net::SIP::Dispatcher::resolve_uri (not
#   only related to stateless proxy)
################################################################


my $dummy = '127.0.0.5:5060'; # never used for delivery
my $delivered_via;
{
	package myLeg;
	use base 'Net::SIP::Leg';
	use Net::SIP::Debug;
	use Net::SIP::Util 'invoke_callback';
	sub deliver {
		my ($self,$packet,$addr,$callback) = @_;
		$delivered_via = $self;
		DEBUG( "deliver through $self" );
		invoke_callback( $callback,0 );
	}
}

my %leg_setup = ( addr => '127.0.0.1', port => 0 );
my $leg_default     = myLeg->new( %leg_setup ) || die;
my $leg_example_com = myLeg->new( %leg_setup ) || die;
my $leg_example_org = myLeg->new( %leg_setup ) || die;

my $loop = Net::SIP::Dispatcher::Eventloop->new;
my $disp = Net::SIP::Dispatcher->new( 
	[ 
		$leg_default,
		$leg_example_com,
		$leg_example_org 
	],
	$loop,
	domain2leg => {
		'example.com'   => $leg_example_com,
		'example.org'   => $leg_example_org,
		'*.example.org' => $leg_example_org,
		'*'             => $leg_default,
	},
	leg2proxy => [
		[ $leg_example_com, $dummy ],
		[ $leg_example_org, $dummy ],
		[ $leg_default,     $dummy ],
	]
) || die;

my $proxy = Net::SIP::StatelessProxy->new(
	dispatcher => $disp 
);
$disp->set_receiver( $proxy );

# -------------------------------------------------------------------------
# fw( address,                      incoming_leg,     expected_outgoing_leg )
# -------------------------------------------------------------------------
fw( 'sip:me@example.com',           $leg_default,     $leg_example_com );
fw( 'sip:me@example.com',           $leg_example_org, $leg_example_com );
fw( 'sip:me@somewhere.example.com', $leg_example_org, $leg_default );
fw( 'sip:me@example.org',           $leg_example_com, $leg_example_org );
fw( 'sip:me@somewhere.example.org', $leg_example_com, $leg_example_org );
fw( 'sip:me@whatever',              $leg_example_com, $leg_default );

# DONE


# -------------------------------------------------------------------------
sub fw {
	my ($to,$incoming_leg,$expected_outgoing_leg) = @_;
	$delivered_via = undef;
	my $request = Net::SIP::Request->new( 'INVITE', $to, {
		to => $to,
		cseq => '1 INVITE',
		'call-id' => sprintf( "%8x\@somewhere.com", rand(2**16 )),
		from => 'me@somewhere.com',
	});
	$disp->receive( $request,$incoming_leg,$dummy );
	$loop->loop(1,\$delivered_via );
	ok( $delivered_via, $expected_outgoing_leg );
}


