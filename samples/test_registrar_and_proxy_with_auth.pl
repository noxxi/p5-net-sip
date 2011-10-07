#!/ur/bin/perl

# registrar in front of proxy
# requests for registered clients get rewritten so that proxy can
# forward requests
# everything with authorization

use strict;
use warnings;
use Net::SIP;

my $ua = Net::SIP::Simple->new( 
	leg => '127.0.0.1:5000',
	domain => 'example.org',
);


my $proxy = $ua->create_chain([ 
	$ua->create_auth(
		user2pass => {
			'101' => 'secret',
			'102' => 'secret',
		},
	),
	$ua->create_registrar(), 
	$ua->create_stateless_proxy() 
],
);
$ua->loop;

