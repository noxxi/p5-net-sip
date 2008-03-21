use strict;
use warnings;
use Net::SIP ':all';

# Proof of concept how to send and receive MESSAGE
# Bugs lurking inside...

# sending message over udp (the only currently supported protocol)
# is not such a good idea because:
# from rfc3428:
#   In particular, UAs that support the MESSAGE request MUST 
#   implement end-to-end authentication, body integrity, and body 
#   confidentiality mechanisms.

# Net::SIP::Simple has no support for arbitrary messages, so we
# use it only for easy setup of the basic infrastructure and then
# use the endpoint inside the Simple object directly to send and
# receive packets
# Bug: it does only MESSAGE, no OPTIONS etc . Unexpected packets
# simply get ignored

my ($sleg,$saddr) = create_socket_to( '127.0.0.1' );
defined( my $pid = fork()) || die "fork failed: $!";

if ( $pid == 0 ) {

	# SERVER: wait for MESSAGE, print it and reply with 200
	my $ua = Simple->new( leg => $sleg, from => 'uas@example.com' );
	my $receive = sub {
		 my ($endpoint,$ctx,$packet,$leg,$from) = @_;
		 if ( $packet->is_request and $packet->method eq 'MESSAGE' ) {
		 	warn "GOT Message\n-----------------------\n".
				($packet->as_parts)[3].
				"\n------------------\n";
			# reply with 2xx
			my $resp = $packet->create_response( '200','OK' );
			$resp->set_header( 'allow' => 'MESSAGE' );
			$endpoint->new_response( undef,$resp,$leg,$from );
		} else {
			DEBUG( 1,"ignored packet ".$packet->dump );
		}
	};
	$ua->{endpoint}->set_application( $receive );
	$ua->loop;
	exit;

} else {

	# CLIENT: send message request, wait for 200 reply and exit

	close($sleg);
	my $sock = create_socket_to( $saddr );
	my $ua = Simple->new( leg => $sock,from => 'uac@example.com' );
	my $stop;
	my $callback = sub {
		my ($endpoint,$ctx,$err,$code,$packet,$leg,$from) = @_;
		warn "UAC got data: ".$packet->as_string;
		$stop = 1;
	};
	$ua->{endpoint}->new_request( 'MESSAGE',
		{ from => $ua->{from}, to => 'uas@example.com' },
		$callback,
		"this is the message",
		uri => "sip:$saddr",
		'content-type' => 'text/plain',
		'allow' => 'MESSAGE',
	);
	$ua->loop( \$stop );
	kill(9,$pid);
}

wait;
