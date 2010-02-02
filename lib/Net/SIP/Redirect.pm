###########################################################################
# package Net::SIP::Redirect
# uses Registrar to redirect incoming calls based on the information
# provided by the registrar
###########################################################################

use strict;
use warnings;

package Net::SIP::Redirect;
use fields qw(dispatcher registrar);
use Net::SIP::Debug;
use Net::SIP::Util ':all';

sub new {
	my ($class,%args) = @_;
	my $self = fields::new($class);
	%$self = %args;
	$self->{dispatcher} or croak( "no dispatcher given" );
	$self->{registrar} or croak( "no registrar given" );
	return $self;
}

sub receive {
	my Net::SIP::Redirect $self = shift;
	my ($packet,$leg,$addr) = @_;

	# accept only INVITEs
	$packet->is_request or return;
	my $method = $packet->method;
	if ( $method eq 'ACK' ) {
		# if I got an ACK cancel delivery of response to INVITE
		 $self->{dispatcher}->cancel_delivery( $packet->tid );
		 return -1; # don't process in next part of chain
	} elsif ( $method ne 'INVITE' ) {
		return; # don't process myself
	}

	my $key = (sip_uri2parts($packet->uri))[3];
	my $resp;
	if ( my @contacts = $self->{registrar}->query($key)) {
		$resp = $packet->create_response('302','Moved Temporarily');
		$resp->add_header( contact => $_ ) for(@contacts);
	} else {
		$resp = $packet->create_response('404','Not found');
	}
	$self->{dispatcher}->deliver( $resp,
		leg => $leg, dst_addr => $addr );
	return $resp->code;
}

1;
