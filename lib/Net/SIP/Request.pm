###########################################################################
# package Net::SIP::Request
# subclass from Net::SIP::Packet for managing the request packets
# has methods for creating ACK, CANCEL based on the request (and response)
# and for adding Digest authorization (md5+qop=auth only) to the
# request based on the requirements in the response
###########################################################################

use strict;
use warnings;

package Net::SIP::Request;
use base 'Net::SIP::Packet';
use Net::SIP::Debug;
use Net::SIP::Util 'invoke_callback';

use Digest::MD5 'md5_hex';

###########################################################################
# Redefine methods from Net::SIP::Packet, no need to find out dynamically
###########################################################################
sub is_request  {1}
sub is_response {0}

###########################################################################
# Accessors for method and URI
###########################################################################
sub method      { return (shift->as_parts())[0] }
sub uri         { return (shift->as_parts())[1] }

sub set_uri {
	my Net::SIP::Request $self = shift;
	$self->{text} = shift;
}

###########################################################################
# set cseq
# Args: ($self,$number)
#   $number: new cseq number
# Returns: $self
###########################################################################
sub set_cseq {
	my Net::SIP::Request $self = shift;
	my $cseq = shift;
	$self->set_header( cseq => "$cseq ".$self->method );
	return $self;
}

###########################################################################
# create ack to response based on original request
# see RFC3261 "17.1.1.3 Construction of the ACK Request"
# Args: ($self,$response)
#  $response: Net::SIP::Response object for request $self
# Returns: $cancel
#  $ack: Net::SIP::Request object for ACK method
###########################################################################
sub create_ack {
	my Net::SIP::Request $self = shift;
	my $response = shift;
	# ACK uses cseq from request
	$self->cseq =~m{(\d+)};
	my $cseq = "$1 ACK";
	my $header = {
		'call-id' => scalar($self->get_header('call-id')),
		from      => scalar($self->get_header('from')),
		# unlike CANCEL the 'to' header is from the response
		to        => [ $response->get_header('to') ],
		via       => [ ($self->get_header( 'via' ))[0] ],
		route     => [ $self->get_header( 'route' ) ],
		cseq      => $cseq,
	};
	return Net::SIP::Request->new( 'ACK',$self->uri,$header );
}

###########################################################################
# Create cancel for request
# Args: $self
# Returns: $cancel
#   $cancel: Net::SIP::Request containing CANCEL for $self
###########################################################################
sub create_cancel {
	my Net::SIP::Request $self = shift;
	# CANCEL uses cseq from request
	$self->cseq =~m{(\d+)};
	my $cseq = "$1 CANCEL";
	my $header = {
		'call-id' => scalar($self->get_header('call-id')),
		from      => scalar($self->get_header('from')),
		# unlike ACK the 'to' header is from the original request
		to        => [ $self->get_header('to') ],
		via       => [ ($self->get_header( 'via' ))[0] ],
		route     => [ $self->get_header( 'route' ) ],
		cseq      => $cseq,
	};
	return Net::SIP::Request->new( 'CANCEL',$self->uri,$header );
}

###########################################################################
# Create response to request
# Args: ($self,$code,$msg;$args,$body)
#   $code: numerical response code
#   $msg:  text for response code
#   $args: additional args for SIP header
#   $body: body as string
# Returns: $response
#   $response: Net::SIP::Response
###########################################################################
sub create_response {
	my Net::SIP::Request $self = shift;
	my ($code,$msg,$args,$body) = @_;

	my %header = (
		cseq      => scalar($self->get_header('cseq')),
		'call-id' => scalar($self->get_header('call-id')),
		from      => scalar($self->get_header('from')),
		to        => [ $self->get_header('to') ],
		'record-route'  => [ $self->get_header( 'record-route' ) ],
		via       => [ $self->get_header( 'via' ) ],
		$args ? %$args : ()
	);
	return Net::SIP::Response->new($code,$msg,\%header,$body);
}


###########################################################################
# Authorize Request based on credentials in response using
# Digest Authorization specified in RFC2617
# Args: ($self,$response,@args)
#   $response: Net::SIP::Response for $self which has code 401 or 407
#   @args: either [ $user,$pass ] if there is one user+pass for all realms
#       or { realm1 => [ $user,$pass ], realm2 => [...].. }
#       for different user,pass in different realms
#       or callback(realm)->[ user,pass ]
# Returns:  0|1
#    1: if (proxy-)=authorization headers were added to $self
#    0: if $self was not modified, e.g. no usable authenticate
#       headers were found
###########################################################################
sub authorize {
	my Net::SIP::Request $self = shift;
	my ($response,$user2pass) = @_;

	# find out format of user2pass
	my ($default_upw,$realm2upw,$cb_upw);
	if ( ref($user2pass) eq 'ARRAY' && ! ref( $user2pass->[0] )) {
		$default_upw = $user2pass;
	} elsif ( ref($user2pass) eq 'HASH' ) {
		$realm2upw = %$user2pass;
	} else {
		$cb_upw = $user2pass;
	}


	my $auth = 0;
	my %auth_map = (
		'proxy-authenticate' => 'proxy-authorization',
		'www-authenticate' => 'authorization',
	);
	while ( my ($req,$resp) = each %auth_map ) {
		if ( my @auth = $response->get_header_hashval( $req ) ) {
			foreach my $a (@auth) {
				my $h = $a->{parameter};

				# RFC2617
				# we support only md5 (not md5-sess or other)
				# and only empty qop or qop=auth (not auth-int or other)

				if ( lc($a->{data}) ne 'digest'
					|| $h->{algorithm} && lc($h->{algorithm}) ne 'md5'
					|| $h->{qop} && lc($h->{qop}) ne 'auth' ) {
					no warnings;
					#warn "unsupported authorization method $a->{data} method=$h->{method} qop=$h->{qop}";
					next;
				}
				my $realm = $h->{realm};
				my $upw = 
					$cb_upw      ? invoke_callback( $cb_upw, $realm ) :
					$realm2upw   ? $realm2upw->{$realm} :
					$default_upw ? $default_upw :
					next;

				# for meaning of a1,a2... and for the full algorithm see RFC2617, 3.2.2
				my $a1 = join(':',$upw->[0],$realm,$upw->[1] ); # 3.2.2.2
				my $a2 = join(':',$self->method,$self->uri );   # 3.2.2.3, qop == auth|undef

				my %digest = (
					username => $upw->[0],
					realm => $realm,
					nonce => $h->{nonce},
					uri => $self->uri,
				);
				$digest{opaque} = $h->{opaque} if defined $h->{opaque};

				# 3.2.2.1
				if ( $h->{qop} ) {
					my $nc = $digest{nc} = 1;
					my $cnonce = $digest{cnonce} = sprintf("%08x",rand(2**32));
					$digest{qop} = $h->{qop};
					$digest{response} = md5_hex( join(':',
						md5_hex($a1),
						$h->{nonce},
						$nc,
						$cnonce,
						$h->{qop},
						md5_hex($a2)
					));
				} else {
					# 3.2.2.1 compability with RFC2069
					$digest{response} = md5_hex( join(':',
						md5_hex($a1),
						$h->{nonce},
						md5_hex($a2),
					));
				}

				# RFC2617 has it's specific ideas what should be quoted and what not
				# so we assemble it manually
				my $header = qq[Digest username="$digest{username}", realm="$digest{realm}",].
					qq[ nonce="$digest{nonce}", uri=$digest{uri}, response="$digest{response}"];
				$header.= qq[, opaque="$digest{opaque}"] if defined $digest{opaque};
				$header.= qq[, cnonce="$digest{cnonce}"] if defined $digest{cnonce};
				$header.= qq[, qop=$digest{qop}] if defined $digest{qop};
				$self->add_header( $resp, $header );
				$auth++;
			}
		}
	}

	return if !$auth; # no usable authenticate headers found

	# increase cseq, because this will be a new request, not a retransmit
	$self->cseq =~m{^(\d+)(.*)};
	$self->set_header( cseq => ($1+1).$2 );

	return 1;
}

1;
