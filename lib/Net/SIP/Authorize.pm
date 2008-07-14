###########################################################################
# package Net::SIP::Authorize
# use in ReceiveChain in front of StatelessProxy, Endpoint.. to authorize request
# by enforcing authorization and only handling request only if it was
# fully authorized
###########################################################################

use strict;
use warnings;

package Net::SIP::Authorize;
use Carp 'croak';
use Net::SIP::Debug;
use Net::SIP::Util ':all';
use Digest::MD5 'md5_hex';
use fields qw( realm opaque user2pass user2a1 i_am_proxy dispatcher );

###########################################################################
# creates new Authorize object
# Args: ($class,%args)
#   %args
#     realm: which realm to announce
#     user2pass: hash of (username => password) or callback which returns
#        password if given username
#     dispatcher: Dispatcher object
#     i_am_proxy: true if should send Proxy-Authenticate, not WWW-Authenticate
# Returns: $self
###########################################################################
sub new {
	my ($class,%args) = @_;
	my $self = fields::new( $class );
	$self->{realm} = $args{realm} || 'p5-net-sip';
	$self->{opaque} = $args{opaque};
	
	$args{user2pass} || $args{user2a1} || croak 'no user2pass or user2a1 known';
	
	$self->{user2pass} = $args{user2pass};
	$self->{user2a1} = $args{user2a1}; 
	$self->{i_am_proxy} = $args{i_am_proxy};
	$self->{dispatcher} = $args{dispatcher} || croak 'no dispatcher';
	return $self;
}

###########################################################################
# handle packet, called from Net::SIP::Dispatcher on incoming requests
# Args: ($self,$packet,$leg,$addr)
#  $packet: Net::SIP::Request
#  $leg: Net::SIP::Leg where request came in (and response gets send out)
#  $addr: ip:port where request came from and response will be send
# Returns: TRUE if it handled the packet 
###########################################################################
sub receive {
	my Net::SIP::Authorize $self = shift;
	my ($packet,$leg,$addr) = @_;

	# don't handle responses
	if ( $packet->is_response ) {
		DEBUG( 100,"pass thru response" );
		return;
	}

	# check authorization on request
	my ($rq_key,$rs_key,$acode) = $self->{i_am_proxy}
		? ( 'proxy-authorization', 'proxy-authenticate',407 )
		: ( 'authorization','www-authenticate',401 )
		;
	my @auth = $packet->get_header( $rq_key );
	my $user2pass = $self->{user2pass};
	my $user2a1 = $self->{user2a1};
	my $realm = $self->{realm};
	my $opaque = $self->{opaque};

	# there might be multiple auth, pick the right realm
	my (@keep_auth,$authorized);	
	
	foreach my $auth ( @auth ) {
		# RFC 2617
		my ($data,$param) = sip_hdrval2parts( $rq_key => $auth );
		if ( $param->{realm} ne $realm ) {
			# not for me
			push @keep_auth,$auth;
			next;
		}
		if ( defined $opaque ) {
			if ( ! defined $param->{opaque} ) {
				DEBUG( 10,"expected opaque value, but got nothing" );
				next;
			} elsif ( $param->{opaque} ne $opaque ) {
				DEBUG( 10,"got wrong opaque value '$param->{opaque}', expected '$opaque'" );
				next;
			}
		}

		my ($user,$nonce,$uri,$resp,$qop,$cnonce,$algo ) = 
			@{$param}{ qw/ username nonce uri response qop cnonce algorithm / };
		if ( lc($data) ne 'digest'
			|| ( $algo && lc($algo) ne 'md5' )
			|| ( $qop && $qop ne 'auth' ) ) {
			DEBUG( 10,"unsupported response: $auth" );
			next;
		};

		# we support with and w/o qop	
		# get a1_hex from either user2a1 or user2pass
		my $a2 = join( ':',$packet->method,$uri );
		my $a1_hex;
		if ( ref($user2a1)) {
			if ( ref($user2a1) eq 'HASH' ) {
				$a1_hex = $user2a1->{$user}
			} else {
				$a1_hex = invoke_callback( $user2a1,$user,$realm );
			}
		} 
		if ( ! defined($a1_hex) && ref($user2pass)) {
			my $pass;
			if ( ref($user2pass) eq 'HASH' ) {
				$pass = $user2pass->{$user}
			} else {
				$pass = invoke_callback( $user2pass,$user );
			}
			$a1_hex = md5_hex(join( ':',$user,$realm,$pass ));
		} 

		my $want_response;
		if ( $qop ) {
			# 3.2.2.1
			$want_response = md5_hex( join( ':',
				$a1_hex,
				$nonce,
				1,
				$cnonce,
				$qop,
				md5_hex($a2)
			));
		} else {
			 # 3.2.2.1 compability with RFC2069			 
			 $want_response = md5_hex( join( ':',
			 	$a1_hex,
				$nonce,
				md5_hex($a2)
			));
		}

		if ( $resp eq $want_response ) {
			$authorized = 1;
		}
	}

	# if authorized remove authorization data from this realm
	# and pass packet thru
	if ( $authorized ) {
		DEBUG( 10, "Request authorized". $packet->dump );
		# set header again
		$packet->set_header( $rq_key => \@keep_auth );
		return;
	}

	# not authorized yet, ask to authenticate
	# keep it simple RFC2069 style
	my $digest = qq[Digest algorithm=MD5, realm="$realm",].
		( defined($opaque) ? qq[ opaque="$opaque",] : '' ).
		' nonce="'. md5_hex( $realm.rand(2**32)).'"';

	my $resp = $packet->create_response(
		$acode,
		'Authorization required',
		{ $rs_key => $digest }
	);

	$self->{dispatcher}->deliver( $resp, leg => $leg, dst_addr => $addr );
	
	# return $acode (TRUE) to show that packet should
	# not passed thru
	return $acode;
}

1;
