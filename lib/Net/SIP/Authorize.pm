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
use fields qw( realm opaque user2pass user2a1 i_am_proxy dispatcher filter );

###########################################################################
# creates new Authorize object
# Args: ($class,%args)
#   %args
#     realm: which realm to announce
#     user2pass: hash of (username => password) or callback which returns
#        password if given username
#     dispatcher: Dispatcher object
#     i_am_proxy: true if should send Proxy-Authenticate, not WWW-Authenticate
#     filter: hashref with extra verification chain, see packages below.
#      Usage:
#      filter => {
#       # filter chain for registration
#       REGISTER => [
#        # all of this three must succeed (user can regist himself)
#        [ 'ToIsFrom','FromIsRealm','FromIsAuthUser' ],
#        # or this must succeed
#        \&call_back, # callback. If arrayref you MUST set [ \&call_back ]
#       ]
#       # filter chain for invites
#       INVITE => 'FromIsRealm',
#      }
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

	if ( my $f = $args{filter}) {
		croak 'filter must be hashref' if ref($f) ne 'HASH';
		my %filter;
		while (my($method,$chain) = each %$f) {
			$chain = [ $chain ] if ref($chain) ne 'ARRAY';
			map { $_ = [$_] if ref($_) ne 'ARRAY' } @$chain;
			# now we have:
			# method => [[ cb00,cb01,cb02,..],[ cb10,cb11,cb12,..],...]
			# where either the cb0* chain or the cb1* chain or the cbX* has to succeed
			for my $or (@$chain) {
				for (@$or) {
					if (ref($_)) {
						# assume callback
					} else {
						# must have authorize class with verify method
						my $pkg = __PACKAGE__."::$_";
						my $sub = UNIVERSAL::can($pkg,'verify') || do {
							# load package
							eval "require $pkg";
							UNIVERSAL::can($pkg,'verify')
						} or die "cannot find sub ${pkg}::verify";
						$_ = $sub;
					}
				}
			}
			$filter{uc($method)} = $chain;
		}
		$self->{filter} = \%filter;
	}
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
	my $method = $packet->method;

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
			# if wrong credentials ask again for authorization
			last if ! defined $pass;
			$a1_hex = md5_hex(join( ':',$user,$realm,$pass ));
		}

		last if ! defined $a1_hex; # not in user2a1 || user2pass

		# ACK just reuse the authorization from INVITE, so they should
		# be checked against method INVITE
		# for CANCEL the RFC doesn't say anything, so we assume it uses
		# CANCEL but try INVITE if this fails
		my @a2 =
			$method eq 'ACK' ? ("INVITE:$uri") :
			$method eq 'CANCEL' ? ("CANCEL:$uri","INVITE:$uri") :
			("$method:$uri");

		while (my $a2 = shift(@a2)) {
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
				if ($self->{filter} and my $or = $self->{filter}{$method}) {
					for my $and (@$or) {
						$authorized = 1;
						for my $cb (@$and) {
							if ( ! invoke_callback(
								$cb,$packet,$leg,$addr,$user,$realm)) {
								$authorized = 0;
								last;
							}
						}
						last if $authorized;
					}
				} else {
					$authorized = 1;
				}
				last;
			}
		}
	}

	# if authorized remove authorization data from this realm
	# and pass packet thru
	if ( $authorized ) {
		DEBUG( 10, "Request authorized ". $packet->dump );
		# set header again
		$packet->set_header( $rq_key => \@keep_auth );
		return;
	}

	# CANCEL or ACK cannot be prompted for authorization, so
	# they should provide the right data already
	# unauthorized CANCEL or ACK are only valid as response to
	# 401/407 from this Authorize, so they should not be propagated
	if ($method eq 'ACK') {
		# cancel delivery of response to INVITE
		$self->{dispatcher}->cancel_delivery( $packet->tid );
		return $acode;
	} elsif ($method eq 'CANCEL') {
		return $acode;
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

###########################################################################
# additional verifications
#  Net::SIP::Authorize::FromIsRealm - checks if the domain in 'From' is
#   the same as the realm in 'Authorization'
#  Net::SIP::Authorize::FromIsAuthUser - checks if the user in 'From' is
#   the same as the username in 'Authorization'
#  Net::SIP::Authorize::ToIsFrom - checks if 'To' and 'From' are equal
#
# Args each: ($packet,$leg,$addr,$auth_user,$auth_realm)
#  $packet: Net::SIP::Request
#  $leg: Net::SIP::Leg where request came in (and response gets send out)
#  $addr: ip:port where request came from and response will be send
#  $auth_user: username from 'Authorization'
#  $auth_realm: realm from 'Authorization'
# Returns: TRUE (1) | FALSE (0)
###########################################################################

package Net::SIP::Authorize::FromIsRealm;
use Net::SIP::Util qw( sip_hdrval2parts sip_uri2parts );
use Net::SIP::Debug;
sub verify {
	my ($packet,$leg,$addr,$auth_user,$auth_realm) = @_;
	my $from = $packet->get_header('from');
	($from) = sip_hdrval2parts( from => $from );
	my ($domain) = sip_uri2parts($from);
	$domain =~s{:\w+$}{};
	return 1 if lc($domain) eq lc($auth_realm); # exact domain
	return 1 if $domain =~m{\.\Q$auth_realm\E$}i; # subdomain
	DEBUG( 10, "No Auth-success: From-domain is '$domain' and realm is '$auth_realm'" );
	return 0;
}

package Net::SIP::Authorize::FromIsAuthUser;
use Net::SIP::Util qw( sip_hdrval2parts sip_uri2parts );
use Net::SIP::Debug;
sub verify {
	my ($packet,$leg,$addr,$auth_user,$auth_realm) = @_;
	my $from = $packet->get_header('from');
	($from) = sip_hdrval2parts( from => $from );
	my (undef,$user) = sip_uri2parts($from);
	return 1 if lc($user) eq lc($auth_user);
	DEBUG( 10, "No Auth-success: From-user is '$user' and auth_user is '$auth_user'" );
	return 0;
}

package Net::SIP::Authorize::ToIsFrom;
use Net::SIP::Util qw( sip_hdrval2parts );
use Net::SIP::Debug;
sub verify {
	my ($packet,$leg,$addr,$auth_user,$auth_realm) = @_;
	my $from = $packet->get_header('from');
	($from) = sip_hdrval2parts( from => $from );
	my $to = $packet->get_header('to');
	($to) = sip_hdrval2parts( to => $to );
	return 1 if lc($from) eq lc($to);
	DEBUG( 10, "No Auth-success: To is '$to' and From is '$from'" );
	return 0;
}

1;
