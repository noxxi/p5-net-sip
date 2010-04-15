###########################################################################
# package Net::SIP::Leg
# a leg is a special kind of socket, which can send and receive SIP packets
# and manipulate transport relevant SIP header (Via,Record-Route)
###########################################################################

use strict;
use warnings;

package Net::SIP::Leg;
use Digest::MD5 'md5_hex';
use Socket;
use Net::SIP::Debug;
use Net::SIP::Util qw( sip_hdrval2parts invoke_callback sip_uri_eq );
use Net::SIP::Packet;
use Net::SIP::Request;
use Net::SIP::Response;
use Errno 'EHOSTUNREACH';

use fields qw( sock addr port proto contact branch via );

# sock: the socket for the leg
# addr,port: addr,port where it listens
# proto: udp|tcp
# contact: to identify myself (default from addr:port)
# branch: base for branch-tag for via header
# via: precomputed part of via value

###########################################################################
# create a new leg
# Args: ($class,%args)
#   %args: hash, the following keys will be used and deleted from hash
#      sock: socket, the addr,port and proto will be determined from this
#      addr,port,proto: if sock is not given they will be used to
#        create a socket. port defaults to 5060 and proto to udp
#        if port is defined and 0 a port will be assigned from the system
#      proto: defaults to udp
#      contact: default based on addr and port
#      branch: if not given will be created
# Returns: $self
###########################################################################
sub new {
	my ($class,%args) = @_;
	my $self = fields::new($class);

	if ( my $addr = delete $args{addr} ) {
		my $port = delete $args{port};
		# port = 0 -> get port from system
		if ( ! defined $port ) {
			$port = $1 if $addr =~s{:(\d+)$}{};
			$port ||= 5060;
		}
		my $proto = $self->{proto} = delete $args{proto} || 'udp';
		if ( ! ( $self->{sock} = delete $args{sock} ) ) {
			$self->{sock} = IO::Socket::INET->new(
				Proto => $proto,
				LocalPort => $port,
				LocalAddr => $addr,
			) || die "failed $proto $addr:$port $!";
		}
		if ( ! $port ) {
			# get the assigned port
			($port) = unpack_sockaddr_in( getsockname( $self->{sock} ));
		}

		$self->{port} = $port;
		$self->{addr} = $addr;

	} elsif ( my $sock = $self->{sock} = delete $args{sock} ) {
		# get data from socket
		($self->{port}, my $addr) = unpack_sockaddr_in( $sock->sockname );
		$self->{addr}  = inet_ntoa( $addr );
		$self->{proto} = ( $sock->socktype == SOCK_STREAM ) ? 'tcp':'udp'
	}

	my ($port,$sip_proto) =
		$self->{port} == 5060 ? ( '','sip' ) :
		( $self->{port} == 5061 and $self->{proto} eq 'tcp' ) ? ( '','sips' ) :
		( ":$self->{port}",'sip' )
		;
	my $leg_addr = $self->{addr}.$port;
	$self->{contact}  = delete $args{contact} || "$sip_proto:$leg_addr";

	$self->{branch} = 'z9hG4bK'.
		( delete $args{branch} || md5_hex( @{$self}{qw( addr port proto )} ));

	$self->{contact} =~m{^\w+:(.*)};
	$self->{via} =  sprintf( "SIP/2.0/%s %s;branch=%s",
		uc($self->{proto}),$leg_addr, $self->{branch} );

	return $self;
}

###########################################################################
# prepare incoming packet for forwarding
# Args: ($self,$packet)
#   $packet: incoming Net::SIP::Packet, gets modified in-place
# Returns: undef | [code,text]
#   code: error code (can be empty if just drop packet on error)
#   text: error description (e.g max-forwards reached..)
###########################################################################
sub forward_incoming {
	my Net::SIP::Leg $self = shift;
	my ($packet) = @_;

	if ( $packet->is_response ) {
		# remove top via
		my $via;
		$packet->scan_header( via => [ sub {
			my ($vref,$hdr) = @_;
			if ( !$$vref ) {
				$$vref = $hdr->{value};
				$hdr->remove;
			}
		}, \$via ]);

	} else {
		# Request

		# Max-Fowards
		my $maxf = $packet->get_header( 'max-forwards' );
		# we don't want to put somebody Max-Forwards: 7363535353 into the header
		# and then crafting a loop, so limit it to the default value
		$maxf = 70 if !$maxf || $maxf>70;
		$maxf--;
		if ( $maxf <= 0 ) {
			# just drop
			DEBUG( 10,'reached max-forwards. DROP' );
			return [ undef,'max-forwards reached 0, dropping' ];
		}
		$packet->set_header( 'max-forwards',$maxf );

		# add received to top via
		my $via;
		$packet->scan_header( via => [ sub {
			my ($vref,$hdr) = @_;
			if ( !$$vref ) {
				# XXXXXXX maybe check that no received header existed before
				$$vref = $hdr->{value}.=
					";received=$self->{addr}:$self->{port}";
				$hdr->set_modified;
			}
		}, \$via ]);


		# check if last hop was strict router
		# remove myself from route
		my $uri = $packet->uri;
		$uri = $1 if $uri =~m{^<(.*)>};
		($uri) = sip_hdrval2parts( route => $uri );
		my $remove_route;
		if ( $uri eq $self->{contact} ) {
			# last router placed myself into URI -> strict router
			# get original URI back from last Route-header
			my @route = $packet->get_header( 'route' );
			if ( !@route ) {
				# ooops, no route headers? -> DROP
				return [ '','request from strict router contained no route headers' ];
			}
			$remove_route = $#route;
			$uri = $route[-1];
			$uri = $1 if $uri =~m{^<(.*)>};
			$packet->set_uri($uri);

		} else {
			# last router was loose,remove top route if it is myself
			my @route = $packet->get_header( 'route' );
			if ( @route ) {
				my $route = $route[0];
				$route = $1 if $route =~m{^<(.*)>};
				($route) = sip_hdrval2parts( route => $route );
				if ( sip_uri_eq( $route,$self->{contact}) ) {
					# top route was me
					$remove_route = 0;
				}
			}
		}
		if ( defined $remove_route ) {
			$packet->scan_header( route => [ sub {
				my ($rr,$hdr) = @_;
				$hdr->remove if $$rr-- == 0;
			}, \$remove_route]);
		}

		# Add Record-Route to request, except
		# to REGISTER (RFC3261, 10.2)
		$packet->insert_header( 'record-route', '<'.$self->{contact}.';lr>' )
			if $packet->method ne 'REGISTER';
	}

	return;
}

###########################################################################
# prepare packet which gets forwarded through this leg
# packet was processed before by forward_incoming on (usually) another
# leg on the same dispatcher.
# Args: ($self,$packet,$incoming_leg)
#   $packet: outgoing Net::SIP::Packet, gets modified in-place
#   $incoming_leg: leg where packet came in
# Returns: undef | [code,text]
#   code: error code (can be empty if just drop packet on error)
#   text: error description (e.g max-forwards reached..)
###########################################################################
sub forward_outgoing {
	my Net::SIP::Leg $self = shift;
	my ($packet,$incoming_leg) = @_;

	if ( $packet->is_request ) {
		# check if myself is already in Via-path
		# in this case drop the packet, because a loop is detected
		if ( my @via = $packet->get_header( 'via' )) {
			my $branch = $self->{branch};
			my $lbranch = length($branch);
			foreach my $via ( @via ) {
				my (undef,$param) = sip_hdrval2parts( via => $via );
				if ( substr( $param->{branch},0,$lbranch ) eq $branch ) {
					DEBUG( 10,'loop detected because outgoing leg is in Via. DROP' );
					return [ undef,'loop detected on outgoing leg, dropping' ];
				}
			}
		}

		# Add Record-Route to request, except
		# to REGISTER (RFC3261, 10.2)
		# This is necessary, because these information are used in in new requests
		# from UAC to UAS, but also from UAS to UAC and UAS should talk to this leg
		# and not to the leg, where the request came in.
		# don't add if the upper record-route is already me, this is the case
		# when incoming and outgoing leg are the same
		if ( $packet->method ne 'REGISTER' ) {
			my $rr;
			unless ( (($rr) = $packet->get_header( 'record-route' ))
				and sip_uri_eq( $rr,$self->{contact} )) {
				$packet->insert_header( 'record-route', '<'.$self->{contact}.';lr>' )
			}
		}

		# strip myself from route header, because I'm done
		if ( my @route = $packet->get_header( 'route' ) ) {
			my $route = $route[0];
			$route = $1 if $route =~m{^<(.*)>};
			($route) = sip_hdrval2parts( route => $route );
			if ( sip_uri_eq( $route,$self->{contact} )) {
				# top route was me, remove it
				my $remove_route = 0;
				$packet->scan_header( route => [ sub {
					my ($rr,$hdr) = @_;
					$hdr->remove if $$rr-- == 0;
				}, \$remove_route]);
			}
		}
	}
	return;
}


###########################################################################
# deliver packet through this leg to specified addr
# add local Via header to requests
# Args: ($self,$packet,$addr;$callback)
#   $packet: Net::SIP::Packet
#   $addr:   ip:port where to deliver
#   $callback: optional callback, if an error occured the callback will
#      be called with $! as argument. If no error occured and the
#      proto is tcp the callback will be called with ENOERR to show
#      that the packet was definitly delivered (and need not retried)
###########################################################################
sub deliver {
	my Net::SIP::Leg $self = shift;
	my ($packet,$addr,$callback) = @_;

	my $isrq = $packet->is_request;
	if ( $isrq ) {
		# add via,
		# clone packet, because I don't want to change the original
		# one because it might be retried later
		# (could skip this for tcp?)
		$packet = $packet->clone;

		# make Via based transaction id
		my $via = $self->{via};
		$via .= md5_hex( $packet->tid );
		$packet->insert_header( via => $via );
	}

	# 2xx responses to INVITE requests and the request itself must have a
	# Contact, Allow and Supported header, 2xx Responses to OPTIONS need
	# Allow and Supported, 405 Responses should have Allow and Supported

	my ($need_contact,$need_allow,$need_supported);
	my $method = $packet->method;
	my $code = ! $isrq && $packet->code;
	if ( $method eq 'INVITE' and ( $isrq or $code =~m{^2} )) {
		$need_contact = $need_allow = $need_supported =1;
	} elsif ( !$isrq and (
		$code == 405 or
		( $method eq 'OPTIONS'  and $code =~m{^2} ))) {
		$need_allow = $need_supported =1;
	}
	if ( $need_contact && ! ( my @a = $packet->get_header( 'contact' ))) {
		# needs contact header, create from this leg and user part of from/to
		my ($user) = sip_hdrval2parts( $isrq
			? ( from => scalar($packet->get_header('from')) )
			: ( to   => scalar($packet->get_header('to')) )
		);
		my $contact = ( $user =~m{([^<>\@\s]+)\@} ? $1 : $user ).
			"\@$self->{addr}:$self->{port}";
		$contact = 'sip:'.$contact if $contact  !~m{^\w+:};
		$packet->insert_header( contact => $contact );
	}
	if ( $need_allow && ! ( my @a = $packet->get_header( 'allow' ))) {
		# insert default methods
		$packet->insert_header( allow => 'INVITE, ACK, OPTIONS, CANCEL, BYE' );
	}
	if ( $need_supported && ! ( my @a = $packet->get_header( 'supported' ))) {
		# set as empty
		$packet->insert_header( supported => '' );
	}


	my ($proto,$host,$port) =
		$addr =~m{^(?:(\w+):)?([\w\-\.]+)(?::(\d+))?$};
	#DEBUG( "%s -> %s %s %s",$addr,$proto||'',$host, $port||'' );
	$port ||= $proto eq 'sips' ? 5061: 5060;


	$self->sendto( $packet->as_string, $host,$port,$callback )
		|| return;
	DEBUG( 2, "delivery from $self->{addr}:$self->{port} to $addr OK:\n%s",
		$packet->dump( Net::SIP::Debug->level -2 ) );
}

###########################################################################
# send data to peer
# Args: ($self,$data,$host,$port,$callback)
#   $data: string representation of SIP packet
#   $host: target ip
#   $port: target port
#   $callback: callback for error|success, see method deliver
# Returns: $success
#   $success: true if no problems occured while sending (this does not
#     mean that the packet was delivered reliable!)
###########################################################################
sub sendto {
	my Net::SIP::Leg $self = shift;
	my ($data,$host,$port,$callback) = @_;

	# XXXXX for now udp only
	# for tcp the delivery might be done over multiple callbacks
	# (eg whenever I can write on the socket)
	# for tcp I need to handle the case where I got a request on
	# the leg, then the leg got closed and the I've need to deliver
	# the response over a new leg, created based on the master leg
	# eg I still need to know which outgoing master leg I have,
	# even if my real outgoing leg is closed (responsed might be
	# delivered over the same tcp connection, but no need to do so)

	if ( $self->{proto} ne 'udp' ) {
		use Errno 'EINVAL';
		DEBUG( 1,"can only proto udp for now, but not $self->{proto}" );
		invoke_callback( $callback, EINVAL );
	}

	my $host4 = inet_aton( $host ) or do {
		# this should not happen because host should better be IP
		DEBUG( 1, "lookup problems of $host?" );
		invoke_callback( $callback, EINVAL );
		return;
	};

	my $target = sockaddr_in( $port,$host4 );
	unless ( $self->{sock}->send( $data,0,$target )) {
		DEBUG( 1,"send failed: callback=$callback error=$!" );
		invoke_callback( $callback, $! );
		return;
	}

	# XXXX dont forget to call callback back with ENOERR if
	# delivery by tcp successful
	return 1;
}

###########################################################################
# receive packet
# for udp socket it just makes a recv on the socket and returns the packet
# for tcp master sockets it makes accept and creates a new leg based on
#   the masters leg.
# Args: ($self)
# Returns: ($packet,$from) || ()
#   $packet: Net::SIP::Packet
#   $from:   ip:port where it got packet from
###########################################################################
sub receive {
	my Net::SIP::Leg $self = shift;

	if ( $self->{proto} ne 'udp' ) {
		DEBUG( 1,"only udp is supported at the moment" );
		return;
	}

	my $from = recv( $self->{sock}, my $buf, 2**16, 0 ) or do {
		DEBUG( 1,"recv failed: $!" );
		return;
	};

	# packet must be at least 13 bytes big (first line incl version
	# + final crlf crlf). Ignore anything smaller, probably keep-alives
	if ( length($buf)<13 ) {
		DEBUG(11,"ignored packet with len ".length($buf)." because to small (keep-alive?)");
		return;
	}

	my $packet = eval { Net::SIP::Packet->new( $buf ) } or do {
		DEBUG( 3,"cannot parse buf as SIP: $@\n$buf" );
		return;
	};

	my ($port,$host) = unpack_sockaddr_in( $from );
	$host = inet_ntoa($host);
	DEBUG( 2,"received on $self->{addr}:$self->{port} from $host:$port packet\n%s",
		$packet->dump( Net::SIP::Debug->level -2 ));

	return ($packet,"$host:$port");
}

###########################################################################
# check if the top via header in the packet is from this Leg
# Args: ($self,$packet)
#  $packet: Net::SIP::Packet (usually Net::SIP::Response)
# Returns: $bool
#  $bool: true if the packets via matches this leg, else false
###########################################################################
sub check_via {
	my ($self,$packet) = @_;
	my ($via) = $packet->get_header( 'via' );
	my ($data,$param) = sip_hdrval2parts( via => $via );
	my $l_branch = $self->{branch};
	my $p_branch = substr( $param->{branch},0,length($l_branch));
	return $l_branch eq $p_branch;
}

###########################################################################
# check if the leg could deliver to the specified addr
# Args: ($self,($addr|%spec))
#  $addr: addr|proto:addr|addr:port|proto:addr:port
#  %spec: hash with keys addr,proto,port
# Returns: $bool
#  $bool: true if we can deliver to $ip with $proto
###########################################################################
sub can_deliver_to {
	my Net::SIP::Leg $self = shift;
	my %spec;
	if (@_>1) {
		%spec = @_
	} else {
		my $spec = shift;
		my ($proto,$addr) = $spec =~m{^(?:(udp|tcp):)?([^:]+)}
			or return; # wrong spec?
		$spec{proto} = $proto if $proto;
		$spec{addr}  = $addr;
		# ignore port
	}

	# check against proto of leg
	return if ( $spec{proto} && $spec{proto} ne $self->{proto} );

	# XXXXX dont know how to find out if I can deliver to this addr from this
	# leg without lookup up route
	# therefore just return true and if you have more than one leg you have
	# to figure out yourself where to send it
	return 1
}

###########################################################################
# returns FD on Leg
# Args: $self
# Returns: socket of leg
###########################################################################
sub fd {
	my Net::SIP::Leg $self = shift;
	return $self->{sock};
}

###########################################################################
# some info about the Leg for debugging
# Args: $self
# Returns: string
###########################################################################
sub dump {
	my Net::SIP::Leg $self = shift;
	return ref($self)." $self->{proto}:$self->{addr}:$self->{port}";
}



1;
