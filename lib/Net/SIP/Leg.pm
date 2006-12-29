###########################################################################
# package Net::SIP::Leg
# a leg is associated with a socket. Alle SIP packets which gets received
# or send through a socket get handled by the associated leg.
#
# the following actions are handled for incoming packets
# - none if just receiving
#
# and for forwarding packets (handled by the incoming leg)
# - check and decrease max-forwards 
# - for forwarding response
#   * remove my via
# - for forwarding requests
#   * add received tag to top via header
#   * add myself as record-route
#   * normalize uri/route when coming from strict router
#   * remove my route
#
# and for outgoing packets:
# - for outgoing requests
#   * add my via
#   * rewrite uri+route if next hop is strict router
# 
###########################################################################

use strict;
use warnings;

package Net::SIP::Leg;
use Digest::MD5 'md5_hex';
use Socket;
use Net::SIP::Debug;
use Net::SIP::Util qw( sip_hdrval2parts invoke_callback );
use Net::SIP::Packet;
use Net::SIP::Request;
use Net::SIP::Response;

use fields qw( sock addr port proto contact branch _via );

# sock: the socket for the leg
# addr,port: addr,port where it listens
# proto: udp|tcp
# contact: to identify myself (default from addr:port)
# branch: branch-tag for via header
# _via: precomputed via value

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

	if ( my $sock = $self->{sock} = delete $args{sock} ) {
		# get data from socket
		($self->{port}, my $addr) = unpack_sockaddr_in( $sock->sockname );
		$self->{addr}  = inet_ntoa( $addr );
		$self->{proto} = ( $sock->socktype == SOCK_STREAM ) ? 'tcp':'udp'

	} elsif ( my $addr = $self->{addr} = delete $args{addr} ) {
		my $port = delete $args{port};
		$port = 5060 if ! defined $port; # port = 0 -> get port from system
		my $proto = $self->{proto} = delete $args{proto} || 'udp';
		$self->{sock} = IO::Socket::INET->new(
			Proto => $proto,
			LocalPort => $port,
			LocalAddr => $addr,
		) || die "failed $proto $addr:$port $!";

		# get the assigned port
		($port) = unpack_sockaddr_in( getsockname( $self->{sock} ));
		$self->{port} = $port;
	}

	unless ( $self->{contact}  = delete $args{contact} ) {
		my ($port,$sip_proto) = 
			$self->{port} == 5060 ? ( '','sip' ) :
			$self->{port} == 5061 && $self->{proto} eq 'udp' ? ( '','sips' ) :
			( ":$self->{port}",'sip' )
			;
		$self->{contact} = $sip_proto.':'.$self->{addr}.$port;
	}

	$self->{branch} = 'z9hG4bK'.
		( delete $args{branch} || md5_hex( @{$self}{qw( addr port proto )} ));

	$self->{contact} =~m{^\w+:(.*)};
	$self->{_via} =  sprintf( "SIP/2.0/%s %s;branch=%s",
		uc($self->{proto}),$1, $self->{branch} );

	return $self;
}

###########################################################################
# handle incoming packet (e.g incoming leg)
# Args: ($self,$packet)
#   $packet: Net::SIP::Packet, gets modified in-place
# Returns: undef | [code,text]
#   code: error code (can be empty if just drop packet on error)
#   text: error description (e.g max-forwards reached..)
###########################################################################
sub incoming {
	my ($self,$packet) = @_;
	# does nothing to the packet
	# XXXX we could check here the via Header is our, e.g. that
	# the packet came in through the right leg
	return;
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
	my ($self,$packet) = @_;

	# Max-Fowards
	my $maxf = $packet->get_header( 'max-forwards' ) || 70;
	$maxf--;
	if ( $maxf <= 0 ) {
		# just drop
		return [ undef,'max-forwards reached 0, dropping' ]; 
	}

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
				if ( $route eq $self->{contact} ) {
					# top route was me
					$remove_route = 0;
				}
			}
		}
		if ( defined $remove_route ) {
			$packet->scan_header( route => [ sub {
				my ($rr,$hdr) = @_;
				$hdr->remove if $rr-- == 0;
			}, \$remove_route]);
		}

		# Add Record-Route to request
		$packet->insert_header( 'record-route', '<'.$self->{contact}.';lr>' );
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

	if ( $packet->is_request ) {
		# add via,
		# clone packet, because I don't want to change the original
		# one because it might be retried later
		# (could skip this for tcp?)
		$packet = $packet->clone; 
		$packet->insert_header( via => $self->{_via} );
	}

	my ($proto,$host,$port) = 
		$addr =~m{^(?:(\w+):)?([\w\-\.]+)(?::(\d+))?$};
	#DEBUG( "%s -> %s %s %s",$addr,$proto||'',$host, $port||'' );
	$port ||= 5060; # only right for sip, not sips!

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
		DEBUG( "can only proto udp for now, but not $self->{proto}" );
		invoke_callback( $callback, EINVAL );
	}

	# XXXXX if host is not IP but hostname this might block!
	$host = inet_aton( $host );
	my $target = sockaddr_in( $port,$host );
	unless ( $self->{sock}->send( $packet->as_string,0,$target )) {
		DEBUG( "send failed: callback=$callback error=$!" );
		invoke_callback( $callback, $! );
		return;
	}

	DEBUG( "delivery from $self->{addr}:$self->{port} to $addr OK:\n".$packet->as_string );

	# XXXX dont forget to call callback back with ENOERR if 
	# delivery by tcp successful
}

###########################################################################
# receive packet
# for udp socket it just makes a recv on the socket and returns the packet
# for tcp master sockets it makes accept and creates a new leg based on
#   the masters leg. 
# Args: ($self,$dispatcher)
#   $dispatcher: Net::SIP::Dispatcher which manages these leg
# Returns: ($packet,$from) || ()
#   $packet: Net::SIP::Packet
#   $from:   ip:port where it got packet from
###########################################################################
sub receive {
	my Net::SIP::Leg $self = shift;
	my $dispatcher = shift;

	if ( $self->{proto} ne 'udp' ) {
		DEBUG( "only udp is supported at the moment" );
		return;
	}

	my $from = recv( $self->{sock}, my $buf, 2**16, 0 ) or do {
		DEBUG( "recv failed: $!" );
		return;
	};

	my $packet = eval { Net::SIP::Packet->new( $buf ) } or do {
		DEBUG( "cannot parse buf as SIP: $@\n$buf" );
		return;
	};

	my ($port,$host) = unpack_sockaddr_in( $from );
	$host = inet_ntoa($host);
	DEBUG( "received on $self->{addr}:$self->{port} from $host:$port packet\n".$packet->as_string );

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
	return ( $param->{branch} eq $self->{branch} );
}

###########################################################################
# check if the leg could deliver to the specified addr
# Args: ($self,$addr)
# Returns: 1|0
###########################################################################
sub can_deliver_to {
	my Net::SIP::Leg $self = shift;
	my $addr = shift;

	# XXXXX dont know how to find out if I can deliver to this addr from this
	# leg without lookup up route
	# therefore just return true and if you have more than one leg you have
	# to figure out yourself where to send it
	return 1
}


	
1;
