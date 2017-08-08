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
use Net::SIP::Util ':all';
use Net::SIP::SocketPool;
use Net::SIP::Packet;
use Net::SIP::Request;
use Net::SIP::Response;
use Errno qw(EHOSTUNREACH EINVAL);
use Hash::Util 'lock_ref_keys';
use Carp;

use fields qw(contact branch via proto src socketpool);

# sock: the socket for the leg
# src: hash addr,port,family where it receives data and sends data from
# proto: udp|tcp
# contact: to identify myself (default from addr:port)
# branch: base for branch-tag for via header
# via: precomputed part of via value

###########################################################################
# create a new leg
# Args: ($class,%args)
#   %args: hash, the following keys will be used and deleted from hash
#      proto: udp|tcp|tls. If not given will be determined from 'sock' or will
#        default to 'udp' or 'tls' (if 'tls' arg is used)
#      host,addr,port,family: source of outgoing and destination of
#        incoming data.
#        If IP address addr not given these values will be determined from
#        'sock'. Otherwise port will default to 5060 or 5061 (tls) and family
#        will be determined from addr syntax. host will default to addr
#      dst: destination for this leg in case a fixed destination is used
#        if not given 'sock' will be checked if connected
#      sock: socket which can just be used
#        if not given will create new socket based on proto, addr, port
#        if dst is given this new socket will be connected (udp only)
#      socketpool: socketpool which can just be used
#        if not given a new SocketPool object will be created based on the given
#        'sock' or the created socket (addr, port...). 'sock' and 'socketpool'
#        must not be given both.
#      tls: optional configuration parameters for IO::Socket::SSL. Implies
#        use of proto 'tls'.
#      contact: contact information
#        default will be based on addr and port
#      branch: branch informaton
#        default will be based on proto, addr, port
# Returns: $self - new leg object
###########################################################################
sub new {
    my ($class,%args) = @_;
    my $self = fields::new($class);

    my $proto = delete $args{proto};
    my $dst = delete $args{dst};
    my $tls = delete $args{tls};
    $proto ||= 'tls' if $tls;

    my ($sip_proto,$default_port) = $proto && $proto eq 'tls'
	? ('sips',5061) : ('sip',5060);

    my $family;
    my $host = delete $args{host};
    if (my $addr = delete $args{addr}) {
	my $port = delete $args{port};
	my $family = delete $args{family};
	if (!$family) {
	    ($addr,my $port_a, $family) = ip_string2parts($addr);
	    die "port given both as argument and contained in address"
		if $port && $port_a && $port != $port_a;
	    $port = $port_a if $port_a;
	}
	# port defined and 0 -> get port from system
	$port = $default_port if ! defined $port;
	$self->{src} = lock_ref_keys({
	    host   => $host || $addr,
	    addr   => $addr,
	    port   => $port,
	    family => $family
	});
    }

    if ($dst && !ref($dst)) {
	my ($ip,$port,$family) = ip_string2parts($dst);
	$family or die "destination must contain IP address";
	$dst = lock_ref_keys({
	    host   => $ip,
	    addr   => $ip,
	    port   => $port,
	    family => $family,
	});
    }

    my $sock = delete $args{sock};
    my $socketpool = delete $args{socketpool};
    die "only socketpool or sock should be given" if $sock && $socketpool;
    $sock ||= $socketpool && $socketpool->master;

    my $sockpeer = undef;
    if (!$sock) {
	# create new socket
	$proto ||= 'udp';
	my $src = $self->{src};
	if (!$src) {
	    # no src given, try to get useable soure from dst
	    die "neither source, destination nor socket given" if !$dst;
	    my $srcip = laddr4dst($dst->{addr}) or die
		"cannot find local IP when connecting to $dst->{addr}";
	    $src = $self->{src} = lock_ref_keys({
		host   => $host || $srcip,
		addr   => $srcip,
		port   => 0,
		family => $dst->{family},
	    });
	}

	croak("addr must be IP address") if ! ip_is_v46($src->{addr});

	my %sockargs = (
	    Proto     => $proto eq 'tls' ? 'tcp' : $proto,
	    Family    => $src->{family},
	    LocalAddr => $src->{addr},
	    Reuse     => 1, ReuseAddr => 1,
	);
	if ($proto eq 'tcp' or $proto eq 'tls') {
	    # with TCP we create a listening socket
	    $sockargs{Listen} = 100;
	} elsif ($dst) {
	    # with UDP we can create a connected socket if dst is given
	    $sockargs{PeerAddr} = $dst->{addr};
	    $sockargs{PeerPort} = $dst->{port};
	    $sockpeer = $dst;
	}

	# create a socket with the given local port
	# if no port is given try 5060,5062.. or let the system pick one
	for my $port ($src->{port}
	    ? $src->{port}
	    : ($default_port, 5062..5100, 0)) {
	    last if $sock = INETSOCK(%sockargs, LocalPort => $port);
	}

	$sock or die "failed to bind to " . ip_parts2string($src).": $!";
	$src->{port} ||= $sock->sockport;
	DEBUG(90,"created socket on ".ip_parts2string($src));

    } else {
	# get proto from socket
	$proto ||= $sock->socktype == SOCK_DGRAM ? 'udp':'tcp';

	# get src from socket
	if (!$self->{src}) {
	    my $saddr = getsockname($sock) or die
		"cannot get local name from provided socket: $!";
	    $self->{src} = ip_sockaddr2parts($saddr);
	    $self->{src}{host} = $host if $host;
	}
	if (!$dst and my $saddr = getpeername($sock)) {
	    # set dst from connected socket
	    $sockpeer = $dst = ip_sockaddr2parts($saddr);
	}
    }

    # create socketpool and add primary socket of leg to it if needed
    $self->{socketpool} = $socketpool ||= Net::SIP::SocketPool->new(
	$proto, $sock, $dst, $sockpeer, $tls);

    my $leg_addr = ip_parts2string({
	%{$self->{src}},
	use_host => 1, # prefer hostname
	default_port => $default_port,
    }, 1);  # use "[ipv6]" even if no port is given
    $self->{contact}  = delete $args{contact} || "$sip_proto:$leg_addr";

    $self->{branch} = 'z9hG4bK'. (
	delete $args{branch}
	|| md5_hex(@{$self->{src}}{qw(addr port)}, $proto)  # ip, port, proto
    );

    $self->{via} =  sprintf( "SIP/2.0/%s %s;branch=",
	uc($proto),$leg_addr );
    $self->{proto} = $proto;

    die "unhandled arguments: ".join(", ", keys %args) if %args;

    return $self;
}

###########################################################################
# do we need retransmits on this leg?
# Args: $self
# Returns: 1|0
#   1: need retransmits (UDP)
#   0: don't need retransmits (TCP, TLS)
###########################################################################
sub do_retransmits {
    my Net::SIP::Leg $self = shift;
    return $self->{proto} eq 'udp' ? 1 : 0;
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
	    my $branch = $self->via_branch($packet,3);
	    foreach my $via ( @via ) {
		my (undef,$param) = sip_hdrval2parts( via => $via );
		# ignore via header w/o branch, although these don't conform to
		# RFC 3261, sect 8.1.1.7
		defined $param->{branch} or next;
		if ( substr( $param->{branch},0,length($branch) ) eq $branch ) {
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
# Args: ($self,$packet,$dst;$callback)
#   $packet: Net::SIP::Packet
#   $dst:    target for delivery as hash host,addr,port,family
#   $callback: optional callback, if an error occurred the callback will
#      be called with $! as argument. If no error occurred and the
#      proto is tcp the callback will be called with error=0 to show
#      that the packet was definitely delivered (and there's no need to retry)
###########################################################################
sub deliver {
    my Net::SIP::Leg $self = shift;
    my ($packet,$dst,$callback) = @_;

    my $isrq = $packet->is_request;
    if ( $isrq ) {
	# add via,
	# clone packet, because I don't want to change the original
	# one because it might be retried later
	# (could skip this for tcp?)
	$packet = $packet->clone;
	$self->add_via($packet);
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
	my ($proto,$addr) = $self->{contact} =~m{^(\w+):(?:.*\@)?(.*)$};
	my $contact = ( $user =~m{([^<>\@\s]+)\@} ? $1 : $user ).
	    "\@$addr";
	$contact = $proto.':'.$contact if $contact !~m{^\w+:};
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

    die "target protocol $dst->{proto} does not match leg $self->{proto}"
	if exists $dst->{proto} && $dst->{proto} ne $self->{proto};
    $dst->{port} ||= $self->{proto} eq 'tls' ? 5061 : 5060;

    $DEBUG && DEBUG( 2, "delivery with %s from %s to %s:\n%s",
	$self->{proto},
	ip_parts2string($self->{src}),
	ip_parts2string($dst),
	$packet->dump( Net::SIP::Debug->level -2 ) );

    return $self->sendto($packet,$dst,$callback);
}

###########################################################################
# send data to peer
# Args: ($self,$packet,$dst,$callback)
#   $packet: SIP packet object
#   $dst:   target as hash host,addr,port,family
#   $callback: callback for error|success, see method deliver
# Returns: $success
#   $success: true if no problems occurred while sending (this does not
#     mean that the packet was delivered reliable!)
###########################################################################
sub sendto {
    my Net::SIP::Leg $self = shift;
    my ($packet,$dst,$callback) = @_;

    $self->{socketpool}->sendto($packet,$dst,$callback)
	&& return 1;
    return;
}

###########################################################################
# Handle newly received packet.
# Currently just passes through the packet
# Args: ($self,$packet,$from)
#   $packet: packet object
#   $from: hash with proto,addr,port,family where the packet came from
# Returns: ($packet,$from)|()
#   $packet: packet object
#   $from: hash with proto,ip,port,family where the packet came from
###########################################################################
sub receive {
    my Net::SIP::Leg $self = shift;
    my ($packet,$from) = @_;

    $DEBUG && DEBUG( 2,"received packet on %s from %s:\n%s",
	sip_sockinfo2uri($self->{proto},@{$self->{src}}{qw(addr port family)}),
	sip_sockinfo2uri(@{$from}{qw(proto addr port family)}),
	$packet->dump( Net::SIP::Debug->level -2 )
    );
    return ($packet,$from);
}


###########################################################################
# check if the top via header matches the transport of this call through
# this leg. Used to strip Via header in response.
# Args: ($self,$packet)
#  $packet: Net::SIP::Packet (usually Net::SIP::Response)
# Returns: $bool
#  $bool: true if the packets via matches this leg, else false
###########################################################################
sub check_via {
    my ($self,$packet) = @_;
    my ($via) = $packet->get_header( 'via' );
    my ($data,$param) = sip_hdrval2parts( via => $via );
    my $cmp_branch = $self->via_branch($packet,2);
    return substr( $param->{branch},0,length($cmp_branch)) eq $cmp_branch;
}

###########################################################################
# add myself as Via header to packet
# Args: ($self,$packet)
#  $packet: Net::SIP::Packet (usually Net::SIP::Request)
# Returns: NONE
# modifies packet in-place
###########################################################################
sub add_via {
    my Net::SIP::Leg $self = shift;
    my $packet = shift;
    $packet->insert_header( via => $self->{via}.$self->via_branch($packet,3));
}

###########################################################################
# computes branch tag for via header
# Args: ($self,$packet,$level)
#  $packet: Net::SIP::Packet (usually Net::SIP::Request)
#  $level: level of detail: 1:leg, 2:call, 3:path
# Returns: $value
###########################################################################
sub via_branch {
    my Net::SIP::Leg $self = shift;
    my ($packet,$level) = @_;
    my $val = $self->{branch};
    $val .= substr( md5_hex( $packet->tid ),0,15 ) if $level>1;
    if ($level>2) {
	my @parts;
	# RT#120816 -  take only known constant values from proxy-authorization
	for(sort $packet->get_header('proxy-authorization')) {
	    my ($typ,$param) = sip_hdrval2parts('proxy-authorization' => $_);
	    push @parts,$typ;
	    for(qw(realm username domain qop algorithm)) {
		push @parts,"$_=$param->{$_}" if exists $param->{$_};
	    }
	}

	# RT#120816 - include only the branch from via header if possible
	if (my $via = ($packet->get_header('via'))[0]) {
	    my (undef,$param) = sip_hdrval2parts(via => $via);
	    push @parts, $param && $param->{branch} || $via;
	}

	push @parts,
	    ( sort $packet->get_header('proxy-require')),
	    $packet->get_header('route'),
	    $packet->get_header('to'),
	    $packet->get_header('from'),
	    ($packet->as_parts())[1];
	$val .= substr(md5_hex(@parts),0,15);
    }
    return $val;
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
	%spec = @_;
    } else {
	@spec{ qw(proto host port family) } = sip_uri2sockinfo(shift());
	$spec{addr} = $spec{family} ? $spec{host} : undef;
    }

    # return false if proto or family don't match
    return if $spec{proto} && $spec{proto} ne $self->{proto};
    return if $spec{family} && $self->{src}
	&& $self->{src}{family} != $spec{family};

    # XXXXX dont know how to find out if I can deliver to this addr from this
    # leg without lookup up route
    # therefore just return true and if you have more than one leg you have
    # to figure out yourself where to send it
    return 1
}

###########################################################################
# check if this leg matches given criteria (used in Dispatcher)
# Args: ($self,$args)
#   $args: hash with any of 'addr', 'port', 'proto', 'sub'
# Returns: true if leg fits all args
###########################################################################
sub match {
    my Net::SIP::Leg $self = shift;
    my $args = shift;
    return if $args->{addr}  && $args->{addr}  ne $self->{src}{addr};
    return if $args->{port}  && $args->{port}  != $self->{src}{port};
    return if $args->{proto} && $args->{proto} ne $self->{proto};
    return if $args->{sub}   && !invoke_callback($args->{sub},$self);
    return 1;
}

###########################################################################
# returns SocketPool object on Leg
# Args: $self
# Returns: $socketpool
###########################################################################
sub socketpool {
    my Net::SIP::Leg $self = shift;
    return $self->{socketpool};
}

###########################################################################
# local address of the leg
# Args: $self;$parts
#  $parts: number of parts to include
#     0 -> address only
#     1 -> address[:non_default_port]
#     2 -> host[:non_default_port]
# Returns: string
###########################################################################
sub laddr {
    my Net::SIP::Leg $self = shift;
    my $parts = shift;
    ! $parts and return $self->{src}{addr};
    return ip_parts2string({
	%{ $self->{src} },
	default_port => $self->{proto} eq 'tls' ? 5061 : 5060,
	$parts == 1 ? () :
	$parts == 2 ? (use_host => 1) :
	die "invalid parts specification $parts",
    });
}

###########################################################################
# some info about the Leg for debugging
# Args: $self
# Returns: string
###########################################################################
sub dump {
    my Net::SIP::Leg $self = shift;
    return ref($self)." $self->{proto}:"
	. ip_parts2string($self->{src});
}


###########################################################################
# returns key for leg
# Args: $self
# Returns: key (string)
###########################################################################
sub key {
    my Net::SIP::Leg $self = shift;
    return ref($self).' '.join(':',$self->{proto},
	@{$self->{src}}{qw(addr port)});
}

1;
