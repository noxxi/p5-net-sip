
###########################################################################
# package Net::SIP::Dispatcher
#
# Manages the sending of SIP packets to the legs (and finding out which
# leg can be used) and the receiving of SIP packets and forwarding to
# the upper layer.
# Handles retransmits
###########################################################################

use strict;
use warnings;

package Net::SIP::Dispatcher;
use fields (
    # interface to outside
    'receiver',       # callback into upper layer
    'legs',           # \@list of Net::SIP::Legs managed by dispatcher
    'eventloop',      # Net::SIP::Dispatcher::Eventloop or similar
    'outgoing_proxy', # optional fixed outgoing proxy
    'domain2proxy',   # optional mapping between SIP domains and proxies (otherwise use DNS)
    # internals
    'do_retransmits', # flag if retransmits will be done (false for stateless proxy)
    'queue',          # \@list of outstanding Net::SIP::Dispatcher::Packet
    'response_cache', # Cache of responses, used to reply to retransmits
    'disp_expire',    # expire/retransmit timer
    'dnsresolv',      # optional external DNS resolver
);

use Net::SIP::Leg;
use Net::SIP::Util ':all';
use Net::SIP::Dispatcher::Eventloop;
use Errno qw(EHOSTUNREACH ETIMEDOUT ENOPROTOOPT);
use IO::Socket;
use List::Util 'first';
use Hash::Util 'lock_ref_keys';
use Carp 'croak';
use Net::SIP::Debug;
use Scalar::Util 'weaken';

# The maximum priority value in SRV records is 0xffff and the lowest priority
# value is considered the best. Make undefined priority higher so that it gets
# considered as last option.
use constant SRV_PRIO_UNDEF => 0x10000;

###########################################################################
# create new dispatcher
# Args: ($class,$legs,$eventloop;%args)
#  $legs:           \@array, see add_leg()
#  $eventloop:      Net::SIP::Dispatcher::Eventloop or similar
#  %args:
#   outgoing_proxy: optional outgoing proxy (ip:port)
#   do_retransmits: set if the dispatcher has to handle retransmits by itself
#       defaults to true
#   domain2proxy: mappings { domain => proxy } if a fixed proxy is used
#       for specific domains, otherwise lookup will be done per DNS
#       proxy can be ip,ip:port or \@list of hash with keys prio, proto, host,
#       port and family like in the DNS SRV record
#       with special domain '*' a default can be specified, so that DNS
#       will not be used at all
#   dnsresolv: DNS resolver function with interface sub->(type,domain,callback)
#       which then calls callback->(\@result) with @result being a list of
#       [ 'SRV',prio,target,port], ['A',ip,name], ['AAAA',ip,name]
# Returns: $self
###########################################################################
sub new {
    my ($class,$legs,$eventloop,%args) = @_;

    my ($outgoing_proxy,$do_retransmits,$domain2proxy,$dnsresolv) = delete
	@args{qw( outgoing_proxy do_retransmits domain2proxy dnsresolv)};
    die "bad args: ".join( ' ',keys %args ) if %args;

    $eventloop ||= Net::SIP::Dispatcher::Eventloop->new;

    # normalize domain2proxy so that its the same format one gets from
    # the SRV record
    $domain2proxy ||= {};
    foreach ( values %$domain2proxy ) {
	if ( ref($_) ) {
	    # should be \@list of [ prio,proto,ip,port,?family ]
	} else {
	    my ($proto,$host,$port,$family) = sip_uri2sockinfo($_)
		or croak( "invalid entry in domain2proxy: $_" );
	    $port ||= $proto && $proto eq 'tls' ? 5061:5060;
	    $_ = [ map { lock_ref_keys({
		prio   => SRV_PRIO_UNDEF,
		proto  => $_,
		host   => $host,
		addr   => $family ? $host : undef,
		port   => $port,
		family => $family
	    }) } $proto ? ($proto) : ('udp','tcp') ];
	}
    }

    my $self = fields::new($class);
    %$self = (
	legs => [],
	queue  => [],
	outgoing_proxy => undef,
	response_cache => {},
	do_retransmits => defined( $do_retransmits ) ? $do_retransmits : 1,
	eventloop      => $eventloop,
	domain2proxy   => $domain2proxy,
	dnsresolv      => $dnsresolv,
    );

    $self->add_leg( @$legs );

    $self->outgoing_proxy($outgoing_proxy) if $outgoing_proxy;

    return $self;
}

# regularly prune queue
sub __disp_expire_timer {
    my $self = shift || return; # dispatcher already deleted (weak reference)
    my $min_expire = $self->queue_expire($self->{eventloop}->looptime);
    if (!$min_expire) {
	# nothing in queue to expire
	delete $self->{disp_expire};
	return;
    }
    # add timer again
    $self->{disp_expire} = $self->add_timer(
	1, [\&__disp_expire_timer, $self], undef, 'disp_expire');
}
sub __set_disp_expire_timer {
    my Net::SIP::Dispatcher $self = shift;
    $self->{disp_expire} and return;
    my $cb = [\&__disp_expire_timer, $self];
    weaken($cb->[1]);
    $self->{disp_expire} = $self->add_timer(1, $cb, undef, 'disp_expire');
}

###########################################################################
# get or set outgoing proxy
# Args: ($self;$proxy)
#  $proxy: optional new proxy or undef if proxy should be none
# Returns:
#  $proxy: current setting, i.e. after possible update
###########################################################################
sub outgoing_proxy {
    my Net::SIP::Dispatcher $self = shift;
    return $self->{outgoing_proxy} if ! @_;
    my $outgoing_proxy = shift;
    my $leg = $self->_find_leg4addr( $outgoing_proxy )
	|| die "cannot find leg for destination $outgoing_proxy";
    $self->{outgoing_proxy} = $outgoing_proxy;
}


###########################################################################
# get or set the event loop
# Args: ($self;$loop)
#  $loop: optional new loop
# Returns:
#  $loop: current setting, i.e. after possible update
###########################################################################
sub loop {
    my Net::SIP::Dispatcher $self = shift;
    return $self->{eventloop} if ! @_;
    $self->{eventloop} = shift;
}


###########################################################################
# set receiver, e.g the upper layer which gets the incoming packets
# received by the dispatcher
# Args: ($self,$receiver)
#   $receiver: object which has receive( Net::SIP::Leg,Net::SIP::Packet )
#     method to handle incoming SIP packets or callback
#     might be undef - in this case the existing receiver will be removed
# Returns: NONE
###########################################################################
sub set_receiver {
    my Net::SIP::Dispatcher $self = shift;
    if ( my $receiver = shift ) {
	if ( my $sub = UNIVERSAL::can($receiver,'receive' )) {
	    # Object with method receive()
	    $receiver = [ $sub,$receiver ]
	}
	$self->{receiver} = $receiver;
    } else {
	# remove receiver
	$self->{receiver} = undef
    }

}

###########################################################################
# adds a leg to the dispatcher
# Args: ($self,@legs)
#  @legs: can be sockets, \%args for constructing or already
#    objects of class Net::SIP::Leg
# Returns: NONE
###########################################################################
sub add_leg {
    my Net::SIP::Dispatcher $self = shift;
    my $legs = $self->{legs};
    foreach my $arg (@_) {

	my $leg;
	# if it is not a leg yet create one based
	# on the arguments
	if ( UNIVERSAL::isa( $arg,'Net::SIP::Leg' )) {
	    # already a leg
	    $leg = $arg;

	} elsif ( UNIVERSAL::isa( $arg,'IO::Handle' )) {
	    # create from socket
	    $leg = Net::SIP::Leg->new( sock => $arg );

	} elsif ( UNIVERSAL::isa( $arg,'HASH' )) {
	    # create from %args
	    $leg = Net::SIP::Leg->new( %$arg );
	} else {
	    croak "invalid spec for leg: $arg";
	}

	push @$legs, $leg;

	if (my $socketpool = $leg->socketpool) {
	    my $cb = sub {
		# don't crash Dispatcher on bad or unexpected packets
		eval {
		    my ($self,$leg,$packet,$from) = @_;
		    $self || return;

		    ($packet,$from) = $leg->receive($packet,$from) or return;

		    if ($packet->is_request) {
			# add received and rport to top via
			$packet->scan_header( via => [ sub {
			    my ($vref,$hdr) = @_;
			    return if $$vref++;
			    my ($d,$h) = sip_hdrval2parts(via => $hdr->{value});
			    my ($host,$port) = $d =~m{^SIP/2\S+\s+(\S+)$}
				? ip_string2parts($1):();
			    my %nh;
			    if ( exists $h->{rport} and ! defined $h->{rport}) {
				$nh{rport} = $from->{port};
			    }
			    if ($host ne $from->{addr}) {
				# either from.addr is the addr for host or we
				# had a different IP address in the via header
				$nh{received} = $from->{addr};
			    } elsif ($nh{rport}) {
				# required because rport was set
				$nh{received} = $from->{addr};
			    }
			    if (%nh) {
				$hdr->{value} = sip_parts2hdrval('via',$d,{ %$h,%nh});
				$hdr->set_modified;
			    }
			}, \( my $cvia )]);
		    }

		    # handle received packet
		    $self->receive( $packet,$leg,$from );
		    1;
		} or DEBUG(1,"dispatcher croaked: $@");
	    };
	    $cb = [ $cb,$self,$leg ];
	    weaken($cb->[1]);
	    weaken($cb->[2]);
	    $socketpool->attach_eventloop($self->{eventloop}, $cb);
	}
    }
}

###########################################################################
# remove a leg from the dispatcher
# Args: ($self,@legs)
#  @legs: Net::SIP::Leg objects
# Returns: NONE
###########################################################################
sub remove_leg {
    my Net::SIP::Dispatcher $self = shift;
    my $legs = $self->{legs};
    foreach my $leg (@_) {
	@$legs = grep { $_ != $leg } @$legs;
	if ( my $pool = $leg->socketpool ) {
	    $pool->attach_eventloop();
	}
    }
}

###########################################################################
# find legs matching specific criterias
# Args: ($self,%args)
#  %args: Hash with some of these keys
#    addr: leg must match addr
#    port: leg must match port
#    proto: leg must match proto
#    sub:  $sub->($leg) must return true
# Returns: @legs
#   @legs: all Legs matching the criteria
# Comment:
# if no criteria given it will return all legs
###########################################################################
sub get_legs {
    my Net::SIP::Dispatcher $self = shift;
    return @{ $self->{legs} } if ! @_; # shortcut

    my %args = @_;
    my @rv;
    foreach my $leg (@{ $self->{legs} }) {
	push @rv,$leg if $leg->match(\%args);
    }
    return @rv;
}


###########################################################################
# map leg to index in list of legs
# Args: @legs,[\$dict]
#  @legs: list of legs
#  $dict: string representation of dictionary, used in i2leg and others
#    to make sure that it the indices come from the same list of legs.
#    Will be set if given
# Returns: @ilegs
#  @ilegs: index of each of @legs in dispatcher, -1 if not found
###########################################################################
sub legs2i {
    my Net::SIP::Dispatcher $self = shift;
    my $legs = $self->{legs};
    if (ref($_[-1]) eq 'SCALAR') {
	my $dict = pop @_;
	$$dict = join("|",map { $_->key } @$legs);
    }
    my @result;
    for(@_) {
	my $i;
	for($i=$#$legs;$i>=0;$i--) {
	    last if $legs->[$i] == $_;
	}
	push @result,$i;
    }
    return @result;
}

###########################################################################
# map index to leg in list of legs
# Args: @ilegs,[\$dict]
#  @ilegs: list of leg indices
#  $dict: optional string representation of dictionary, will return ()
#     if $dict does not match current legs and order in dispatcher
# Returns: @legs
#  @legs: list of legs matching indices
###########################################################################
sub i2legs {
    my Net::SIP::Dispatcher $self = shift;
    my $legs = $self->{legs};
    if (ref($_[-1])) {
	return if ${pop(@_)} ne join("|",map { $_->key } @$legs);
    }
    return @{$legs}[@_];
}

###########################################################################
# add timer
# propagates to add_timer of eventloop
# Args: ($self,$when,$cb,$repeat)
#   $when: when callback gets called, can be absolute time (epoch, time_t)
#     or relative time (seconds)
#   $cb: callback
#   $repeat: after how much seconds it gets repeated (default 0, e.g never)
# Returns: $timer
#   $timer: Timer object, has method cancel for canceling timer
###########################################################################
sub add_timer {
    my Net::SIP::Dispatcher $self = shift;
    return $self->{eventloop}->add_timer( @_ );
}

###########################################################################
# initiate delivery of a packet, e.g. put packet into delivery queue
# Args: ($self,$packet,%more_args)
#   $packet: Net::SIP::Packet which needs to be delivered
#   %more_args: hash with some of the following keys
#     id:        id for packet, used in cancel_delivery
#     callback:  [ \&sub,@arg ] for calling back on definite delivery
#       success (tcp only) or error (timeout,no route,...)
#     leg:       specify outgoing leg, needed for responses
#     dst_addr:  specify outgoing addr as hash with keys
#         proto,addr,port,family,host. Needed for responses.
#     do_retransmits: if retransmits should be done, default from
#        global value (see new())
# Returns: NONE
# Comment: no return value, but die()s on errors
###########################################################################
sub deliver {
    my Net::SIP::Dispatcher $self = shift;
    my ($packet,%more_args) = @_;
    my $now = delete $more_args{now};
    my $do_retransmits = delete $more_args{do_retransmits};
    $do_retransmits = $self->{do_retransmits} if !defined $do_retransmits;

    DEBUG( 100,"deliver $packet" );

    if ( $packet->is_response ) {
	# cache response for 32 sec (64*T1)
	if ( $do_retransmits ) {
	    my $cid = join( "\0",
		map { $packet->get_header($_) }
		qw( cseq call-id from to )
	    );
	    $self->{response_cache}{$cid} = {
		packet => $packet,
		expire => ( $now ||= time()) +32
	    };
	}
    }

    my $new_entry = Net::SIP::Dispatcher::Packet->new(
	packet => $packet,
	%more_args
    );

    $new_entry->prepare_retransmits( $now ) if $do_retransmits;

    push @{ $self->{queue}}, $new_entry;
    $self->__set_disp_expire_timer;
    $self->__deliver( $new_entry );
}

###########################################################################
# cancel delivery of all packets with specific id
# Args: ($self,$typ?,$id)
#   $typ: what to cancel, e.g. 'id','callid' or 'qentry', optional,
#     defaults to 'id' if $id is not ref or 'qentry' if $id is ref
#   $id: id to cancel, can also be queue entry
# Returns: bool, true if the was something canceled
###########################################################################
sub cancel_delivery {
    my Net::SIP::Dispatcher $self = shift;
    my ($callid,$id,$qentry);
    if ( @_ == 2 ) {
	my $typ = shift;
	if ( $typ eq 'callid' ) { $callid = shift }
	elsif ( $typ eq 'id' ) { $id = shift }
	elsif ( $typ eq 'qentry' ) { $qentry = shift }
	else {
	    croak( "bad typ '$typ', should be id|callid|qentry" );
	}
    } else {
	$id = shift;
	if ( ref($id)) {
	    $qentry = $id;
	    $id = undef;
	}
    }
    my $q = $self->{queue};
    my $qn = @$q;
    if ( $qentry ) {
	# it's a *::Dispatcher::Packet
	DEBUG( 100,"cancel packet id: $qentry->{id}" );
	@$q = grep { $_ != $qentry } @$q;
    } elsif ( defined $id ) {
	no warnings; # $_->{id} can be undef
	DEBUG( 100, "cancel packet id $id" );
	@$q = grep { $_->{id} ne $id } @$q;
    } elsif ( defined $callid ) {
	no warnings; # $_->{callid} can be undef
	DEBUG( 100, "cancel packet callid $callid" );
	@$q = grep { $_->{callid} ne $callid } @$q;
    } else {
	croak( "cancel_delivery w/o id" );
    }
    $self->__set_disp_expire_timer;
    return @$q < $qn; # true if items got deleted
}



###########################################################################
# Receive a packet from a leg and forward it to the upper layer
# if the packet is a request and I have a cached response resend it
# w/o involving the upper layer
# Args: ($self,$packet,$leg,$from)
#   $packet: Net::SIP::Packet
#   $leg:    through which leg it was received
#   $from:   where the packet comes from: [proto,ip,from,family]
# Returns: NONE
# Comment: if no receiver is defined using set_receiver the packet
#   will be silently dropped
###########################################################################
sub receive {
    my Net::SIP::Dispatcher $self = shift;
    my ($packet,$leg,$from) = @_;

    if ( $packet->is_request ) {
	my $cache = $self->{response_cache};
	if ( %$cache ) {
	    my $cid = join( "\0",
		map { $packet->get_header($_) }
		qw( cseq call-id from to )
	    );

	    if ( my $response = $cache->{$cid} ) {
		# I have a cached response, use it
		$self->deliver($response->{packet},
		    leg => $leg,
		    dst_addr => $from,
		);
		return;
	    }
	}
    }

    invoke_callback( $self->{receiver},$packet,$leg,$from );
}

###########################################################################
# expire the entries on the queue, eg removes expired entries and
# calls callback if necessary
# expires also the response cache
# Args: ($self;$time)
#   $time: expire regarding $time, if not given use time()
# Returns: undef|$min_expire
#   $min_expire: time when next thing expires (undef if nothing to expire)
###########################################################################
sub queue_expire {
    my Net::SIP::Dispatcher $self = shift;
    my $now = shift || $self->{eventloop}->looptime;

    # expire queue
    my $queue = $self->{queue};
    my (@nq,$changed,$min_expire);
    foreach my $qe (@$queue) {

	my $retransmit;
	if ( my $retransmits = $qe->{retransmits} ) {
	    while ( @$retransmits && $retransmits->[0] < $now ) {
		$retransmit = shift(@$retransmits);
	    }

	    if ( !@$retransmits ) {
		# completely expired
		DEBUG( 50,"entry %s expired because expire=%.2f but now=%d", $qe->tid,$retransmit,$now );
		$changed++;
		$qe->trigger_callback( ETIMEDOUT );

		# don't put into new queue
		next;
	    }

	    if ( $retransmit ) {
		# need to retransmit the packet
		$self->__deliver( $qe );
	    }

	    my $next_retransmit = $retransmits->[0];
	    if ( !defined($min_expire) || $next_retransmit<$min_expire ) {
		$min_expire = $next_retransmit
	    }
	}
	push @nq,$qe;

    }
    $self->{queue} = \@nq if $changed;

    # expire response cache
    my $cache = $self->{response_cache};
    foreach my $cid ( keys %$cache ) {
	my $expire = $cache->{$cid}{expire};
	if ( $expire < $now ) {
	    delete $cache->{$cid};
	} elsif ( !defined($min_expire) || $expire<$min_expire ) {
	    $min_expire = $expire
	}
    }

    # return time to next expire for optimizations
    DEBUG( 50,"next expire %s", $min_expire || '<undef>' );
    return $min_expire;
}


###########################################################################
# the real delivery of a queue entry:
# if no leg,addr try to determine them from request-URI
# prepare timeout handling
# Args: ($self,$qentry)
#   $qentry: Net::SIP::Dispatcher::Packet
# Returns: NONE
# Comment:
# this might be called several times for a queue entry, eg as a callback
# at the various stages (find leg,addr for URI needs DNS lookup which
# might be done asynchronous, eg callback driven, send might be callback
# driven for tcp connections which need connect, multiple writes...)
###########################################################################
sub __deliver {
    my Net::SIP::Dispatcher $self = shift;
    my $qentry = shift;

    # loop until leg und dst_addr are known, when we call leg->deliver
    my $leg = $qentry->{leg}[0];
    if ( $leg && @{ $qentry->{leg}}>1 ) {
	DEBUG( 50,"picking first of multiple legs: ".join( " ", map { $_->dump } @{ $qentry->{leg}} ));
    }
    my $dst_addr = $qentry->{dst_addr}[0];

    if ( ! $dst_addr || ! $leg) {

	# if explicit routes given use first route
	# else resolve URI from request

	my $uri;
	my $packet = $qentry->{packet};
	if ( my ($route) =  $packet->get_header( 'route' )) {
	    ($uri) = sip_hdrval2parts( route => $route );
	} else {
	    $uri = $packet->uri;
	}

	DEBUG( 100,"no dst_addr or leg yet, uri='$uri'" );

	my $callback = sub {
	    my ($self,$qentry,@error) = @_;
	    if ( @error ) {
		$qentry->trigger_callback(@error);
		return $self->cancel_delivery( $qentry );
	    } else {
		$self->__deliver($qentry);
	    }
	};
	return $self->resolve_uri(
	    $uri,
	    $qentry->{dst_addr},
	    $qentry->{leg},
	    [ $callback, $self,$qentry ],
	    $qentry->{proto},
	);
    }

    if ($qentry->{retransmits} && ! $leg->do_retransmits) {
	$qentry->{retransmits} = undef;
    }

    # I have leg and addr, send packet thru leg to addr
    my $cb = sub {
	my ($self,$qentry,$error) = @_;
	$self || return;
	if ( !$error  && $qentry->{retransmits} ) {
	    # remove from queue even if timeout
	    $self->cancel_delivery( $qentry );
	}
	$qentry->trigger_callback( $error );
    };

    # adds via on cloned packet, calls cb if definite success (tcp)
    # or error
    #Carp::confess("expected reference, got $dst_addr") if !ref($dst_addr);
    $DEBUG && DEBUG(50,"deliver through leg ".$leg->dump.' @'
	.ip_parts2string($dst_addr));
    weaken( my $rself = \$self );
    $cb = [ $cb,$self,$qentry ];
    weaken( $cb->[1] );
    $leg->deliver( $qentry->{packet},$dst_addr,$cb );

    if ( !$qentry->{retransmits} ) {
	# remove from queue if no timeout
	$self->cancel_delivery( $qentry );
    }
}



###########################################################################
# resolve URI, determine dst_addr and outgoing leg
# Args: ($self,$uri,$dst_addr,$legs,$callback;$allowed_proto,$allowed_legs)
#   $uri: URI to resolve
#   $dst_addr: reference to list where to put dst_addr
#   $legs: reference to list where to put leg
#   $callback: called with () if resolved successfully, else called
#      with @error
#   $allowed_proto: optional \@list of protocols (default udp, tcp, tls).
#      If given only only these protocols will be considered and in this order.
#   $allowed_legs: optional list of legs which are allowed
# Returns: NONE
###########################################################################
sub resolve_uri {
    my Net::SIP::Dispatcher $self = shift;
    my ($uri,$dst_addr,$legs,$callback,$allowed_proto,$allowed_legs) = @_;

    # packet should be a request packet (see constructor of *::Dispatcher::Packet)
    my ($domain,$user,$sip_proto,$param) = sip_uri2parts($uri);
    $domain or do {
	DEBUG( 50,"bad URI '$uri'" );
	return invoke_callback($callback, EHOSTUNREACH );
    };

    my @proto;
    my $force_port;
    my $default_port = 5060;
    if ( $sip_proto eq 'sips' ) {
	$default_port = 5061;
	@proto = 'tls';
    } elsif ( my $p = $param->{transport} ) {
	# explicit spec of proto
	@proto = lc($p)
    } else {
	# XXXX maybe we should use tcp first if the packet has a specific
	# minimum length, udp should not be used at all if the packet size is > 2**16
	@proto = ( 'udp','tcp' );
    }

    # change @proto so that only the protocols from $allowed_proto are ini it
    # and that they are tried in the order from $allowed_proto
    if ( $allowed_proto && @$allowed_proto ) {
	my @proto_new;
	foreach my $ap ( @$allowed_proto ) {
	    my $p = first { $ap eq $_ } @proto;
	    push @proto_new,$p if $p;
	}
	@proto = @proto_new;
	@proto or do {
	    DEBUG( 50,"no protocols allowed for $uri" );
	    @$dst_addr = ();
	    return invoke_callback( $callback, ENOPROTOOPT ); # no proto available
	};
    }

    $dst_addr ||= [];
    $allowed_legs ||= [ $self->get_legs ];
    if ( @$legs ) {
	my %allowed = map { $_ => 1 } @$legs;
	@$allowed_legs = grep { $allowed{$_} } @$allowed_legs;
    }
    @$allowed_legs or do {
	DEBUG( 50,"no legs allowed for '$uri'" );
	return invoke_callback($callback, EHOSTUNREACH );
    };

    my $ip_addr = $param->{maddr};
    {
	my ($host,$port,$family) = eval { ip_string2parts($domain, $ip_addr ? 1:0) };
	$host or do {
	    DEBUG( 50,"bad URI '$uri'" );
	    return invoke_callback($callback, EHOSTUNREACH );
	};
	$force_port = $port if defined $port;
	if ($family) {
	    $ip_addr ||= $host;
	    $domain = ip_ptr($host,$family);
	} else {
	    $domain = $host;
	}
    }
    DEBUG( 100,"domain=$domain" );

    # do we have a fixed proxy for the domain or upper domain?
    if ( ! @$dst_addr ) {
	my $d2p = $self->{domain2proxy};
	if ( $d2p && %$d2p ) {
	    my $dom = $domain;
	    my $addr = $d2p->{$dom}; # exact match
	    while ( ! $addr) {
		$dom =~s{^[^\.]+\.}{} or last;
		$addr = $d2p->{ "*.$dom" };
	    }
	    $addr ||= $d2p->{ $dom = '*'}; # catch-all
	    if ( $addr ) {
		DEBUG( 50,"setting dst_addr from domain specific proxy for domain $dom" );
		@$dst_addr = @$addr;
		undef $force_port;
	    }
	}
    }

    # do we have a global outgoing proxy?
    if ( !@$dst_addr
	&& ( my $addr = $self->{outgoing_proxy} )) {
	# if we have a fixed outgoing proxy use it
	DEBUG( 50,"setting dst_addr+leg to $addr from outgoing_proxy" );
	@$dst_addr = ( $addr );
	undef $force_port;
    }

    # is it an IP address?
    if ( !@$dst_addr && $ip_addr ) {
	DEBUG( 50,"setting dst_addr from URI because IP address given" );
	@$dst_addr = ( $ip_addr );
    }

    # is param maddr set?
    if ( my $ip = $param->{maddr} ) {
	@$dst_addr = ($ip) if ip_is_v46($ip);
    }


    # entries are hashes of prio,proto,host,addr,port,family
    my @resp;
    foreach my $addr ( @$dst_addr ) {
	if ( ref($addr)) {
	    push @resp,$addr; # right format: see domain2proxy
	} else {
	    my ($proto,$host,$port,$family) = sip_uri2sockinfo($addr)
		or next;
	    $addr = lock_ref_keys({
		proto  => $proto,
		host   => $host,
		addr   => $family ? $host : undef,
		port   => $port || $force_port || $default_port,
		family => $family
	    });
	    push @resp, map { lock_ref_keys({
		%$addr,
		proto => $_,
		prio  => SRV_PRIO_UNDEF,
	    }) } $proto ? ($proto) : @proto;
	}
    }

    # should we use a fixed transport?
    if (@resp and  my $proto = $param->{transport} ) {
	$proto = lc($proto);
	if ($proto eq 'udp') {
	    @resp = grep { $_->{proto} eq 'udp' } @resp
	} elsif ($proto eq 'tcp') {
	    # accept proto tcp and tls
	    @resp = grep { $_->{proto} ne 'udp' } @resp
	} elsif ($proto eq 'tls') {
	    @resp = grep { $_->{proto} eq 'tls' } @resp
	} else {
	    # no matching proto available
	    @resp = ();
	}
	return invoke_callback($callback, ENOPROTOOPT) if ! @resp;
    }

    my @param = ( $dst_addr,$legs,$allowed_legs,$force_port,$default_port,$callback );
    if (@resp) {
	# directly call __resolve_uri_final if all names are resolved
	return __resolve_uri_final( @param,\@resp )
	    if ! grep { ! $_->{addr} } @resp;
	return $self->dns_host2ip(\@resp,
	    [ \&__resolve_uri_final, @param ]);
    }

    # If no fixed mapping DNS needs to be used

    # XXXX no full support for RFC3263, eg we don't support NAPTR
    # but query instead directly for _sip._udp.domain.. like in
    # RFC2543 specified

    # filter protocols not supported by any leg
    my @proto_new;
    foreach my $p ( @proto ) {
	my $l = first { $_->match({ proto => $p }) } @$allowed_legs;
	push @proto_new,$p if $l;
    }
    @proto = @proto_new;
    @proto or do {
	DEBUG( 50,"no legs allowed for $uri" );
	@$dst_addr = ();
	return invoke_callback( $callback, ENOPROTOOPT ); # no proto available
    };

    return $self->dns_domain2srv($domain, \@proto,
	[ \&__resolve_uri_final, @param ]);
}

sub __resolve_uri_final {
    my ($dst_addr,$legs,$allowed_legs,$force_port,$default_port,$callback,$resp) = @_;
    $DEBUG && DEBUG_DUMP( 100,$resp );

    return invoke_callback( $callback,EHOSTUNREACH )
	unless $resp && @$resp;

    # overwrite port if it was forced by user
    do { $_->{port} = $force_port for(@$resp) } if $force_port;

    # for A|AAAA records we got no port, use default_port
    $_->{port} ||= $default_port for(@$resp);

    # sort by prio and eliminate duplicates
    # FIXME: can contradict order in @proto
    if (@$resp>1) {
	my %dup;
	@$resp =
	    sort { $a->{prio} <=> $b->{prio} }
	    grep { !$dup{$_->{host},$_->{family},$_->{proto},$_->{addr},$_->{port}}++ }
	    @$resp;
    }

    @$dst_addr = ();
    @$legs = ();
    foreach my $r ( @$resp ) {
	if (my @l = grep { $_->can_deliver_to(
	    proto  => $r->{proto},
	    host   => $r->{host},
	    addr   => $r->{addr},
	    port   => $r->{port},
	    family => $r->{family},
	)} @$allowed_legs) {
	    push @$dst_addr, $r;
	    push @$legs, @l;
	} else {
	    DEBUG(50,"no leg with $r->{proto} to %s", ip_parts2string($r));
	}
    }

    # remove duplicates
    if (@$legs>1) {
	my %dup;
	@$legs = grep { !$dup{$_}++ } @$legs;
    }

    return invoke_callback( $callback, EHOSTUNREACH ) if !@$dst_addr;
    invoke_callback( $callback );
}


sub _find_leg4addr {
    my Net::SIP::Dispatcher $self = shift;
    my $dst_addr = shift;
    if (!ref($dst_addr)) {
	my @si = sip_uri2sockinfo($dst_addr);
	$dst_addr = lock_ref_keys({
	    proto  => $si[0],
	    host   => $si[1],
	    addr   => $si[3] ? $si[1] : undef,
	    port   => $si[2],
	    family => $si[3],
	});
    }
    return grep { $_->can_deliver_to(%$dst_addr) } @{ $self->{legs} };
}

###########################################################################
# resolve hostname to IP using DNS
# Args: ($self,$host,$callback)
#   $host: hostname or hash with hostname as keys or list of hashes which have
#     a host value but miss an addr value
#   $callback: gets called with (result)|() once finished
#     result is @IP for single hosts or the input hash ref where the
#     IPs are filled in as values or the list filled with addr, family
# Returns: NONE
###########################################################################
sub dns_host2ip {
    my Net::SIP::Dispatcher $self = shift;
    my ($host,$callback) = @_;

    my (@rec,$cb);
    if (!ref($host)) {
	# scalar: return ip(s)
	@rec = { host => $host };
	my $transform = sub {
	    my ($callback,$res) = @_;
	    invoke_callback($callback,
		grep { $_ } map { $_->{addr} } @$res);
	};
	$cb = [ $transform, $callback ];

    } elsif (ref($host) eq 'HASH') {
	# hash: fill hash values
	@rec = map { (host => $_) } keys(%$host);
	return invoke_callback($callback, $host) if ! @rec;
	my $transform = sub {
	    my ($host,$callback,$res) = @_;
	    $host->{$_->{host}} = $_->{addr} for @$res;
	    invoke_callback($callback, $host);
	};
	$cb = [ $transform, $host, $callback ];

    } else {
	# list of hashes: fill in addr and family in place
	my @hasip;
	for(@$host) {
	    if ($_->{addr}) {
		push @hasip, $_;
	    } else {
		push @rec, $_;
	    }
	}
	return invoke_callback($callback, $host) if ! @rec;

	my $transform = sub {
	    my ($hasip,$callback,$res) = @_;
	    # original order might be changed !!!
	    push @$res, @$hasip;
	    invoke_callback($callback, $res);
	};
	$cb = [ $transform, \@hasip, $callback ];
    }

    my @queries;
    for (@rec) {
	my %q = (name => $_->{host}, rec => $_);
	push @queries, { type  => 'AAAA', %q } if CAN_IPV6;
	push @queries, { type  => 'A',    %q };
    }

    my $res = $self->{dnsresolv} || __net_dns_resolver($self->{eventloop});
    __generic_resolver({
	queries  => \@queries,
	callback => $cb,
	resolver => $res,
    });
}

###########################################################################
# get SRV records using DNS
# Args: ($self,$domain,$proto,$sip_proto,$callback)
#   $domain: domain for SRV query
#   $proto: which protocols to check: list of udp|tcp|tls
#   $callback: gets called with result once finished
#      result is \@list of hashes with prio, proto, host ,port, family
# Returns: NONE
###########################################################################
sub dns_domain2srv {
    my Net::SIP::Dispatcher $self = shift;
    my ($domain,$protos,$callback) = @_;

    # Try to get SRV records for _sip._udp.domain or _sip._tcp.domain
    my @queries;
    for(@$protos) {
	push @queries, {
	    type  => 'SRV',
	    name  => $_ eq 'tls' ? "_sips._tcp.$domain" : "_sip._$_.$domain",
	    rec => { host => $domain, proto => $_ },
	}
    }

    # If we have any results for SRV we can break,
    # otherwise continue with with A|AAAA
    push @queries, { type => 'BREAK-IF-RESULTS' };
    for(@$protos) {
	my %r = (
	    name => $domain,
	    rec => {
		prio => SRV_PRIO_UNDEF,
		host => $domain,
		proto => $_,
		port => undef,
	    }
	);
	push @queries, { type => 'AAAA', %r } if CAN_IPV6;
	push @queries, { type => 'A', %r };
    }

    my $res = $self->{dnsresolv} || __net_dns_resolver($self->{eventloop});
    __generic_resolver({
	queries  => \@queries,
	callback => $callback,
	resolver => $res,
    });
}


# generic internal resolver helper
# expects to be initially called as
#   __generic_resolver({
#	queries  => \@queries,
#	callback => $callback,
#	resolver => $res,
#   });
#
# where queries are a list of tasks for DNS lookup with
#  type: SRV|A|AAAA
#  name: the name to lookup
#  rec:  the record to enrich with
#         SRV: prio, proto, host, addr, port, family
#         A|AAAA: addr, family
#
# resolver is a function to do the actual resolving.
# An implementation using Net::DNS is done in __net_dns_resolver.
# It will be called as
#  resolver->(type,name,callback) where
#  type:     SRV|A|AAAA
#  name:     the name to lookup
#  callback: callback to invoke after lookup is done with the list of
#    answers, i.e. list-ref containing
#    [ 'SRV',  prio, proto, host, port ]
#    [ 'A',    addr, name ]
#    [ 'AAAA', addr, name ]
#
# callback is invoked when all queries are done with the list of
# enriched records

sub __generic_resolver {
    my ($state,$qid,$ans) = @_;
    $DEBUG && DEBUG_DUMP(100,[$qid,$ans]) if $qid;

    my $queries = $state->{queries};
    my $results = $state->{results} ||= [];
    goto after_answers if !$qid;

    for(my $i=0; $i<@$queries; $i++) {
	my $q = $queries->[$i];
	if ($q->{type} eq 'BREAK-IF-RESULTS') {
	    if (@$results and $i==0) {
		# skip remaining queries
		@$queries = ();
		last;
	    }
	    if ($i==0) {
		# remove if top query
		shift(@$queries);
		$i--;
	    }
	    next;
	}

	"$q->{type}:$q->{name}" eq $qid or next;

	# query matches qid of answer, remove from @$queries
	splice(@$queries,$i,1);
	$i--;

	if ($q->{type} eq 'SRV') {
	    my (%addr2ip,@res);
	    for(@$ans) {
		my $type = shift(@$_);
		if ($type eq 'A' or CAN_IPV6 ? $type eq 'AAAA' : 0) {
		    # supplemental data
		    my ($ip,$name) = @_;
		    push @{ $addr2ip{$name}}, [$ip, $type];
		    next;
		}
		next if $type ne 'SRV';
		my ($prio,$host,$port) = @$_;
		my $family = ip_is_v46($host);
		push @res, lock_ref_keys({
		    %{$q->{rec}},
		    prio   => $prio,
		    host   => $host,
		    addr   => $family ? $host : undef,
		    port   => $port,
		    family => $family,
		});
	    }
	    for(my $i=0; $i<@res; $i++) {
		$res[$i]{family} and next;
		my $ipt = $addr2ip{$res[$i]{host}} or next;
		my $r = splice(@res,$i,1);
		for(@$ipt) {
		    my ($ip,$type) = @$_;
		    splice(@res,$i,0, lock_ref_keys({
			%$r,
			addr => $ip,
			family => $type eq 'A' ? AF_INET : AF_INET6,
		    }));
		    $i++;
		}
		$i--;
	    }
	    for my $r (@res) {
		if ($r->{family}) {
		    # done: host in SRV record is already IP address
		    push @$results, $r;
		    next;
		}

		# need to resolve host in SRV record - put queries on top
		for my $type (CAN_IPV6 ? qw(AAAA A) : qw(A)) {
		    unshift @$queries, {
			type => $type,
			name => $r->{host},
			rec => lock_ref_keys({
			    %$r,
			    family => $type eq 'A' ? AF_INET : AF_INET6,
			})
		    };
		}
	    }

	} elsif ($q->{type} eq 'AAAA' || $q->{type} eq 'A') {
	    for(@$ans) {
		my ($type,$ip) = @$_;
		push @$results, lock_ref_keys({
		    %{$q->{rec}},
		    addr   => $ip,
		    family => $type eq 'A' ? AF_INET : AF_INET6,
		});
	    }
	} else {
	    die "unknown type $q->{type}";
	}
    }

    after_answers:
    if (!@$queries) {
	# no more queries -> done
	invoke_callback($state->{callback}, @$results && $results);
	return;
    }

    # still queries -> send next to resolver
    my $q = $queries->[0];
    DEBUG(52,'issue lookup for %s %s',$q->{type}, $q->{name});
    $state->{resolver}($q->{type}, $q->{name}, [
	\&__generic_resolver,
	$state,
	"$q->{type}:$q->{name}"
    ]);
}

my $NetDNSResolver;
sub __net_dns_resolver {
    my $eventloop = shift;

    # Create only a single resolver.
    $NetDNSResolver ||= eval {
	require Net::DNS;
	Net::DNS->VERSION >= 0.56 or die "version too old, need 0.56+";
	Net::DNS::Resolver->new;
    } || die "cannot create resolver: Net::DNS not available?: $@";

    my $dnsread = sub {
	my ($sock,$callback) = @_;
	my $q = $NetDNSResolver->bgread($sock);
	$eventloop->delFD($sock);
	my @ans;
	for my $rr ( $q->answer ) {
	    if ($rr->type eq 'SRV' ) {
		push @ans, [
		    'SRV',
		    $rr->priority,
		    $rr->target,
		    $rr->port,
		];
	    } elsif ($rr->type eq 'A' || $rr->type eq 'AAAA') {
		push @ans, [ $rr->type, $rr->address, $rr->name ];
	    }
	}
	invoke_callback($callback,\@ans);
    };

    return sub {
	my ($type,$name,$callback) = @_;
	my $sock = $NetDNSResolver->bgsend($name,$type);
	$eventloop->addFD($sock, EV_READ,
	    [$dnsread, $sock, $callback],
	    'dns'
	);
    };
}


###########################################################################
# Net::SIP::Dispatcher::Packet
# Container for Queue entries in Net::SIP::Dispatchers queue
###########################################################################
package Net::SIP::Dispatcher::Packet;
use fields (
    'id',           # transaction id, used for canceling delivery if response came in
    'callid',       # callid, used for canceling all deliveries for this call
    'packet',       # the packet which nees to be delivered
    'dst_addr',     # to which adress the packet gets delivered, is array-ref because
		    # the DNS/SRV lookup might return multiple addresses and protocols:
		    # [ { hash: proto, addr, port, family, host }, { ... }, ...]
    'leg',          # through which leg the packet gets delivered, same number
		    # of items like dst_addr
    'retransmits',  # array of retransmit time stamps, if undef no retransmit will be
		    # done, if [] no more retransmits can be done (trigger ETIMEDOUT)
		    # the last element in this array will not used for retransmit, but
		    # is the timestamp, when the delivery fails permanently
    'callback',     # callback for DSN (success, ETIMEDOUT...)
    'proto',        # list of possible protocols, default tcp and udp for sip:
);

use Net::SIP::Debug;
use Net::SIP::Util ':all';
use Hash::Util 'lock_ref_keys';

###########################################################################
# create new Dispatcher::Packet
# Args: ($class,%args)
#  %args: hash with values according to fields
#    for response packets leg and dst_addr must be set
# Returns: $self
###########################################################################
sub new {
    my ($class,%args) = @_;
    my $now = delete $args{now};

    my $self = fields::new( $class );
    %$self = %args;
    $self->{id} ||= $self->{packet}->tid;
    $self->{callid} ||= $self->{packet}->callid;

    my $addr = $self->{dst_addr};
    if (!$addr) {
    } elsif (!ref($addr)) {
	my @si = sip_uri2sockinfo($addr);
	$self->{dst_addr} = [ lock_ref_keys({
	    proto  => $si[0],
	    host   => $si[1],
	    addr   => $si[3] ? $si[1] : undef,
	    port   => $si[2],
	    family => $si[3],
	}) ];
    } elsif (ref($addr) eq 'HASH') {
	$self->{dst_addr} = [ $addr ];
    } else {
	# assume its already in the expected format, i.e. list of hashes
    }
    if ( my $leg = $self->{leg} ) {
	$self->{leg} = [ $leg ] if UNIVERSAL::can( $leg,'deliver' );
    }

    $self->{dst_addr} ||= [];
    $self->{leg} ||= [];
    return $self;
}

###########################################################################
# prepare retransmit infos if dispatcher handles retransmits itself
# Args: ($self;$now)
#   $now: current time
# Returns: NONE
###########################################################################
sub prepare_retransmits {
    my Net::SIP::Dispatcher::Packet $self = shift;
    return if $self->{leg}[0] && ! $self->{leg}[0]->do_retransmits;

    my $now = shift;
    my $p = $self->{packet};

    # RFC3261, 17.1.1.2 (final response to INVITE) -> T1=0.5, T2=4
    # RFC3261, 17.1.2.2 (non-INVITE requests)      -> T1=0.5, T2=4
    # RFC3261, 17.1.1.2 (INVITE request)           -> T1=0.5, T2=undef
    # no retransmit -> T1=undef

    my ($t1,$t2);
    if ( $p->is_response ) {
	if ( $p->code > 100 && $p->cseq =~m{\sINVITE$} ) {
	    # this is a final response to an INVITE
	    # this is the only type of response which gets retransmitted
	    # (until I get an ACK)
	    ($t1,$t2) = (0.500,4);
	}
    } elsif ( $p->method eq 'INVITE' ) {
	# INVITE request
	($t1,$t2) = (0.500,undef);
    } elsif ( $p->method eq 'ACK' ) {
	# no retransmit of ACKs
    } else {
	# non-INVITE request
	($t1,$t2) = (0.500,4);
    }

    # no retransmits?
    $t1 || return;

    $now ||= time();
    my $expire = $now + 64*$t1;
    my $to = $t1;
    my $rtm = $now + $to;

    my @retransmits;
    while ( $rtm < $expire ) {
	push @retransmits, $rtm;
	$to *= 2;
	$to = $t2 if $t2 && $to>$t2;
	$rtm += $to
    }
    DEBUG( 100,"retransmits $now + ".join( " ", map { $_ - $now } @retransmits ));
    $self->{retransmits} = \@retransmits;
}



###########################################################################
# use next dst_addr (eg if previous failed)
# Args: $self
# Returns: $addr
#   $addr: new address it will use or undef if no more addresses available
###########################################################################
sub use_next_dstaddr {
    my Net::SIP::Dispatcher::Packet $self = shift;
    my $addr = $self->{dst_addr} || return;
    shift(@$addr);
    my $leg = $self->{leg} || return;
    shift(@$leg);
    return @$addr && $addr->[0];
}

###########################################################################
# trigger callback to upper layer
# Args: ($self;$errno)
#  $errno: Errno
# Returns: $callback_done
#  $callback_done: true if callback was triggered, if no callback existed
#    returns false
###########################################################################
sub trigger_callback {
    my Net::SIP::Dispatcher::Packet $self = shift;
    my $error = shift;
    my $cb = $self->{callback} || return;
    invoke_callback( $cb,$error,$self);
    return 1;
}

###########################################################################
# return transaction id of packet
# Args: $self
# Returns: $tid
###########################################################################
sub tid {
    my Net::SIP::Dispatcher::Packet $self = shift;
    return $self->{packet}->tid;
}
1;
