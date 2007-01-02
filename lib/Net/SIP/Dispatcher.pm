
###########################################################################
# package Net::SIP::Dispatcher
# manages the sending and receiving from packets through the Legs
# packets will be send using the deliver() command, received packets
# will be propageted to the upper layer using receiver->receive
# This layer converts URI in outgoing requests to addr(s) and finds 
# the associated leg, the delivery itself will be done using leg->deliver
# This layer does not really care about timeouts, but the upper layer can give
# a timeout when deliver()ing a packet and the dispatcher will call the
# upper layer back, if the delivery wasn't definitly successful within the
# timeframe (definitly successful was it only if it was send over a reliable
# transport, eg tcp, or if the upper layer signaled that it received a response
# using cancel_delivery())
# The upper layer is responsible for retrying. Therefore it will receive
# a *::Dispatcher::Packet back in the callback if an error occured and
# can timely redeliver the packet. If all attempts to deliver the packet
# to one address failed it can call dpacket->use_next_dstaddr for trying
# the next address.
# - deliver
#   deliver the packet to dstaddr through the leg
#   on definite success (only tcp) call callback
#   on definite failure (no route, timeout,..) call callback
#   if leg,addr not given determine them from the (request) packets URI
#   packet gets send but if send not definitly successful it will stay for 
#   timeout in the queue and notify the upper layer if timeout gone
# - cancel_delivery
#   cancel pending delivery/timeout of all packets with id
#   used by the upper layer to remove packets from send queue if it
#   received already a response to it
# - mainloop
#   mainloop: try delivery of packets in send-queue, handle timeouts
#   and receive packets
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
	'outgoing_leg',   # Leg for outgoing_proxy
	'queue',          # \@list of outstanding Net::SIP::Dispatcher::Packet
	'response_cache', # Cache of responses, used to reply to retransmits
);

use Net::SIP::Leg;
use Net::SIP::Util qw( invoke_callback );
use Errno qw(EHOSTUNREACH ETIMEDOUT);
use IO::Socket;
use List::Util 'first';
use Net::DNS;
use Carp 'croak';
use Net::SIP::Debug;


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
#       proxy can be ip,ip:port or \@list of [ prio,proto,ip,port ] like
#       in the DNS SRV record.
#       with special domain '*' a default can be specified, so that DNS
#       will not be used at all
# Returns: $self
###########################################################################
sub new {
	my ($class,$legs,$eventloop,%args) = @_;
	my ($outgoing_proxy,$do_retransmits,$domain2proxy) 
		= delete @args{qw( outgoing_proxy do_retransmits domain2proxy )};
	die "bad args: ".join( ' ',keys %args ) if %args;

	$eventloop ||= Net::SIP::Dispatcher::Eventloop->new;

	# normalize domain2proxy so that its the same format one gets from
	# the SRV record
	$domain2proxy ||= {};
	foreach ( values %$domain2proxy ) {
		if ( ref($_) ) { # should be \@list of [ prio,proto,ip,port ]
		} elsif ( m{^([\d\.]+)(?::(\d+))} ) {
			$_ = [ [ -1,'udp',$1,$2 ||5060 ] ]
		} else {
			croak( "invalid entry in domain2proxy: $_" );
		}
	}

	my $self = fields::new($class);
	%$self = (
		legs => [],
		queue  => [],
		outgoing_proxy => undef,
		outgoing_leg => undef,
		response_cache => {},
		do_retransmits => defined( $do_retransmits ) ? $do_retransmits : 1,
		eventloop => $eventloop,
		domain2proxy => $domain2proxy,
	);

	$self->add_leg( @$legs );

	if ( $outgoing_proxy ) {
		my $leg = $self->_find_leg4addr( $outgoing_proxy )
			|| die "cannot find leg for destination $outgoing_proxy";
		$self->{outgoing_proxy} = $outgoing_proxy;
		$self->{outgoing_leg}   = $leg;
	}


	# regularly prune queue
	my $sub = sub {
		my ($self,$loop) = @_;
		$self->queue_expire($loop->looptime);
	};
	$self->add_timer( 1,[ $sub,$self,$eventloop ],1 );

	return $self;
}

###########################################################################
# set receiver, e.g the upper layer which gets the incoming packets
# received by the dispatcher
# Args: ($self,$receiver)
#   $receiver: object which has receive( Net::SIP::Leg,Net::SIP::Packet ) 
#     method to handle incoming SIP packets or callback
# Returns: NONE
###########################################################################
sub set_receiver {
	my Net::SIP::Dispatcher $self = shift;
	my $receiver = shift;
	if ( my $sub = UNIVERSAL::can($receiver,'receive' )) {
		# Object with method receive()
		$receiver = [ $sub,$receiver ]
	}
	$self->{receiver} = $receiver;
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
	foreach my $leg (@_) {

		# copy before modifying
		my $leg = $leg; 

		# if it is not a leg yet create one based
		# on the arguments
		if ( UNIVERSAL::isa( $leg,'Net::SIP::Leg' )) {
			# already a leg

		} elsif ( UNIVERSAL::isa( $leg,'IO::Handle' )) {
			# create from socket
			my $sock = $leg;
			$leg = Net::SIP::Leg->new( sock => $sock );

		} elsif ( UNIVERSAL::isa( $leg,'HASH' )) {
			# create from %args
			my %args = %$leg;
			$leg = Net::SIP::Leg->new( %args );
		}

		push @$legs, $leg;

		my $cb = sub {
			my ($self,$leg) = @_;

			# leg->receive might return undef if the packet wasnt
			# read successfully. for tcp connections the receive
			# on a listening socket might cause a new leg to be added
			# which then will receive the packet (maybe over multiple
			# read attempts)
			my ($packet,$from) = $leg->receive or do {
				DEBUG( "failed to receive" );
				return;
			};

			# handle received packet
			$self->receive( $packet,$leg,$from );
		};
		$self->{eventloop}->addFD( $leg->{sock}, [ $cb,$self,$leg ]);
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
		$self->{eventloop}->delFD( $leg->{sock} );
	}
}

###########################################################################
# find legs matching specific criterias
# Args: ($self,%args)
#  %args: Hash with some of these keys
#    addr: leg must match addr
#    port: leg must match port
#    proto: leg must match proto
#    sock: leg must match sock
#    sub:  $sub->($leg) must return true
# Returns: @legs
#   @legs: all Legs matching the criteria
# Comment:
# if no criteria given it will return all legs
###########################################################################
sub get_legs {
	my Net::SIP::Dispatcher $self = shift;
	my %args = @_;
	my @rv;
	foreach my $leg (@{ $self->{legs} }) {
		next if $args{addr} && $args{addr} ne $leg->{addr};
		next if $args{port} && $args{port} != $leg->{port};
		next if $args{proto} && $args{proto} ne $leg->{proto};
		next if $args{sock} && $args{sock} != $leg->{sock};
		next if $args{sub} && !$args{sub}->($leg);
		push @rv,$leg
	}
	return @rv;
}
	

###########################################################################
# add timer
# propagates to addTimer of eventloop
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
	return $self->{eventloop}->addTimer( @_ );
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
#     dst_addr:  specify outgoing addr [ip,port] or sockaddr, needed 
#       for responses
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

	DEBUG( "deliver $packet" );

	if ( $packet->is_response ) {
		# cache response for 32 sec (64*T1)
		my $cid = $packet->get_header( 'cseq' )
			."\0".$packet->get_header( 'call-id' );
		$self->{response_cache}{$cid} = {
			packet => $packet,
			expire => ( $now ||= time()) +32
		};
	}

	my $new_entry = Net::SIP::Dispatcher::Packet->new(
		packet => $packet,
		%more_args
	);

	$new_entry->prepare_retransmits( $now ) if $do_retransmits;

	push @{ $self->{queue}}, $new_entry;
	$self->__deliver( $new_entry );
}

###########################################################################
# cancel delivery of all packets with specific id
# Args: ($self,$id)
#   $id: id to cancel, can also be queue entry
# Returns: NONE
###########################################################################
sub cancel_delivery {
	my Net::SIP::Dispatcher $self = shift;
	my ($id) = @_;
	my $q = $self->{queue};
	if ( ref($id)) {
		# it's a *::Dispatcher::Packet
		DEBUG( "cancel packet $id: $id->{id}" );
		@$q = grep { $_ != $id } @$q;
	} else {
		no warnings; # $_->{id} can be undef
		DEBUG( "cancel packet $id" );
		@$q = grep { $_->{id} ne $id } @$q;
	}
}



###########################################################################
# Receive a packet from a leg and forward it to the upper layer
# if the packet is a request and I have a cached response resend it
# w/o involving the upper layer
# Args: ($self,$packet,$leg,$from)
#   $packet: Net::SIP::Packet
#   $leg:    through which leg it was received
#   $from:   where the packet comes from (ip:port)
# Returns: NONE
# Comment: if no receiver is defined using set_receiver the packet
#   will be silently dropped
###########################################################################
sub receive {
	my Net::SIP::Dispatcher $self = shift;
	my ($packet,$leg,$from) = @_;

	if ( $packet->is_request ) {
		my $cid = $packet->get_header( 'cseq' )
			."\0".$packet->get_header( 'call-id' );

		if ( my $response = $self->{response_cache}{$cid} ) {
			# I have a cached response, use it
			$self->deliver($response->{packet}, leg => $leg, dst_addr => $from);
			return;
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
				# completly expired
				DEBUG( "entry %s expired because expire=%.2f but now=%d", $qe->tid,$retransmit,$now );
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

	while (1) {

		# loop until leg und dst_addr are known, when we call leg->deliver
		my $leg = $qentry->{leg};
		my $dst_addr = $qentry->{dst_addr}[0];

		if ( ! $dst_addr ) {

			DEBUG( "no dst_addr yet" );

			if ( my $addr = $self->{outgoing_proxy} ) {
				# if we have a fixed outgoing proxy use it
				$qentry->set_dstaddr( $addr );
				$qentry->{leg} = $self->{outgoing_leg};
				DEBUG( "setting dst_addr to $addr from outgoing_proxy" );
				next;
			}

			return $self->__resolve_uri( $qentry, [ \&__deliver,$self,$qentry ] );

		} elsif ( ! $leg ) {
			# find leg for dst_addr
			DEBUG( "no leg for dst_addr=$dst_addr yet" );
			$qentry->{leg} = $self->_find_leg4addr( $dst_addr )
				|| return $qentry->trigger_callback( EHOSTUNREACH );
			next;

		} else {
			# I have leg and addr, send packet thru leg to addr
			my $cb = sub {
				my ($qentry,$error) = @_;
				if ( !$error  && $qentry->{retransmits} ) {
					# remove from queue even if timeout
					$self->cancel_delivery( $qentry );
				}
				$qentry->trigger_callback( $error );
			};

			# adds via on cloned packet, calls cb if definite success (tcp)
			# or error
			DEBUG( "deliver through leg $leg \@$dst_addr" );
			$leg->deliver( $qentry->{packet},$dst_addr, [ $cb,$qentry ] );

			if ( !$qentry->{retransmits} ) {
				# remove from queue if no timeout
				$self->cancel_delivery( $qentry );
			}
		}
		last;
	}
		
}


###########################################################################
# resolve URI, eg determine dst_addr for URI
# Args: ($self,$qentry,$callback)
#   $qentry: *::Dispatcher::Packet
#   $callback: [ $sub,@arg ], called if resolving is successfully done
#      if resolving failed it will call the callback from $qentry
# Returns: NONE
###########################################################################
sub __resolve_uri {
	my Net::SIP::Dispatcher $self = shift;
	my ($qentry,$callback) = @_;

	# we need to get dst_addr from URI
	# packet should be a request packet (see constructor of *::Dispatcher::Packet)
	my $uri = $qentry->{packet}->uri;
	my $domain = $uri;
	$domain =~s{^<?sip\w*:}{}i; # strip protocol
	$domain =~s{.*\@}{};        # strip user part
	$domain =~s{[>\s;].*}{};    # strip parameters...
	if ( $domain eq '' ) {
		# bad URI!
		$qentry->trigger_callback( EHOSTUNREACH );
		return $self->cancel_delivery( $qentry );
	}

	my @proto;
	my $default_port = 5060;
	my $sip_proto = 'sip';
	# XXXX hack, better would be to really parse URI, see *::Util::sip_hdrval2parts
	if ( $uri =~m{^sips:}i ) {
		$default_port = 5061;
		@proto = 'tcp';
		$sip_proto = 'sips';
	} elsif ( $uri =~m{;transport="?(udp|tcp)}i ) {
		# explicit spec of proto
		@proto = lc($1)
	} else {
		# XXXX maybe we should use tcp first if the packet has a specific
		# minimum length, udp should not be used at all if the packet size is > 2**16
		@proto = ( 'udp','tcp' );
	}

	# if domain part of URI looks like 
	if ( $domain =~m{^\d+\.\d+\.\d+\.\d+(:\d+)?$} ) {
		# looks like IPv4 address
		my $addr = $1 ? $domain: $domain.':'.$default_port;
		$qentry->set_dstaddr( map { "$_:$addr" } @proto );
		invoke_callback( $callback );
		return;
	}

	# do we have a fixed mapping for the domain or upper domain?
	my $resp;
	my $d2p = $self->{domain2proxy};
	if ( $d2p && %$d2p ) {
		$domain =~s{\.+$}{}; # trailing dots
		while (1) {
			$resp = $d2p->{$domain} and last;
			$domain =~s{^[^\.]+\.}{} or last;
		}
		$resp ||= $d2p->{'*'}; # catch-all
	}

	# If no fixed mapping DNS need to be used
	if ( ! $resp ) {

		# XXXX no full support for RFC3263, eg we don't support NAPTR
		# but query instead directly for _sip._udp.domain.. like in
		# RFC2543 specified

		# XXXX fixme, don't do blocking DNS queries
		my $dns = Net::DNS::Resolver->new;

		# entries in form [ prio,proto,ip,port ]
		my @resp;

		# Try to get SRV records for _sip._udp.domain or _sip._tcp.domain
		foreach my $proto ( @proto ) {
			if ( my $q = $dns->query( '_'.$sip_proto.'._'.$proto.'.'.$domain,'SRV' )) {
				foreach my $rr ( $q->answer ) {
					$rr->type eq 'SRV' || next;
					# XXX fixme, get IPs for name
					push @resp,[ $rr->priority, $proto,$rr->name,$rr->port ]
				}
			}
		}
		# if no SRV records try to resolve address directly
		unless (@resp) {
			# try addr directly
			if ( my $q = $dns->query( $domain,'A' )) {
				foreach my $rr ($q->answer ) {
					$rr->type eq 'A' || next;
					# XXX fixme, get *all* IPs for name
					push @resp,map {
						[ -1, $_ , $rr->address,$default_port ]
					} @proto;
				}
			}
		}

		$resp = \@resp;
	}
	DEBUG_DUMP( $resp );
	if ( ! @$resp ) {
		$qentry->trigger_callback( EHOSTUNREACH );
		return $self->cancel_delivery( $qentry );
	}


	# sort by prio
	@$resp = sort { $a->[0] <=> $b->[0] } @$resp;

	my @addr = map { "$_->[1]:$_->[2]:$_->[3]" } @$resp;
	$qentry->set_dstaddr( @addr );
	invoke_callback( $callback );
}


sub _find_leg4addr {
	my Net::SIP::Dispatcher $self = shift;
	my $dst_addr = shift;
	my $legs = $self->{legs};
	return $legs->[0] if @$legs == 1;
	foreach my $leg (@$legs) {
		return $leg if $leg->can_deliver_to( $dst_addr );
	}
	return; # nothing found
}

###########################################################################
# Net::SIP::Dispatcher::Packet
# Container for Queue entries in Net::SIP::Dispatchers queue
###########################################################################
package Net::SIP::Dispatcher::Packet;
use fields ( 
	'id',           # transaction id, used for canceling delivery if response came in
	'packet',       # the packet which nees to be delivered
	'leg',          # through which leg the packet gets delivered
	'dst_addr',     # to which adress the packet gets delivered, is array-ref because
	                # the DNS/SRV lookup might return multiple addresses and protocols
	'retransmits',  # array of retransmit time stamps, if undef no retransmit will be
	                # done, if [] no more retransmits can be done (trigger ETIMEDOUT)
					# the last element in this array will not used for retransmit, but
					# is the timestamp, when the delivery fails permanently
	'callback',     # callback for DSN (success, ETIMEDOUT...)
);

use Net::SIP::Debug;
use Net::SIP::Util 'invoke_callback';

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

	if ( my $addr = $self->{dst_addr} ) {
		$self->{dst_addr} = [ $addr ] if !ref($addr)
	}

	# figure out retransmit times
	my $p = $self->{packet} || die "no packet for delivery";
	if ( $p->is_response ) {
		unless ( $self->{leg} && $self->{dst_addr} ) {
			die "Response packet needs leg and dst_addr"
		}
	}
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
	DEBUG( "retransmits $now + ".join( " ", map { $_ - $now } @retransmits ));
	$self->{retransmits} = \@retransmits;
}



###########################################################################
# set dst_addr
# Args: ($self,@dst_addr)
#   @dst_addr: hash with ip:port (ip, not hostname !!) or
#     proto:ip:port, where proto is udp|tcp. If no proto is
#     given udp is assumed
# Returns: NONE
###########################################################################
sub set_dstaddr {
	my Net::SIP::Dispatcher::Packet $self = shift;
	$self->{dst_addr} = [ @_ ]
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
	invoke_callback( $cb, $error ? ($error,$self):() );
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
