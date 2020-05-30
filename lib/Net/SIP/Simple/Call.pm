
###########################################################################
# Net::SIP::Simple::Call
# manages a call, contains Net::SIP::Endpoint::Context
# has hooks for some RTP handling
###########################################################################

use strict;
use warnings;

package Net::SIP::Simple::Call;
use base 'Net::SIP::Simple';
use fields qw( call_cleanup rtp_cleanup ctx param );

###########################################################################
# call_cleanup: callbacks for cleaning up call, called at the end
# rtp_cleanup: callbacks for cleaning up RTP connections, called
#   on reINVITEs and at the end
# ctx: Net::SIP::Endpoint::Context object for this call
# param: various parameter to control behavior
#   leg: thru which leg the call should be directed (default: first leg)
#   init_media: initialize handling for media (RTP) data, see
#    Net::SIP::Simple::RTP
#   sdp : predefined Net::SIP::SDP or data accepted from NET::SIP::SDP->new
#   media_lsocks: if sdp is provided the sockets has to be provided too
#     \@list of sockets for each media, each element in the list is
#     either the socket (udp) or [ rtp_socket,rtpc_socket ]
#   sdp_on_ack: send SDP data on ACK, not on INVITE
#   asymetric_rtp: socket for sending media to peer are not the same as
#      the sockets, where the media gets received, creates media_ssocks
#   media_ssocks: sockets used to send media to peer. If not given
#       and asymetric_rtp is used the sockets will be created, if not given
#       and not !asymetric_rtp media_lsocks will be used, e.g. symetric RTP
#   recv_bye: callback or scalar-ref used when call is closed by peer
#   send_bye: callback or scalar-ref used when call is closed by local side
#   sdp_peer: Net::SIP::SDP from peer
#   clear_sdp: ' causes that keys sdp,sdp_peer,media_ssocks and
#       media_lsocks gets cleared on new invite, so that a new SDP session
#       need to be established
#   cb_final: callback which will be called on final response in INVITE
#       with (status,self,%args) where status is OK|FAIL
#   cb_preliminary: callback which will be called on preliminary response
#       in INVITE with (self,code,packet)
#   cb_established: callback which will be called on receiving ACK in INVITE
#       with (status,self) where status is OK|FAIL
#   cb_invite: callback called with ($self,$packet) when INVITE is received
#   cb_dtmf: callback called with ($event,$duration) when DTMF events
#       are received, works only with media handling from Net::SIP::Simple::RTP
#   cb_notify: callback called with ($self,$packet) when NOTIFY is received
#   sip_header: hashref of SIP headers to add
#   call_on_hold: one-shot parameter to set local media addr to 0.0.0.0,
#       will be set to false after use
#   dtmf_methods: supported DTMF methods for receiving, default 'rfc2833,audio'
#   rtp_param: [ pt,size,interval,name ] RTP payload type, packet size and interval
#       between packets managed in Net::SIP::Simple::RTP, default is PCMU/8000,
#       e.g [ 0,160,160/8000 ]
#       a name can be added in which case an rtpmap and ptme entry will be created in the
#       SDP, e.g. [ 97,50,0.03,'iLBC/8000' ]
###########################################################################

use Net::SIP::Util qw(:all);
use Net::SIP::Debug;
use Net::SIP::DTMF 'dtmf_extractor';
use Socket;
use Storable 'dclone';
use Carp 'croak';
use Scalar::Util 'weaken';

###########################################################################
# create a new call based on a controller
# Args: ($class,$control,$ctx;$param)
#   $control: Net::SIP::Simple object which controls this call
#   $ctx: SIP address of peer for new call or NET::SIP::Endpoint::Context
#        or hashref for constructing NET::SIP::Endpoint::Context
#   $param: see description of field 'param'
# Returns: $self
###########################################################################
sub new {
    my ($class,$control,$ctx,$param) = @_;
    my $self = fields::new( $class );
    %$self = %$control;

    $self->{ua_cleanup} = [];
    $ctx = { to => $ctx } if ! ref($ctx);
    $ctx->{from}    ||= $self->{from};
    $ctx->{contact} ||= $self->{contact};
    $ctx->{auth}    ||= $self->{auth};
    $ctx->{route}   ||= $self->{route};
    $self->{ctx} = $ctx;

    $self->{call_cleanup} = [];
    $self->{rtp_cleanup}  = [];
    $self->{param} = $param ||= {};
    $param->{init_media} ||= $self->rtp( 'media_recv_echo' );
    $param->{rtp_param} ||= [ 0,160,160/8000 ]; # PCMU/8000: 50*160 bytes/second
    $param->{dtmf_events} ||= []; # get added by sub dtmf

    if (my $cb = delete $param->{cb_cleanup}) {
	push @{$self->{call_cleanup}}, $cb;
    }
    return $self;
}

###########################################################################
# Cleanups
# explicit cleanups might be necessary if callbacks reference back into
# the object so that it cannot be cleaned up by simple ref-counting alone
###########################################################################

sub cleanup {
    my Net::SIP::Simple::Call $self = shift;
    $self->rtp_cleanup;
    while ( my $cb = shift @{ $self->{call_cleanup} } ) {
	invoke_callback($cb,$self)
    }
    if (my $ctx = delete $self->{ctx}) {
	$self->{endpoint}->close_context( $ctx );
    }
    $self->{param} = {};
}

sub rtp_cleanup {
    my Net::SIP::Simple::Call $self = shift;
    while ( my $cb = shift @{ $self->{rtp_cleanup} } ) {
	invoke_callback($cb,$self)
    }
    DEBUG( 100,"done" );
}

sub DESTROY {
    DEBUG( 100,"done" );
}


###########################################################################
# return peer of call
# Args: $self
# Returns: $peer
###########################################################################
sub get_peer {
    my Net::SIP::Simple::Call $self = shift;
    return $self->{ctx}->peer;
}

###########################################################################
# set parameter
# Args: ($self,%param)
# Returns: $self
###########################################################################
sub set_param {
    my Net::SIP::Simple::Call $self = shift;
    my %args = @_;
    @{ $self->{param} }{ keys %args } = values %args;
    return $self;
}

###########################################################################
# get value for parameter(s)
# Args: ($self,@keys)
# Returns: @values|$value[0]
###########################################################################
sub get_param {
    my Net::SIP::Simple::Call $self = shift;
    my @v = @{$self->{param}}{@_};
    return wantarray ? @v : $v[0];
}

###########################################################################
# (Re-)Invite other party
# Args: ($self,%param)
#   %param: see description of field 'param', gets merged with param
#     already on object so that the values are valid for future use
# Returns: Net::SIP::Endpoint::Context
# Comment:
# If cb_final callback was not given it will loop until it got a final
# response, otherwise it will return immediately
###########################################################################
sub reinvite {
    my Net::SIP::Simple::Call $self = shift;
    my %args = @_;

    my $param = $self->{param};
    my $clear_sdp = delete $args{clear_sdp};
    $clear_sdp = $param->{clear_sdp} if ! defined $clear_sdp;
    if ( $clear_sdp ) {
	# clear SDP keys so that a new SDP session will be created
	@{ $param }{qw( sdp _sdp_saved sdp_peer media_ssocks media_lsocks )} = ()
    }
    $self->{param} = $param = { %$param, %args } if %args;


    my $leg = $param->{leg};
    if ( ! $leg ) {
	($leg) = $self->{dispatcher}->get_legs();
	$param->{leg} = $leg;
    }

    my $ctx = $self->{ctx};

    my $sdp;
    if ( ! $param->{sdp_on_ack} ) {
	$self->_setup_local_rtp_socks;
	$sdp = $param->{sdp}
    }

    # predefined callback
    my $cb = sub {
	my Net::SIP::Simple::Call $self = shift || return;
	my ($endpoint,$ctx,$errno,$code,$packet,$leg,$from,$ack) = @_;

	if ( $errno ) {
	    if (!$code || $code != 487) {
		$self->error( "Failed with error $errno".( $code ? " code=$code" :"" ) );
	    } else {
		# code 487: request was canceled, probably be me -> ignore
	    }
	    invoke_callback( $param->{cb_final}, 'FAIL',$self,errno => $errno,
		code => $code,packet => $packet );
	    return;
	}

	# new requests in existing call are handled in receive()
	return $self->receive( @_ ) if $packet->is_request;

	# response to INVITE
	# all other responses will not be propagated to this callback
	my $param = $self->{param};
	if ( $code =~m{^1\d\d} ) {
	    # preliminary response, ignore
	    DEBUG(10,"got preliminary response of %s|%s to INVITE",$code,$packet->msg );
	    invoke_callback( $param->{cb_preliminary},$self,$code,$packet );
	    return;
	} elsif ( $code !~m{^2\d\d} ) {
	    DEBUG(10,"got response of %s|%s to INVITE",$code,$packet->msg );
	    invoke_callback( $param->{cb_final},'FAIL',$self,code => $code,
		packet => $packet );
	    return;
	}

	# cleanup RTP from last call
	$self->rtp_cleanup;

	$self->_setup_peer_rtp_socks( $packet ) || do {
	    invoke_callback( $param->{cb_final},'FAIL',$self );
	    return;
	};
	if ( $param->{sdp_on_ack} && $ack ) {
	    $self->_setup_local_rtp_socks;
	    $ack->set_body( $param->{sdp} );
	}
	invoke_callback( $param->{cb_final},'OK',$self, packet => $packet );
	invoke_callback( $param->{init_media},$self,$param );
    };


    my $stopvar = 0;
    $param->{cb_final} ||= \$stopvar;
    $cb = [ $cb,$self ];
    weaken( $cb->[1] );
    $self->{ctx} = $self->{endpoint}->invite(
	$ctx, $cb, $sdp,
	$param->{sip_header} ? %{ $param->{sip_header} } : ()
    );

    if ( $param->{cb_final} == \$stopvar ) {

	# This callback will be called on timeout or response to cancel which
	# got send after ring_time was over
	my $noanswercb;
	if ( $param->{ring_time} ) {
	    $noanswercb = sub {
		my Net::SIP::Simple::Call $self = shift || return;
		my ($endpoint,$ctx,$errno,$code,$packet,$leg,$from,$ack) = @_;

		$stopvar = 'NOANSWER' ;
		my $param = $self->{param};
		invoke_callback( $param->{cb_noanswer}, 'NOANSWER',$self,
		    errno => $errno,code => $code,packet => $packet );

		if ( $code =~ m{^2\d\d} ) {
		    DEBUG(10,"got response of %s|%s to CANCEL",$code,$packet->msg );
		    invoke_callback( $param->{cb_final},'NOANSWER',$self,code => $code,
			packet => $packet );
		}
	    };
	    $noanswercb = [ $noanswercb,$self ];
	    weaken( $noanswercb->[1] );

	    # wait until final response
	    $self->loop( $param->{ring_time}, \$stopvar );

	    unless ($stopvar) { # timed out
		$self->{endpoint}->cancel_invite( $self->{ctx},undef, $noanswercb );
		$self->loop( \$stopvar );
	    }
	} else {
	    # wait until final response
	    $self->loop( \$stopvar );
	}

	$param->{cb_final} = undef;
    }
    return $self->{ctx};
}


###########################################################################
# cancel call
# Args: ($self,%args)
#   %args:
#     cb_final: callback when CANCEL was delivered. If not given send_cancel
#        callback on Call object will be used
# Returns: true if call could be canceled
# Comment: cb_final gets triggered if the reply for the CANCEL is received
# or waiting for the reply timed out
###########################################################################
sub cancel {
    my Net::SIP::Simple::Call $self = shift;
    my %args = @_;

    my $cb = delete $args{cb_final};
    %args = ( %{ $self->{param} }, %args );
    $cb ||= $args{send_cancel};

    my $cancel_cb = [
	sub {
	    my Net::SIP::Simple::Call $self = shift || return;
	    my ($cb,$args,$endpoint,$ctx,$error,$code) = @_;
	    # we don't care about the cause of this callback
	    # it might be a successful or failed reply packet or no reply
	    # packet at all (timeout) - the call is considered closed
	    # in any case except for 1xx responses
	    if ( $code && $code =~m{^1\d\d} ) {
		DEBUG( 10,"got prelimary response for CANCEL" );
		return;
	    }
	    invoke_callback( $cb,$args );
	},
	$self,$cb,\%args
    ];
    weaken( $cancel_cb->[1] );

    return $self->{endpoint}->cancel_invite( $self->{ctx}, undef, $cancel_cb );
}

###########################################################################
# end call
# Args: ($self,%args)
#   %args:
#     cb_final: callback when BYE was delivered. If not given send_bye
#        callback on Call object will be used
# Returns: NONE
# Comment: cb_final gets triggered if the reply for the BYE is received
# or waiting for the reply timed out
###########################################################################
sub bye {
    my Net::SIP::Simple::Call $self = shift;
    my %args = @_;

    my $cb = delete $args{cb_final};
    %args = ( %{ $self->{param} }, %args );
    $cb ||= $args{send_bye};

    my $bye_cb = [
	sub {
	    my Net::SIP::Simple::Call $self = shift || return;
	    my ($cb,$args,$endpoint,$ctx,$error,$code) = @_;
	    # we don't care about the cause of this callback
	    # it might be a successful or failed reply packet or no reply
	    # packet at all (timeout) - the call is considered closed
	    # in any case except for 1xx responses
	    # FIXME: should we check for 302 moved etc?
	    if ( $code && $code =~m{^1\d\d} ) {
		DEBUG( 10,"got prelimary response for BYE" );
		return;
	    }
	    invoke_callback( $cb,$args );
	    $self->cleanup;
	},
	$self,$cb,\%args
    ];
    weaken( $bye_cb->[1] );

    $self->{endpoint}->new_request( 'BYE',$self->{ctx}, $bye_cb );
}

###########################################################################
# request
# Args: ($self,$method,$body,%args)
#   $method: method name
#   $body:   optional body
#   %args:
#     cb_final: callback when response got received
#     all other args will be used to create request (mostly as header
#       for the request, see Net::SIP::Endpoint::new_request)
# Returns: NONE
###########################################################################
sub request {
    my Net::SIP::Simple::Call $self = shift;
    my ($method,$body,%args) = @_;

    my $cb = delete $args{cb_final};
    my %cbargs = ( %{ $self->{param} }, %args );

    my $rqcb = [
	sub {
	    my Net::SIP::Simple::Call $self = shift || return;
	    my ($cb,$args,$endpoint,$ctx,$error,$code,$pkt) = @_;
	    if ( $code && $code =~m{^1\d\d} ) {
		DEBUG( 10,"got prelimary response for request $method" );
		return;
	    }
	    invoke_callback( $cb,
		$error ? 'FAIL':'OK',
		$self,
		{ code => $code, packet => $pkt}
	    );
	},
	$self,$cb,\%cbargs
    ];
    weaken( $rqcb->[1] );

    $self->{endpoint}->new_request( $method,$self->{ctx},$rqcb,$body,%args );
}

###########################################################################
# send DTMF (dial tone) events
# Args: ($self,$events,%args)
#  $events: string of characters from dial pad, any other character will
#    cause pause
#  %args:
#    duration: length of dial tone in milliseconds, default 100
#    cb_final: callback called with (status,errormsg) when done
#       status can be OK|FAIL. If not given will wait until all
#       events are sent
#    methods: methods it should try for DTMF in this order
#       default is 'rfc2833,audio'. If none of the specified
#       methods is supported by peer it will croak
# Returns: NONE
# Comments: works only with media handling from Net::SIP::Simple::RTP
###########################################################################
sub dtmf {
    my ($self,$events,%args) = @_;
    my $duration = $args{duration} || 100;
    my @methods = split(m{[\s,]+}, lc($args{methods}||'rfc2833,audio'));

    my %payload_type;
    while ( ! %payload_type
	and my $m = shift(@methods)) {
	my $type;
	if ( $m eq 'rfc2833' ) {
	    $type = $self->{param}{sdp_peer}
		&& $self->{param}{sdp_peer}->name2int('telephone-event/8000','audio');
	} elsif ( $m eq 'audio' ) {
	    my $sdp_peer = $self->{param}{sdp_peer};
	    if ($sdp_peer) {
		$type = $sdp_peer->name2int('PCMU/8000','audio') // $sdp_peer->name2int('PCMA/8000','audio');
		if (!defined $type) {
			my $media = $sdp_peer->get_media();
			my ($fmt) = map { ($_->{media} eq 'audio') ? $_->{fmt} : () } @$media;
			($type) = grep { $_ == 0 || $_ == 8 } @$fmt; # Only PCMU=0 and PCMA=8 are supported
		}
	    }
	    $type //= 0; # default id for PCMU/8000
	} else {
	    croak("unknown method $m in methods:$args{methods}");
	}
	%payload_type = ( $m."_type" => $type ) if defined $type;
    }
    %payload_type or croak("no usable DTMF method found");

    my $arr = $self->{param}{dtmf_events};
    my $lastev;
    for( split('',$events)) {
	if ( m{[\dA-D*#]} ) {
	    if (defined $lastev) {
		# force some silence to distinguish DTMF
		push @$arr, {
		    duration => ($lastev eq $_) ? 100 : 50,
		    %payload_type
		}
	    }
	    push @$arr, {
		event => $_,
		duration => $duration,
		%payload_type,
	    };
	    $lastev = $_;
	} else {
	    # pause
	    push @$arr, { duration => $duration, %payload_type };
	    $lastev = undef;
	}
    }
    if ( my $cb_final = $args{cb_final} ) {
	push @$arr, { cb_final => $cb_final }
    } else {
	my $stopvar;
	push @$arr, { cb_final => \$stopvar };
	$self->loop(\$stopvar);
    }
}

###########################################################################
# handle new packets within existing call
# Args: ($self,$endpoint,$ctx,$error,$code,$packet,$leg,$from)
#   $endpoint: the endpoint
#   $ctx: context for call
#   $error: errno if error occurred
#   $code: code from responses
#   $packet: incoming packet
#   $leg: leg where packet came in
#   $from: addr from where packet came
# Returns: NONE
###########################################################################
sub receive {
    my ($self,$endpoint,$ctx,$error,$code,$packet,$leg,$from) = @_;
    if ( ! $packet ) {
	$self->error( "error occurred: $error" );
    } elsif ( $packet->is_request ) {
	my $method = $packet->method;
	my $param = $self->{param};

	if ( $method eq 'BYE' || $method eq 'CANCEL' ) {
	    # tear down
	    $self->cleanup;
	    invoke_callback( $param->{recv_bye},$param);
	    # everything else already handled by Net::SIP::Endpoint::Context

	} elsif ( $method eq 'ACK' || $method eq 'INVITE' ) {

	    # can transport sdp data
	    if ( my $sdp_peer = eval { $packet->sdp_body } ) {
		DEBUG( 50,"got sdp data from peer: ".$sdp_peer->as_string );
		$self->_setup_peer_rtp_socks( $sdp_peer );
	    } elsif ($@) {
		# mailformed SDP?
		DEBUG(10,"SDP parsing failed, ignoring packet: $@");
		return;
	    }

	    if ( $method eq 'INVITE' ) {

		if ( $param->{clear_sdp} ) {
		    # clear SDP keys so that a new SDP session will be created
		    @{ $param }{qw( sdp _sdp_saved sdp_peer media_ssocks media_lsocks )} = ()
		}

		$param->{leg} ||= $leg;
		$self->_setup_local_rtp_socks;
		my $resp = invoke_callback($param->{cb_invite},$self,$packet);

		# by default send 200 OK with sdp body
		$resp = $packet->create_response('200','OK',{},$param->{sdp})
		    if ! $resp || ! UNIVERSAL::isa($resp,'Net::SIP::Packet');
		DEBUG( 100,'created response '.$resp->as_string );
		$self->{endpoint}->new_response( $ctx,$resp,$leg,$from );

	    } elsif ( $method eq 'ACK' ) {
		$self->rtp_cleanup; # close last RTP session
		invoke_callback($param->{cb_established},'OK',$self);
		invoke_callback($param->{init_media},$self,$param);
	    }

	} elsif ( $method eq 'OPTIONS' ) {

	    my $response = $packet->create_response( '200','OK',$self->{options} );
	    $self->{endpoint}->new_response( $ctx,$response,$leg,$from );

	} elsif ( $method eq 'NOTIFY' ) {

	    my $response = $packet->create_response( '200','OK' );
	    $self->{endpoint}->new_response( $ctx,$response,$leg,$from );
	    invoke_callback($param->{cb_notify},$self,$packet);
	}

    } else {
	# don't expect any responses.
	# Response to BYE is handled by Net::SIP::Endpoint::Context
	# other responses from the peer I don't expect
	DEBUG( 100,"got response. WHY? DROP." );
    }
}

###########################################################################
# setup $self->{param} for remote socks from remote SDP data
# Args: ($self,$data)
#   $data: packet containing sdp_body (Net::SIP::Packet) or
#     SDP data (Net::SIP::SDP)
# Returns: NONE
###########################################################################
sub _setup_peer_rtp_socks {
    my Net::SIP::Simple::Call $self = shift;
    my $param = $self->{param};
    my $data = shift || $param->{sdp_peer};

    my $sdp_peer;
    if ( UNIVERSAL::isa( $data, 'Net::SIP::Packet' )) {
	$sdp_peer = $data->sdp_body or do {
	    $self->error( "No SDP body in packet" );
	    return;
	};
    } else {
	$sdp_peer = $data
    }

    $param->{sdp_peer} = $sdp_peer;

    my @media = $sdp_peer->get_media;
    my $ls = $param->{media_lsocks};
    if ( $ls && @$ls && @media != @$ls ) {
	$self->error( "Unexpected number of media entries in SDP from peer" );
	return;
    }

    my $raddr = $param->{media_raddr} = [];
    my @media_dtmfxtract;
    for( my $i=0;$i<@media;$i++) {
	my $m = $media[$i];
	my $range = $m->{range} || 1;
	my $paddr = ip_canonical($m->{addr});
	if (!$m->{port} or  $paddr eq '0.0.0.0' or  $paddr eq '::') {
	    # on-hold for this media
	    push @$raddr, undef;
	} else {
	    my @socks = map { ip_parts2sockaddr($m->{addr},$m->{port}+$_) }
		(0..$range-1);
	    push @$raddr, @socks == 1 ? $socks[0] : \@socks;

	    if ( $m->{media} eq 'audio' and $param->{cb_dtmf} ) {
		my $fmt = $param->{rtp_param}->[0];
		$fmt = 0 if $fmt != 0 and $fmt != 8; # Only PCMU=0 and PCMA=8 are supported, default is PCMU
		my $fmt_name = ($fmt == 8) ? 'PCMA' : 'PCMU';
		my %mt = (audio => "$fmt_name/8000", rfc2833 => "telephone-event/8000");
		my $mt = $param->{dtmf_methods} || 'audio,rfc2833';
		my (%rmap,%pargs);
		for($mt =~m{([\w+\-]+)}g) {
		    my $type = $mt{$_} or die "invalid dtmf_method: $_";
		    $rmap{$type} = $_.'_type';
		    %pargs = (audio_type => $fmt) if $_ eq 'audio';
		}
		for my $l (@{$m->{lines}}) {
		    $l->[0] eq 'a' or next;
		    my ($type,$name) = $l->[1] =~m{^rtpmap:(\d+)\s+(\S+)} or next;
		    my $pname = $rmap{$name} or next;
		    $pargs{$pname} = $type;
		}
		$media_dtmfxtract[$i] = dtmf_extractor(%pargs) if %pargs;
	    }
	}
    }

    $param->{media_dtmfxtract} = @media_dtmfxtract ? \@media_dtmfxtract :undef;

    return 1;
}

###########################################################################
# setup local RTP socks
# Args: $self
# Returns: NONE
# Comments: set sdp,media_lsocks,media_ssocks in self->{param}
###########################################################################
sub _setup_local_rtp_socks {
    my Net::SIP::Simple::Call $self = shift;
    my $param = $self->{param};

    my $call_on_hold = $param->{call_on_hold};
    $param->{call_on_hold} = 0; # one-shot

    my $sdp = $param->{_sdp_saved} || $param->{sdp};
    if ( $sdp && !UNIVERSAL::isa( $sdp,'Net::SIP::SDP' )) {
	$sdp = Net::SIP::SDP->new( $sdp );
    }

    my $laddr = $param->{leg}->laddr(0);
    if ( !$sdp ) {
	# create SDP body
	my $raddr = $param->{media_rsocks};

	# if no raddr yet just assume one
	my @media;
	my $rp = $param->{rtp_param};
	if ( my $sdp_peer = $param->{sdp_peer} ) {
	    foreach my $m ( $sdp_peer->get_media ) {
		if ( $m->{proto} ne 'RTP/AVP' ) {
		    $self->error( "only RTP/AVP supported" );
		    return;
		}
		my @a;
		if ( $m->{media} eq 'audio' ) {
		    # enforce the payload type based on rtp_param
		    $m = { %$m, fmt => $rp->[0] };
		    push @a, (
			"rtpmap:$rp->[0] $rp->[3]",
			"ptime:".$rp->[2]*1000
		    ) if $rp->[3];
		    push @a, (
			"rtpmap:101 telephone-event/8000",
			"fmtp:101 0-16"
		    );
		}
		push @media, {
		    media => $m->{media},
		    proto => $m->{proto},
		    range => $m->{range},
		    fmt   => [ $m->{fmt},101 ],
		    a     => \@a,
		};
	    }
	} else {
	    my @a;
	    push @a,( "rtpmap:$rp->[0] $rp->[3]" , "ptime:".$rp->[2]*1000) if $rp->[3];
	    my $te = $rp->[3] && $rp->[0] == 101 ? 102: 101;
	    push @a, ( "rtpmap:$te telephone-event/8000","fmtp:$te 0-16" );
	    push @media, {
		proto => 'RTP/AVP',
		media => 'audio',
		fmt   => [ $rp->[0] || 0, $te ],
		a     => \@a,
	    }
	}

	my $lsocks = $param->{media_lsocks} = [];
	foreach my $m (@media) {
	    my ($port,@socks) = create_rtp_sockets( $laddr,$m->{range} )
		or die $!;
	    push @$lsocks, @socks == 1 ? $socks[0] : \@socks;
	    $m->{port} = $port;
	}

	$sdp = $param->{sdp} = Net::SIP::SDP->new(
	    { addr => $laddr },
	    @media
	);
    }

    unless ( $param->{media_lsocks} ) {
	# SDP body was provided, but sockets not
	croak( 'not supported: if you provide SDP body you need to provide sockets too' );
    }

    # asymetric_rtp, e.g. source socket of packet to peer is not the socket where RTP
    # from peer gets received
    if ( !$param->{media_ssocks} && $param->{asymetric_rtp} ) {
	my @arg = (
	    Proto => 'udp',
	    LocalAddr => ( $param->{rtp_addr} || $laddr )
	);
	my $msocks = $param->{media_ssocks} = [];
	foreach my $m (@{ $param->{media_lsocks} }) {
	    my $socks;
	    if ( UNIVERSAL::isa( $m,'ARRAY' )) {
		$socks = [];
		foreach my $sock (@$m) {
		    push @$socks, INETSOCK(@arg) || die $!;
		}
	    } else {
		$socks = INETSOCK(@arg) || die $!;
	    }
	    push @$msocks,$socks;
	}
    }

    $param->{_sdp_saved} = $sdp;
    if ( $call_on_hold ) {
	$sdp = dclone($sdp); # make changes on clone
	my @new = map { [ '0.0.0.0',$_->{port} ] } $sdp->get_media;
	$sdp->replace_media_listen( @new );
	$param->{sdp} = $sdp;
    }
}

1;
