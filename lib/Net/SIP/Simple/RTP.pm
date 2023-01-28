###########################################################################
# Net::SIP::Simple::RTP
# implements some RTP behaviors
# - media_recv_echo: receive and echo data with optional delay back
#    can save received data
# - media_send_recv: receive and optionally save data. Sends back data
#    from file with optional repeat count
###########################################################################

use strict;
use warnings;

package Net::SIP::Simple::RTP;

use Net::SIP::Util qw(invoke_callback ip_sockaddr2parts ip_parts2string);
use Socket;
use Net::SIP::Debug;
use Net::SIP::DTMF;
use Net::SIP::Dispatcher::Eventloop;

# on MSWin32 non-blocking sockets are not supported from IO::Socket
use constant CAN_NONBLOCKING => $^O ne 'MSWin32';

###########################################################################
# creates function which will initialize Media for echo back
# Args: ($writeto,$delay)
#   $delay: how much packets delay between receive and echo back (default 0)
#     if <0 no ddata will be send back (e.g. recv only)
#   $writeto: where to save received data (default: don't save)
# Returns: [ \&sub,@args ]
###########################################################################
sub media_recv_echo {
    my ($writeto,$delay) = @_;

    my $sub = sub {
	my ($delay,$writeto,$call,$args) = @_;

	my $lsocks = $args->{media_lsocks};
	my $ssocks = $args->{media_ssocks} || $lsocks;
	my $raddr  = $args->{media_raddr};
	my $mdtmf  = $args->{media_dtmfxtract};
	my $didit = 0;
	for( my $i=0;$i<@$lsocks;$i++ ) {
	    my $sock = $lsocks->[$i] || next;
	    $sock = $sock->[0] if UNIVERSAL::isa( $sock,'ARRAY' );
	    my $s_sock = $ssocks->[$i];
	    $s_sock = $s_sock->[0] if UNIVERSAL::isa( $s_sock,'ARRAY' );

	    my $addr = $raddr->[$i];
	    $addr = $addr->[0] if ref($addr);

	    my @delay_buffer;
	    my $channel = $i;
	    my $echo_back = sub {
		my ($s_sock,$remote,$delay_buffer,$delay,$writeto,$targs,$didit,$sock) = @_;
		{
		    my (undef,$mpt,undef,$tstamp,undef,undef,$payload) =
			_receive_rtp($sock,$writeto,$targs,$didit,$channel)
			or last;
		    #DEBUG( "$didit=$$didit" );
		    $$didit = 1;

		    last if ! $s_sock || ! $remote; # call on hold ?

		    my $seq = ++($targs->{wseq} //= int(rand(2**16)));

		    # source ID for RTP stream, uniq for each stream
		    my $ssrc = $targs->{wssrc} //= int(rand(2**32));

		    my @pkt = _generate_dtmf($targs,$seq,$tstamp,$ssrc);
		    if (@pkt && $pkt[0] ne '') {
			DEBUG( 100,"send DTMF to RTP");
			send( $s_sock,$_,0,$remote ) for(@pkt);
			return; # send DTMF *instead* of echo data
		    }

		    last if $delay<0;
		    my $buf = pack('CCnNN',0b10000000,$mpt,$seq,$tstamp,$ssrc).$payload;
		    push @$delay_buffer, $buf;
		    while ( @$delay_buffer > $delay ) {
			send( $s_sock,shift(@$delay_buffer),0,$remote );
		    }
		    CAN_NONBLOCKING && redo; # try recv again
		}
	    };

	    $call->{loop}->addFD($sock, EV_READ,
		[ $echo_back,$s_sock,$addr,\@delay_buffer,$delay || 0,$writeto,{
		    dtmf_gen => $args->{dtmf_events},
		    dtmf_xtract => $mdtmf && $mdtmf->[$i] && $args->{cb_dtmf}
			&& [ $mdtmf->[$i], $args->{cb_dtmf} ],
		},\$didit ],
		'rtp_echo_back' );
	    my $reset_to_blocking = CAN_NONBLOCKING && $s_sock->blocking(0);
	    push @{ $call->{ rtp_cleanup }}, [ sub {
		my ($call,$sock,$rb) = @_;
		DEBUG( 100,"rtp_cleanup: remove socket %d",fileno($sock));
		$call->{loop}->delFD( $sock );
		$sock->blocking(1) if $rb;
	    }, $call,$sock,$reset_to_blocking ];
	}

	# on RTP inactivity for at least 10 seconds close connection
	my $timer = $call->{dispatcher}->add_timer( 10,
	    [ sub {
		my ($call,$didit,$timer) = @_;
		if ( $$didit ) {
		    $$didit = 0;
		} else {
		    DEBUG(10, "closing call because if inactivity" );
		    $call->bye;
		    $timer->cancel;
		}
	    }, $call,\$didit ],
	    10,
	    'rtp_inactivity',
	);
	push @{ $call->{ rtp_cleanup }}, [
	    sub {
		shift->cancel;
		DEBUG( 100,"cancel RTP timer" );
	    },
	    $timer
	];
    };

    return [ $sub,$delay,$writeto ];
}

###########################################################################
# creates function which will initialize Media for saving received data
# into file and sending data from another file
# Args: ($readfrom;$repeat,$writeto)
#   $readfrom: where to read data for sending from (filename or callback
#     which returns payload)
#   $repeat: if <= 0 the data in $readfrom will be send again and again
#     if >0 the data in $readfrom will be send $repeat times
#   $writeto: where to save received data (undef == don't save), either
#     filename or callback which gets packet as argument
# Returns: [ \&sub,@args ]
###########################################################################
sub media_send_recv {
    my ($readfrom,$repeat,$writeto) = @_;

    my $sub = sub {
	my ($writeto,$readfrom,$repeat,$call,$args) = @_;

	my $lsocks = $args->{media_lsocks};
	my $ssocks = $args->{media_ssocks} || $lsocks;
	my $raddr  = $args->{media_raddr};
	my $mdtmf  = $args->{media_dtmfxtract};
	my $didit = 0;
	for( my $i=0;$i<@$lsocks;$i++ ) {
	    my $channel = $i;
	    my $sock = $lsocks->[$i];
	    my ($timer,$reset_to_blocking);

	    # recv once I get an event on RTP socket
	    if ($sock) {
		$sock = $sock->[0] if UNIVERSAL::isa( $sock,'ARRAY' );
		my $receive = sub {
		    my ($writeto,$targs,$didit,$sock) = @_;
		    while (1) {
			my $buf = _receive_rtp($sock,$writeto,$targs,$didit,$channel);
			defined($buf) or return;
			CAN_NONBLOCKING or return;
		    }
		};
		$call->{loop}->addFD($sock, EV_READ,
		    [
			$receive,
			$writeto,
			{
			    dtmf_gen => $args->{dtmf_events},
			    dtmf_xtract => $mdtmf && $mdtmf->[$i] && $args->{cb_dtmf}
				&& [ $mdtmf->[$i], $args->{cb_dtmf} ],
			},
			\$didit
		    ],
		    'rtp_receive'
		);
		$reset_to_blocking = CAN_NONBLOCKING && $sock->blocking(0);
	    }

	    # sending need to be done with a timer
	    # ! $addr == call on hold
	    my $addr = $raddr->[$i];
	    $addr = $addr->[0] if ref($addr);
	    if ($addr and my $s_sock = $ssocks->[$i]) {
		$s_sock = $s_sock->[0] if UNIVERSAL::isa( $s_sock,'ARRAY' );
		my $cb_done = $args->{cb_rtp_done} || sub { shift->bye };
		$timer = $call->{dispatcher}->add_timer(
		    0, # start immediately
		    [ \&_send_rtp,$s_sock,$call->{loop},$addr,$readfrom,$channel, {
			repeat => $repeat || 1,
			cb_done => [ sub { invoke_callback(@_) }, $cb_done, $call ],
			rtp_param => $args->{rtp_param},
			dtmf_gen => $args->{dtmf_events},
			dtmf_xtract => $mdtmf && $mdtmf->[$i] && $args->{cb_dtmf}
			    && [ $mdtmf->[$i], $args->{cb_dtmf} ],
			}],
		    $args->{rtp_param}[2], # repeat timer
		    'rtpsend',
		);
	    }

	    push @{ $call->{rtp_cleanup}}, [ sub {
		my ($call,$sock,$timer,$rb) = @_;
		if ($sock) {
		    $call->{loop}->delFD($sock);
		    $sock->blocking(1) if $rb;
		}
		$timer->cancel() if $timer;
	    }, $call,$sock,$timer,$reset_to_blocking ];
	}

	# on RTP inactivity for at least 10 seconds close connection
	my $timer = $call->{dispatcher}->add_timer( 10,
	    [ sub {
		my ($call,$args,$didit,$timer) = @_;
		if ( $$didit ) {
		    $$didit = 0;
		} else {
		    DEBUG( 10,"closing call because if inactivity" );
		    $call->bye;
		    $timer->cancel;
		}
	    }, $call,$args,\$didit ],
	    10,
	    'rtp_inactivity',
	);
	push @{ $call->{ rtp_cleanup }}, [ sub { shift->cancel }, $timer ];
    };

    return [ $sub,$writeto,$readfrom,$repeat ];
}

###########################################################################
# Helper to receive RTP and optionally save it to file
# Args: ($sock,$writeto,$targs,$didit,$channel)
#   $sock: RTP socket
#   $writeto: filename for saving or callback which gets packet as argument
#   $targs: \%hash to hold state info between calls of this function
#   $didit: reference to scalar which gets set to TRUE on each received packet
#     and which gets set to FALSE from a timer, thus detecting inactivity
#   $channel: index of RTP channel
# Return: $packet | $packet,$mpt,$seq,$tstamp,$ssrc,$csrc,$payload
#   $packet: received RTP packet (including header)
#   $mpt,$seq,$tstamp,$ssrc,$csrc,$payload - parsed details from RTP header
###########################################################################
sub _receive_rtp {
    my ($sock,$writeto,$targs,$didit,$channel) = @_;

    my $from = recv( $sock,my $buf,2**16,0 );
    return if ! $from || !defined($buf) || $buf eq '';
    DEBUG( 50,"received %d bytes from RTP", length($buf));

    if(0) {
	DEBUG( "got data on socket %d %s from %s",fileno($sock),
	    ip_sockaddr2string(getsockname($sock)),
	    ip_sockaddr2string($from));
    }

    $$didit = 1;
    my $packet = $buf;

    my ($vpxcc,$mpt,$seq,$tstamp,$ssrc) = unpack( 'CCnNN',substr( $buf,0,12,'' ));
    my $version = ($vpxcc & 0xc0) >> 6;
    if ( $version != 2 ) {
	DEBUG( 100,"RTP version $version" );
	return
    }
    # skip csrc headers
    my $cc = $vpxcc & 0x0f;
    my $csrc = $cc && substr( $buf,0,4*$cc,'' );

    # skip extension header
    my $xh = $vpxcc & 0x10 ? (unpack( 'nn', substr( $buf,0,4,'' )))[1] : 0;
    substr( $buf,0,4*$xh,'' ) if $xh;

    # ignore padding
    my $padding = $vpxcc & 0x20 ? unpack( 'C', substr($buf,-1,1)) : 0;
    my $payload = $padding ? substr( $buf,0,length($buf)-$padding ): $buf;

    DEBUG( 100,"ch=%d payload=%d/%d pt=%d xh=%d padding=%d cc=%d",
	$channel, $seq, length($payload), $mpt & 0x7f, $xh, $padding, $cc);
    if ( $targs->{ssrc} && $targs->{ssrc} != $ssrc ) {
	# RTP stream has changed, reset rseq
	delete $targs->{rseq};
    }
    if ( defined $targs->{rseq} && $seq<= $targs->{rseq}
	&& $targs->{rseq} - $seq < 60000 ) {
	DEBUG( 10,"seq=$seq last=$targs->{rseq} - dropped" );
	return;
    }
    $targs->{rseq} = $seq;

    if ( ref($writeto)) {
	# callback
	invoke_callback($writeto,$payload,$seq,$tstamp,$channel,$mpt & 0x7f);
    } elsif ( $writeto ) {
	# save into file
	my $fd = $targs->{fdr};
	if ( !$fd ) {
	    open( $fd,'>',$writeto ) || die $!;
	    $targs->{fdr} = $fd
	}
	syswrite($fd,$payload);
    }

    if ( my $xt = $targs->{dtmf_xtract} ) {
	my ($sub,$cb) = @$xt;
	if ( my ($event,$duration) = $sub->($packet)) {
	    DEBUG(40,"received dtmf <$event,$duration>");
	    $cb->($event,$duration);
	}
    }

    return wantarray ? ( $packet,$mpt,$seq,$tstamp,$ssrc,$csrc,$payload ): $packet;
}

###########################################################################
# Helper to read  RTP data from file (PCMU 8000) and send them through
# the RTP socket
# Args: ($sock,$loop,$addr,$readfrom,$targs,$timer)
#   $sock: RTP socket
#   $loop: event loop (used for looptime for timestamp)
#   $addr: where to send data
#   $readfrom: filename for reading or callback which will return payload
#   $channel: index of RTP channel
#   $targs: \%hash to hold state info between calls of this function
#     especially 'repeat' holds the number of times this data has to be
#     send (<=0 means forever) and 'cb_done' holds a [\&sub,@arg] callback
#     to end the call after sending all data
#     'repeat' makes only sense if $readfrom is filename
#   $timer: timer which gets canceled once all data are send
# Return: NONE
###########################################################################
sub _send_rtp {
    my ($sock,$loop,$addr,$readfrom,$channel,$targs,$timer) = @_;

    my $seq = ++($targs->{wseq} //= int(rand(2**16)));

    # source ID for RTP stream, uniq for each stream
    my $ssrc = $targs->{wssrc} //= int(rand(2**32));

    # 32 bit timestamp based on seq and packet size
    my $timestamp = ( $targs->{rtp_param}[1] * $seq ) % 2**32;

    my @pkt = _generate_dtmf($targs,$seq,$timestamp,$ssrc);
    if (@pkt && $pkt[0] ne '') {
	DEBUG( 100,"send DTMF to RTP");
	send( $sock,$_,0,$addr ) for(@pkt);
	return;
    }

    my $buf;
    my $rtp_event;
    my $payload_type;

    if ( ref($readfrom) ) {
	# payload by callback
	$buf = invoke_callback($readfrom,$seq,$channel);
	if ( !$buf ) {
	    DEBUG( 50, "no more data from callback" );
	    $timer && $timer->cancel;
	    invoke_callback( $targs->{cb_done} );
	    return;
	}
	($buf,$payload_type,$rtp_event,$timestamp) = @$buf if ref($buf);
    } else {
	# read from file
	for(my $tries = 0; $tries<2;$tries++ ) {
	    my $fd = $targs->{fd};
	    if ( !$fd ) {
		$targs->{repeat} = -1 if $targs->{repeat} < 0;
		if ( $targs->{repeat} == 0 ) {
		    # no more sending
		    DEBUG( 50, "no more data from file" );
		    $timer && $timer->cancel;
		    invoke_callback( $targs->{cb_done} );
		    return;
		}

		open( $fd,'<',$readfrom ) || die $!;
		$targs->{fd} = $fd;
	    }
	    my $size = $targs->{rtp_param}[1]; # 160 for PCMU/8000
	    last if read( $fd,$buf,$size ) == $size;
	    # try to reopen file
	    close($fd);
	    $targs->{fd} = undef;
	    $targs->{repeat}--;
	}
    }

    die $! if ! defined $buf or $buf eq '';
    if (0) {
	DEBUG(50, "%s -> %s seq=%d ts=%x",
	    ip_sockaddr2string(getsockname($sock)),
	    ip_sockaddr2string($addr),
	    $seq, $timestamp
	);
    }

    # add RTP header
    $rtp_event = 0 if ! defined $rtp_event;
    $payload_type = $targs->{rtp_param}[0]||0   # 0 == PMCU 8000
	if ! defined $payload_type;

    my $header = pack('CCnNN',
	0b10000000, # Version 2
	$payload_type | ( $rtp_event << 7 ) ,
	$seq, # sequence
	$timestamp,
	$ssrc,
    );
    DEBUG( 100,"send %d bytes to RTP", length($buf));
    send( $sock,$header.$buf,0,$addr );
}

###########################################################################
# Helper to send DTMF
# Args: ($targs,$seq,$timestamp,$srcid)
#  $targs: hash which is shared with _send_rtp and other callbacks, contains
#    dtmf array with events
#  $seq,$timestamp,$srcid: parameter for RTP packet
# Returns: @pkt
#  ():            no DTMF events to handle
#  $pkt[0] eq '': DTMF in process, but no data
#  @pkt:          RTP packets to send
###########################################################################
sub _generate_dtmf {
    my ($targs,$seq,$timestamp,$srcid) = @_;
    my $dtmfs = $targs->{dtmf_gen};
    $dtmfs and @$dtmfs or return;

    while ( @$dtmfs ) {
	my $dtmf = $dtmfs->[0];
	if ( my $duration = $dtmf->{duration} ) {
	    DEBUG(40,"generate dtmf ".(
		$dtmf->{sub} ? '<sub>' :
		defined $dtmf->{event} ? "<$dtmf->{event},$duration>"  :
		"<pause,$duration>"
	    ));
	    my $cb = $dtmf->{sub}
		||= dtmf_generator($dtmf->{event},$duration,%$dtmf);
	    my @pkt = $cb->($seq,$timestamp,$srcid);
	    return @pkt if @pkt;
	}
	shift(@$dtmfs);
	if ( my $cb = $dtmf->{cb_final} ) {
	    invoke_callback($cb,'OK');
	}
    }
    return;
}

1;
