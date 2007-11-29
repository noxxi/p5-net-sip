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

use Net::SIP::Util qw(invoke_callback);
use Socket;
use Net::SIP::Debug;


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
		my $raddr = $args->{media_raddr};
		my $didit = 0;
		for( my $i=0;1;$i++ ) {
			my $sock = $lsocks->[$i] || last;
			$sock = $sock->[0] if UNIVERSAL::isa( $sock,'ARRAY' );
			my $s_sock = $ssocks->[$i] || last;
			$s_sock = $s_sock->[0] if UNIVERSAL::isa( $s_sock,'ARRAY' );

			my $addr = $raddr->[$i];
			$addr = $addr->[0] if ref($addr);

			my @delay_buffer;
			my $echo_back = sub {
				my ($s_sock,$remote,$delay_buffer,$delay,$writeto,$targs,$didit,$sock) = @_;
				for my $dummy (1) {
					my $buf = _receive_rtp( $sock,$writeto,$targs,$didit );
					defined($buf) or last;
					#DEBUG( "$didit=$$didit" );
					$$didit = 1;
					next if $delay<0;
					next if ! $remote; # call on hold ?
					push @$delay_buffer, $buf;
					while ( @$delay_buffer > $delay ) {
						send( $s_sock,shift(@$delay_buffer),0,$remote );
					}
					CAN_NONBLOCKING && redo; # try recv again
				}
			};

			$call->{loop}->addFD( $sock,
				[ $echo_back,$s_sock,$addr,\@delay_buffer,$delay || 0,$writeto,{},\$didit ] );
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
		my $raddr = $args->{media_raddr};
		my $didit = 0;
		for( my $i=0;1;$i++ ) {
			my $sock = $lsocks->[$i] || last;
			$sock = $sock->[0] if UNIVERSAL::isa( $sock,'ARRAY' );
			my $s_sock = $ssocks->[$i] || last;
			$s_sock = $s_sock->[0] if UNIVERSAL::isa( $s_sock,'ARRAY' );

			my $addr = $raddr->[$i];
			$addr = $addr->[0] if ref($addr);

			# recv once I get an event on RTP socket
			my $receive = sub { 
				my ($writeto,$targs,$didit,$sock) = @_;
				while (1) {
					my $buf = _receive_rtp( $sock,$writeto,$targs,$didit ); 
					defined($buf) or return;
					CAN_NONBLOCKING or return;
				}
			};
			$call->{loop}->addFD( $sock, [ $receive,$writeto,{},\$didit ] );
			my $reset_to_blocking = CAN_NONBLOCKING && $sock->blocking(0);

			# sending need to be done with a timer
			# ! $addr == call on hold
			if ( $addr ) {
				my $cb_done = $args->{cb_rtp_done} || sub { shift->bye };
				my $timer = $call->{dispatcher}->add_timer(
					0, # start immediatly
					[ \&_send_rtp,$s_sock,$call->{loop},$addr,$readfrom, {
						repeat => $repeat || 1,
						cb_done => [ sub { invoke_callback(@_) }, $cb_done, $call ],
						rtp_param => $args->{rtp_param},
					}],
					$args->{rtp_param}[2], # repeat timer
					'rtpsend',
				);

				push @{ $call->{ rtp_cleanup }}, [ sub {
					my ($call,$sock,$timer,$rb) = @_;
					$call->{loop}->delFD( $sock );
					$sock->blocking(1) if $rb;
					$timer->cancel();
				}, $call,$sock,$timer,$reset_to_blocking ];
			}
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
# Args: ($sock,$writeto,$targs,$didit)
#   $sock: RTP socket
#   $writeto: filename for saving or callback which gets packet as argument
#   $targs: \%hash to hold state info between calls of this function
#   $didit: reference to scalar which gets set to TRUE on each received packet
#     and which gets set to FALSE from a timer, thus detecting inactivity
# Return: $packet
#   $packet: received RTP packet (including header)
###########################################################################
sub _receive_rtp {
	my ($sock,$writeto,$targs,$didit) = @_;

	my $from = recv( $sock,my $buf,2**16,0 );
	return if ! $from || !defined($buf) || $buf eq '';
	DEBUG( 50,"received %d bytes from RTP", length($buf));

	if(0) {
		use Socket;
		my ($lport,$laddr) = unpack_sockaddr_in( getsockname($sock));
		$laddr = inet_ntoa( $laddr ).":$lport";
		my ($pport,$paddr) = unpack_sockaddr_in( $from );
		$paddr = inet_ntoa( $paddr ).":$pport";
		DEBUG( "got data on socket %d %s from %s",fileno($sock),$laddr,$paddr );
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
	substr( $buf,0,4*$cc,'' ) if $cc;

	# skip extension header
	my $xh = $vpxcc & 0x10 ? (unpack( 'nn', substr( $buf,0,4,'' )))[1] : 0;
	substr( $buf,0,4*$xh,'' ) if $xh;

	# ignore padding
	my $padding = $vpxcc & 0x20 ? unpack( 'C', substr($buf,-1,1)) : 0;
	my $payload = $padding ? substr( $buf,0,length($buf)-$padding ): $buf;

	DEBUG( 100,"payload=$seq/%d xh=%d padding=%d cc=%d", length($payload),$xh,$padding,$cc );
	if ( $targs->{rseq} && $seq<= $targs->{rseq} ) {
		DEBUG( 10,"seq=$seq last=$targs->{rseq} - dropped" );
		return;
	}
	$targs->{rseq} = $seq;

	if ( ref($writeto)) {
		# callback
		invoke_callback( $writeto,$payload,$seq,$tstamp );
	} elsif ( $writeto ) {
		# save into file
		my $fd = $targs->{fdr};
		if ( !$fd ) {
			open( $fd,'>',$writeto ) || die $!;
			$targs->{fdr} = $fd
		}
		syswrite($fd,$payload);
	}

	return $packet;
}

###########################################################################
# Helper to read  RTP data from file (PCMU 8000) and send them through
# the RTP socket
# Args: ($sock,$loop,$addr,$readfrom,$targs,$timer)
#   $sock: RTP socket
#   $loop: event loop (used for looptime for timestamp)
#   $addr: where to send data
#   $readfrom: filename for reading or callback which will return payload
#   $targs: \%hash to hold state info between calls of this function
#     especially 'repeat' holds the number of times this data has to be
#     send (<=0 means forever) and 'cb_done' holds a [\&sub,@arg] callback
#     to end the call after sending all data
#     'repeat' makes only sense if $readfrom is filename
#   $timer: timer which gets canceled once all data are send
# Return: NONE
###########################################################################
sub _send_rtp {
	my ($sock,$loop,$addr,$readfrom,$targs,$timer) = @_;

	my ($buf);
	if ( ref($readfrom) ) {
		# payload by callback
		$buf = invoke_callback( $readfrom );
		if ( !$buf ) {
			DEBUG( 50, "no more data from callback" );
			$timer && $timer->cancel;
			invoke_callback( $targs->{cb_done} );
			return;
		}
	} else {
		# read from file
		for(my $tries = 0; $tries<2;$tries++ ) {
			$targs->{wseq} ||= int( rand( 2**16 ));
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
	$buf || die $!;

	# add RTP header
	$targs->{wseq}++;
	my $seq = $targs->{wseq};
	# 32 bit timestamp based on seq and packet size
	# FIXME: it assumes here that packet size == number of samples which is true only for 8bit
	my $timestamp = ( $targs->{rtp_param}[1] * $seq ) % 2**32; 

	if (0) {
		my ($fp,$fa) = unpack_sockaddr_in( getsockname($sock) );
		$fa = inet_ntoa($fa);
		my ($tp,$ta) = unpack_sockaddr_in( $addr );
		$ta = inet_ntoa($ta);
		DEBUG( 50, "$fa:$fp -> $ta:$tp seq=$seq ts=%x",$timestamp );
	}

	my $header = pack('CCnNN',
		0b10000000, # Version 2
		$targs->{rtp_param}[0], # 0 == PMCU 8000
		$seq, # sequence
		$timestamp,
		0x1234,    # source ID
	);
	DEBUG( 100,"send %d bytes to RTP", length($buf));
	send( $sock,$header.$buf,0,$addr ) || die $!;
}

1;
