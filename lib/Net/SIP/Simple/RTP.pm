###########################################################################
# Net::SIP::Simple::RTP
# implements some RTP behaviors
# - media_recv_echo: receive and echo data with optional delay back
#    can save received data
# - media_send_recv: receive and optionally save data. Sends back data
#    from file with optional repeat count
# only PCMU 8000 data will be handled at the moment
###########################################################################

use strict;
use warnings;

package Net::SIP::Simple::RTP;

use Net::SIP::Util qw(invoke_callback);
use Socket;
use Net::SIP::Debug;

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
			my $addr = $raddr->[$i] || last;
			$addr = $addr->[0] if ref($addr);
			my @delay_buffer;

			my $echo_back = sub {
				my ($s_sock,$remote,$delay_buffer,$delay,$writeto,$targs,$didit,$sock) = @_;
				my $buf = _receive_rtp( $sock,$writeto,$targs,$didit );
				#DEBUG( "$didit=$$didit" );
				$$didit = 1;
				return if $delay<0;
				push @$delay_buffer, $buf;
				while ( @$delay_buffer > $delay ) {
					send( $s_sock,shift(@$delay_buffer),0,$remote );
				}
			};

			$call->{loop}->addFD( $sock, 
				[ $echo_back,$s_sock,$addr,\@delay_buffer,$delay || 0,$writeto,{},\$didit ] );
			push @{ $call->{ rtp_cleanup }}, [ sub {
				my ($call,$sock) = @_;
				$call->{loop}->delFD( $sock );
			}, $call,$sock ];
		}

		# on RTP inactivity for at least 10 seconds close connection
		my $timer = $call->{dispatcher}->add_timer( 10,
			[ sub {
				my ($call,$didit,$timer) = @_;
				DEBUG( "$didit=$$didit" );
				if ( $$didit ) {
					$$didit = 0;
				} else {
					DEBUG( "closing call because if inactivity" );
					$call->bye;
					$timer->cancel;
				}
			}, $call,\$didit ],
			10
		);
		push @{ $call->{ rtp_cleanup }}, [ sub { shift->cancel }, $timer ];
	};

	return [ $sub,$delay,$writeto ];
}

###########################################################################
# creates function which will initialize Media for saving received data
# into file and sending data from another file
# Args: ($readfrom;$repeat,$writeto)
#   $readfrom: where to read data for sending from
#   $repeat: if <= 0 the data in $readfrom will be send again and again
#     if >0 the data in $readfrom will be send $repeat times
#   $writeto: where to save received data (undef == don't save)
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
			my $addr = $raddr->[$i] || last;
			$addr = $addr->[0] if ref($addr);

			# recv once I get an event on RTP socket
			my $receive = sub { my $sock = pop; _receive_rtp( $sock,@_ ); };
			$call->{loop}->addFD( $sock, [ $receive,$writeto,{},\$didit ] );

			# sending need to be done with a timer
			my $timer = $call->{dispatcher}->add_timer( 
				0, # start immediatly
				[ \&_send_rtp,$s_sock,$addr,$readfrom, { 
					repeat => $repeat || 1, 
					cb_done => [ 
						sub { invoke_callback(@_) },
						$args->{cb_rtp_done} || sub { shift->bye }, 
						$call 
					] 
				}],
				160/8000, # 8000 bytes per second, 160 bytes per sample
			);

			DEBUG( "$call $sock $timer" );
			push @{ $call->{ rtp_cleanup }}, [ sub {
				my ($call,$sock,$timer) = @_;
				$call->{loop}->delFD( $sock );
				$timer->cancel();
			}, $call,$sock,$timer ];
		}

		# on RTP inactivity for at least 10 seconds close connection
		my $timer = $call->{dispatcher}->add_timer( 10,
			[ sub {
				my ($call,$args,$timer) = @_;
				if ( $args->{didit} ) {
					$args->{didit} = 0;
				} else {
					DEBUG( "closing call because if inactivity" );
					$call->bye;
					$timer->cancel;
				}
			}, $call,$args ],
			10
		);
		push @{ $call->{ rtp_cleanup }}, [ sub { shift->cancel }, $timer ];
	};

	return [ $sub,$writeto,$readfrom,$repeat ];
}

###########################################################################
# Helper to receive RTP and optionally save it to file
# Args: ($sock,$writeto,$targs)
#   $sock: RTP socket
#   $writeto: filename for saving
#   $targs: \%hash to hold state info between calls of this function
# Return: $packet
#   $packet: received RTP packet (including header)
###########################################################################
sub _receive_rtp {
	my ($sock,$writeto,$targs,$didit) = @_;

	recv( $sock,my $buf,2**16,0 );
	DEBUG( "received %d bytes from RTP", length($buf));
	$buf || return;

	$$didit = 1;
	my $packet = $buf;

	my ($vpxcc,$mpt,$seq,$tstamp,$ssrc) = unpack( 'CCnNN',substr( $buf,0,12,'' ));
	my $version = ($vpxcc & 0xc0) >> 6;
	if ( $version != 2 ) {
		DEBUG( "RTP version $version" );
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

	DEBUG( "payload=$seq/%d xh=%d padding=%d cc=%d", length($payload),$xh,$padding,$cc );
	if ( $targs->{rseq} && $seq<= $targs->{rseq} ) {
		DEBUG( "seq=$seq last=$targs->{rseq} - dropped" );
		return;
	}
	$targs->{rseq} = $seq;

	# save into file
	if ( $writeto ) {
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
# Args: ($sock,$addr,$readfrom,$targs)
#   $sock: RTP socket
#   $addr: where to send data
#   $readfrom: filename for reading
#   $targs: \%hash to hold state info between calls of this function
#     especially 'repeat' holds the number of times this data has to be
#     send (<=0 means forever) and 'cb_done' holds a [\&sub,@arg] callback
#     to end the call after sending all data
# Return: NONE
###########################################################################
use Time::HiRes 'gettimeofday';
sub _send_rtp {
	my ($sock,$addr,$readfrom,$targs) = @_;

	{
		my ($fp,$fa) = unpack_sockaddr_in( getsockname($sock) );
		$fa = inet_ntoa($fa);
		my ($tp,$ta) = unpack_sockaddr_in( $addr );
		$ta = inet_ntoa($ta);
		DEBUG( "send from $fa:$fp to $ta:$tp" );
	}

    # read from file
    my $buf;
    for(my $tries = 0; $tries<2;$tries++ ) {
        $targs->{wseq} ||= int( rand( 2**16 ));
        my $fd = $targs->{fd};
        if ( !$fd ) {
			$targs->{repeat} = -1 if $targs->{repeat} < 0;
			if ( $targs->{repeat} == 0 ) {
				# no more sending
				invoke_callback( $targs->{cb_done} );
				return;
			}

            open( $fd,'<',$readfrom ) || die $!;
            $targs->{fd} = $fd;
        }
        last if read( $fd,$buf,160 ) == 160;
        # try to reopen file
        close($fd);
        $targs->{fd} = undef;
		$targs->{repeat}--;
    }
    $buf || die $!;

    # add RTP header
    my ($high,$low) = gettimeofday();
    my $timestamp = ( $high << 16 ) | ( $low >> 16 );
    $targs->{wseq}++;
    DEBUG( "seq=$targs->{wseq} ts=%x",$timestamp );
    my $header = pack('CCnNN',
        0b10000000, # Version 2
        0b00000000, # PMCU 8000
        $targs->{wseq}, # sequence
        $timestamp,
        0x1234,    # source ID
    );
    send( $sock,$header.$buf,0,$addr ) || die $!;
}

1;
