###########################################################################
# Net::SIP::DTMF
# implements DTMF handling (audio and rfc2833)
###########################################################################

use strict;
use warnings;
package Net::SIP::DTMF;
use base 'Exporter';
our @EXPORT = qw(dtmf_generator);

use Net::SIP::Debug;
use Time::HiRes 'gettimeofday';
use Carp 'croak';

###########################################################################
# sub dtmf_generator returns a sub, which is used to generate RTP packet
# for DTMF events
# Args: ($event,$duration,%args)
#  $event: DTMF event (int 0-16)
#  $duration: duration in ms
#  %args:
#   rfc2833_type => $rtptype: if defined will generate RFC2833 RTP events
#   audio_type   => $rtptype: if defined will generate audio
#   volume       => volume for rfc2833 events (default 10)
# Returns: $sub
#  $sub: sub which returns @rtp_packets when called with
#    $sub->($seq,$timestamp,$srcid)
#    if $sub returns () the DTMF event is finished (>duration)
#    if $sub returns ('') no data are produced (pause between events)
#    usually sub will return just one packet, but for RTP event ends it
#    will return 3 to make sure that at least one gets received
#   
###########################################################################
sub dtmf_generator {
	my ($event,$duration,%pargs) = @_;
	if ( defined( my $type = $pargs{rfc2833_type} )) {
		# create RFC2833 payload
		return _dtmf_rtpevent($event,$type,$duration,%pargs);
	} elsif ( defined($type = $pargs{audio_type})) {
		# create audio payload
		return _dtmf_audio($event,$type,$duration,%pargs);
	} else {
		croak "neither rfc2833 nor audio RTP type defined"
	}
}

###########################################################################
# sub _dtmf_audio returns a sub to generate audio/silence for DTMF in 
# any duration
# Args: $event,$duration
# Returns: $sub for $event
# Comment: the sub should then be called with $sub->($seq,$timstamp,$srcid)
#  This will generate the RTP packet. 
#  If $event is no DTMF event it will return a sub which  gives silence.
#  Data returned from the subs are PCMU/8000, 160 samples per packet
###########################################################################

{
	my %event2f = (
		'0' => [ 941,1336 ],
		'1' => [ 697,1209 ],
		'2' => [ 697,1336 ],
		'3' => [ 697,1477 ],
		'4' => [ 770,1209 ],
		'5' => [ 770,1336 ],
		'6' => [ 770,1477 ],
		'7' => [ 852,1209 ],
		'8' => [ 852,1336 ],
		'9' => [ 852,1477 ],
		'*' => [ 941,1209 ], '10' => [ 941,1209 ],
		'#' => [ 941,1477 ], '11' => [ 941,1477 ],
		'A' => [ 697,1633 ], '12' => [ 697,1633 ],
		'B' => [ 770,1633 ], '13' => [ 770,1633 ],
		'C' => [ 852,1633 ], '14' => [ 852,1633 ],
		'D' => [ 941,1633 ], '15' => [ 941,1633 ],
	);

	my $tabsize = 256;
	my $volume  = 100;
	my $speed   = 8000;
	my $samples4pkt = 160;
	my @costab;
	my @ulaw_expandtab;
	my @ulaw_compresstab;

	sub _dtmf_audio {
		my ($event,$type,$duration) = @_;

		$duration/=1000; # ms ->s
		my $start = gettimeofday();

		my $f = $event2f{$event};
		if ( ! $f ) {
			# generate silence
			return sub { 
				my ($seq,$timestamp,$srcid) = @_;
				return if gettimeofday() - $start > $duration; # done
				return pack('CCnNNa*',
					0b10000000,
					$type,
					$seq,
					$timestamp,
					$srcid,
					pack('C',128) x $samples4pkt,
				);
			}
		}

		if (!@costab) {
			for(my $i=0;$i<$tabsize;$i++) {
				$costab[$i] = $volume/100*16383*cos(2*$i*3.14159265358979323846/$tabsize);
			}
			for( my $i=0;$i<128;$i++) {
				$ulaw_expandtab[$i] = int( (256**($i/127) - 1) / 255 * 32767 ); 
			}
			my $j = 0;
			for( my $i=0;$i<32768;$i++ ) {
				$ulaw_compresstab[$i] = $j;
				$j++ if $j<127 and $ulaw_expandtab[$j+1] - $i < $i - $ulaw_expandtab[$j];
			}
		}
		
		my ($f1,$f2) = @$f;
		$f1*= $tabsize;
		$f2*= $tabsize;
		my $d1 = int($f1/$speed);
		my $d2 = int($f2/$speed);
		my $g1 = $f1 % $speed;
		my $g2 = $f2 % $speed;
		my $e1 = int($speed/2);
		my $e2 = int($speed/2);
		my $i1 = my $i2 = 0;

		return sub {
			my ($seq,$timestamp,$srcid) = @_;
			return if gettimeofday() - $start > $duration; # done

			my $samples = $samples4pkt;
			my $buf = '';
			while ( $samples-- > 0 ) {
				my $val = $costab[$i1]+$costab[$i2];
				my $c = $val>=0 ? 255-$ulaw_compresstab[$val] : 127-$ulaw_compresstab[-$val];
				$buf .= pack('C',$c);

				$e1+= $speed, $i1++ if $e1<0;
				$i1 = ($i1+$d1) % $tabsize;
				$e1-= $g1;

				$e2+= $speed, $i2++ if $e2<0;
				$i2 = ($i2+$d2) % $tabsize;
				$e2-= $g2;
			}
			return pack('CCnNNa*',
				0b10000000,
				$type,
				$seq,
				$timestamp,
				$srcid,
				$buf,
			);
		}
	}
}


###########################################################################
###########################################################################
sub _dtmf_rtpevent {
	my ($event,$type,$duration,%args) = @_;
	my $volume = $args{volume} || 10;

	$duration/=1000; # ms ->s
	my $start = gettimeofday();
	my $end = 0;
	my $first = 1;
	my $initial_timestamp;

	return sub {
		my ($seq,$timestamp,$srcid) = @_;

		# all packets get timestamp from start of event
		if ( ! $initial_timestamp ) {
			$initial_timestamp = $timestamp; 
			return ''; # need another call to get duration
		}

		if ( gettimeofday() - $start > $duration ) {
			return if $end; # end already sent
			$end = 1;
		}

		return '' if ! defined $event;

		my $pt = $type;
		if ( $first ) {
			$first = 0;
			$pt |= 0b10000000; # marker bit set on first packet of event
		}
		return pack('CCnNNCCn',
			0b10000000,
			$pt,
			$type,
			$seq,
			$initial_timestamp,
			$srcid,
			$event,
			($end<<7) | $volume,
			$timestamp - $initial_timestamp,
		);
	}
}

1;
