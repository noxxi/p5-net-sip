###########################################################################
# Net::SIP::DTMF
# implements DTMF handling (audio and rfc2833)
###########################################################################

use strict;
use warnings;
package Net::SIP::DTMF;
use base 'Exporter';
our @EXPORT = qw(dtmf_generator dtmf_extractor);

use Net::SIP::Debug;
use Time::HiRes 'gettimeofday';
use Carp 'croak';

###########################################################################
# sub dtmf_generator returns a sub, which is used to generate RTP packet
# for DTMF events
# Args: ($event,$duration,%args)
#  $event: DTMF event ([0-9A-D*#]), anything else will be pause
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

    # empty or invalid stuff will cause pause/silence
    $event = '' if ! defined $event or $event !~ m{[\dA-D\*\#]}i;

    if ( defined( my $type = $pargs{rfc2833_type} )) {
	# create RFC2833 payload
	return _dtmf_gen_rtpevent($event,$type,$duration,%pargs);
    } elsif ( defined($type = $pargs{audio_type})) {
	# create audio payload
	return _dtmf_gen_audio($event,$type,$duration,%pargs);
    } else {
	croak "neither rfc2833 nor audio RTP type defined"
    }
}

###########################################################################
# sub dtmf_extractor creates sub to extract DTMF from RTP
# Args: (%pargs)
#  %pargs: rfc2833_type, audio_type like in dtmf_generator
#    will try to extract DTMF from RTP packets for any type set, e.g.
#    RFC2833 and audio can be done in parallel
# Returns: $sub
#  $sub: should be called with ($packet,[$time]), if $time not
#    given current time will be used. The $sub itself will return () if no
#    event (end) was found and ($event,$duration,$type) if event was detected.
#    $event is [0-9A-D*#], $type rfc2833|audio
# Comment: FIXME - maybe disable audio detection if a rfc2833 event was
#    received. In this case the peer obviously uses rfc2833
###########################################################################
sub dtmf_extractor {
    my %pargs = @_;
    my %sub;
    if ( defined( my $type = delete $pargs{rfc2833_type} )) {
	# extract from RFC2833 payload
	$sub{$type} = _dtmf_xtc_rtpevent(%pargs);
    }
    if ( defined( my $type = delete $pargs{audio_type})) {
	# extract from audio payload
	$sub{$type} = _dtmf_xtc_audio($type);
    }
    croak "neither rfc2833 nor audio RTP type defined" if ! %sub;

    my $lastseq;
    return sub {
	my ($pkt,$time) = @_;
	my ($ver,$type,$seq,$tstamp,$srcid,$payload) = unpack('CCnNNa*',$pkt);
	$ver == 0b10000000 or return;
	my $marker;
	if ($type & 0b10000000) {
	    $marker = 1;
	    $type &= 0b01111111;
	}

	my $seqdiff;
	if (defined $lastseq) {
	    $seqdiff = (2**16 + $seq - $lastseq) & 0xffff;
	    if (!$seqdiff) {
		$DEBUG && DEBUG(20,"dropping duplicate RTP");
		return;
	    } elsif ($seqdiff>2**15) {
		$DEBUG && DEBUG(20,"dropping out of order RTP");
		return;
	    } else {
		$DEBUG && $seqdiff>1 && DEBUG(30,'lost %d packets (%d-%d)',
		    $seqdiff-1,$lastseq+1,$seq-1);
	    }
	}
	$lastseq = $seq;

	my $sub = $sub{$type} or return;
	my ($event,$duration,$media)  = $sub->($payload,$time,$marker,$seqdiff)
	    or return;
	return ($event, int(1000*$duration),$media);
    };
}


###########################################################################
# END OF PUBLIC INTERFACE
###########################################################################

###########################################################################
#
#                  RTP DTMF events
#
###########################################################################
# mapping between event string and integer for RTP events
my %event2i;
{ my $i=0; %event2i = map { $_ => $i++ } split('','0123456789*#ABCD'); }
my %i2event = reverse %event2i;


###########################################################################
# generate DTMF RTP events according to rfc2833
# Args: $event,$duration,%args
#  %args: volume => v will be used to set volume of RTP event, default 10
# Returns: $sub for $event
# Comment: the sub should then be called with $sub->($seq,$timstamp,$srcid)
#  This will generate the RTP packet.
#  If $event is no DTMF event it will return '' to indicate pause
###########################################################################
sub _dtmf_gen_rtpevent {
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

	return '' if $event eq '';

	my $pt = $type;
	if ( $first ) {
	    $first = 0;
	    $pt |= 0b10000000; # marker bit set on first packet of event
	}
	return pack('CCnNNCCn',
	    0b10000000,
	    $pt,
	    $seq,
	    $initial_timestamp,
	    $srcid,
	    $event2i{$event},
	    ($end<<7) | $volume,
	    $timestamp > $initial_timestamp
		? $timestamp - $initial_timestamp
		: 0x10000 - $initial_timestamp + $timestamp,
	);
    }
}

###########################################################################
# returns sub to extract DTMF events from RTP telephone-event/8000 payload
# Args: NONE
# Returns: $sub
#  $sub - will be called with ($rtp_payload,[$time],$marker)
#   will return ($event,$duration) if DTMF event was found
###########################################################################
sub _dtmf_xtc_rtpevent {
    my $current_event;
    return sub {
	my ($payload,$time,$marker) = @_;
	my ($event,$volume,$duration) = unpack('CCn',$payload);
	$event = $i2event{$event};
	my $end;
	if ( $volume & 0b10000000 ) {
	    $end = 1;
	    $volume &= 0b01111111
	}
	$DEBUG && DEBUG(100,"DTMF event [%s] end=%d vol=%d duration=%d",
	    $event, $end, $volume, $duration);
	if ( ! $current_event ) {
	    return if $end; # probably repeated send of end
	    # we don't look at the marker for initial packet, because maybe
	    # the initial packet got lost
	    $current_event = [ $event,$time||gettimeofday(),$volume ];
	} elsif ( $event eq $current_event->[0] ) {
	    if ( $end ) {
		# explicit end of event
		my $ce = $current_event;
		$current_event = undef;
		$time ||= gettimeofday();
		return ($ce->[0],$time - $ce->[1],'rfc2833');
	    }
	} else {
	    # implicit end because we got another event
	    my $ce = $current_event;
	    $time||= gettimeofday();
	    $current_event = [ $event,$time,$volume ];
	    return if ! $ce->[2]; # volume == 0
	    return ($ce->[0],$time - $ce->[1],'rfc2833');
	}
	return;
    };
}

###########################################################################
#
#                  RTP DTMF audio
#
###########################################################################

# mapping between frequence and key for audio
my @freq1 = (697,770,852,941);
my @freq2 = (1209,1336,1477,1633);
my @keys  = '123A 456B 789C *0#D' =~m{(\S)}g;

my (%event2f,@f2event);
for( my $i=0;$i<@keys;$i++ ) {
    my $freq1 = $freq1[ $i/4 ];
    my $freq2 = $freq2[ $i%4 ];
    $event2f{$keys[$i]} = [$freq1,$freq2];
    $f2event[$freq1][$freq2] = $keys[$i];
}

# basic paramter, PCMU/8000 160 samples per RTP packet
my $volume      = 100;
my $samples4s   = 8000;
my $samples4pkt = 160;

use constant PI => 3.14159265358979323846;

# tables for audio processing get computed on first use
# cosinus is precomputed. How exakt a cos will be depends on
# the size of the table $tabsize
my $tabsize = 256;
my @costab;

# tables for PCMU u-law compression
my @ulaw_expandtab;
my @ulaw_compresstab;

# tables for PCMA a-law compression
my @alaw_expandtab;
my @alaw_compresstab;

# Goertzel algorithm
my $gzpkts = 3; # 3 RTP packets = 60ms
my %coeff;
my @blackman; # exact blackman

# precompute stuff into tables for faster operation
sub _init_audio_processing {

    # audio generation
    @costab and return;
    for(my $i=0;$i<$tabsize;$i++) {
	$costab[$i] = $volume/100*16383*cos(2*PI*$i/$tabsize);
    }

    my $alaw_c = 1 + log(87.6);

    # PCMU/8000 u-law and PCMA/8000 a-law (de)compression
    for( my $i=0;$i<128;$i++) {
	$ulaw_expandtab[$i] = int( (256**($i/127) - 1) / 255 * 32767 );
	$alaw_expandtab[$i ^ 0x55] = ($i/127 < 1/$alaw_c) ? int($i/127 * $alaw_c / 87.6 * 32767) : int(exp($i/127 * $alaw_c - 1) / 87.6 * 32767);
    }
    my $ulaw = 0;
    my $alaw = 0;
    for( my $i=0;$i<32768;$i++ ) {
	$ulaw_compresstab[$i] = $ulaw;
	$alaw_compresstab[$i] = $alaw ^ 0x55;
	$ulaw++ if $ulaw<127 and $ulaw_expandtab[$ulaw+1] - $i < $i - $ulaw_expandtab[$ulaw];
	$alaw++ if $alaw<127 and $alaw_expandtab[($alaw+1) ^ 0x55] - $i < $i - $alaw_expandtab[$alaw ^ 0x55];
    }

    for my $freq (@freq1,@freq2) {
	my $k = int(0.5+$samples4pkt*$freq/$samples4s);
	my $w = 2*PI/$samples4pkt*$k;
	$coeff{$freq} = 2*cos($w);
    }

    my $n = $samples4pkt*$gzpkts;
    for( my $i=0;$i<$n;$i++) {
	$blackman[$i] = 0.426591 - 0.496561*cos(2*PI*$i/$n) +0.076848*cos(4*PI*$i/$n)
    }
}


###########################################################################
# sub _dtmf_gen_audio returns a sub to generate audio/silence for DTMF in
# any duration
# Args: $event,$duration
# Returns: $sub for $event
# Comment: the sub should then be called with $sub->($seq,$timstamp,$srcid)
#  This will generate the RTP packet.
#  If $event is no DTMF event it will return a sub which  gives silence.
#  Data returned from the subs are PCMU/8000 or PCMA/8000, 160 samples per packet
###########################################################################
sub _dtmf_gen_audio {
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
		# Silence byte for PCMA=8 is 0xD5 and for PCMU=0 is 0xFF
		pack('C', $type == 8 ? 0xD5 : 0xFF) x $samples4pkt,
	    );
	}
    }

    _init_audio_processing() if !@costab;

    my ($f1,$f2) = @$f;
    $f1*= $tabsize;
    $f2*= $tabsize;
    my $d1 = int($f1/$samples4s);
    my $d2 = int($f2/$samples4s);
    my $g1 = $f1 % $samples4s;
    my $g2 = $f2 % $samples4s;
    my $e1 = int($samples4s/2);
    my $e2 = int($samples4s/2);
    my $i1 = my $i2 = 0;

    return sub {
	my ($seq,$timestamp,$srcid) = @_;
	return if gettimeofday() - $start > $duration; # done

	my $samples = $samples4pkt;
	my $buf = '';
	while ( $samples-- > 0 ) {
	    my $val = $costab[$i1]+$costab[$i2];
	    my $c;
	    if ($type == 8) { # PCMA
	        $c = $val>=0 ? 128+$alaw_compresstab[$val] : $alaw_compresstab[-$val];
	    } else { # PCMU
	        $c = $val>=0 ? 255-$ulaw_compresstab[$val] : 127-$ulaw_compresstab[-$val];
	    }
	    $buf .= pack('C',$c);

	    $e1+= $samples4s, $i1++ if $e1<0;
	    $i1 = ($i1+$d1) % $tabsize;
	    $e1-= $g1;

	    $e2+= $samples4s, $i2++ if $e2<0;
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



###########################################################################
# returns sub to extract DTMF events from RTP PCMU/8000 or PCMA/8000 payload
# Args: ($type)
#  $type - (optional) RTC type: 8 for PCMA/8000, otherwise PCMU/8000
# Returns: $sub
#  $sub - will be called with ($rtp_payload,[$time])
#   will return ($event,$duration) if DTMF event was found, event being 0..15
###########################################################################
sub _dtmf_xtc_audio {
    my ($type) = @_;
    _init_audio_processing() if !@costab;
    my (%d1,%d2,@time,@lastev);
    return sub {
	my ($payload,$time) = @_;
	$time ||= gettimeofday();
	my @samples = map {
	    ( (defined $type && $type == 8)
	    ?
	    ( $_<128 ? -$alaw_expandtab[$_] : $alaw_expandtab[$_-128] )/32768
	    :
	    ( $_<128 ? -$ulaw_expandtab[127-$_] : $ulaw_expandtab[255-$_] )/32768
	    )
	    } unpack('C*',$payload);
	@samples == $samples4pkt or return; # unexpected sample size

	unshift @time, $time;

	for my $f (@freq1,@freq2) {
	    my $coeff = $coeff{$f};

	    my $da1 = $d1{$f} ||= [];
	    my $da2 = $d2{$f} ||= [];
	    unshift @$da1,0;
	    unshift @$da2,0;

	    for(my $gzi=0;$gzi<@$da1;$gzi++) {
		my $d1 = $da1->[$gzi];
		my $d2 = $da2->[$gzi];
		my $o  = $gzi*$samples4pkt;
		for( my $i=0;$i<@samples;$i++) {
		    ($d2,$d1) = ($d1, $samples[$i]*$blackman[$i+$o] + $coeff*$d1 - $d2);
		}
		$da1->[$gzi] = $d1;
		$da2->[$gzi] = $d2;
	    }
	}

	return if @time < $gzpkts;

	$time = pop @time;
	my @r;
	for my $f (@freq1,@freq2) {
	    my $d1 = pop(@{$d1{$f}});
	    my $d2 = pop(@{$d2{$f}});
	    push @r, [ $f, $d1*$d1+$d2*$d2-$d1*$d2*$coeff{$f} ];
	}


	# the highest two freq should be significantly higher then rest
	@r = sort { $b->[1] <=> $a->[1] } @r; # sort by magnitude, largest first
	my $event;
	if ( @r and ! $r[2][1] || $r[1][1]/$r[2][1]> 5 ) {
	    $event = $f2event[ $r[0][0] ][ $r[1][0] ];
	    $event = $f2event[ $r[1][0] ][ $r[0][0] ] if ! defined $event;
	}

	$event = '' if ! defined $event;
	push @lastev,[$event,$time];
	# remove pause from start of lastev
	shift(@lastev) while (@lastev && $lastev[0][0] eq '');

	# if last event same as first wait for more
	if ( ! @lastev ) {
	    # return; # no events detected
	} elsif ( $event eq $lastev[0][0] ) {
	    return;   # event not finished
	} else {
	    my @ev = shift(@lastev);
	    while (@lastev and $lastev[0][0] eq $ev[0][0]) {
		push @ev,shift(@lastev);
	    }
	    # get the event at least 2 times
	    return if @ev == 1;
	    return ($ev[0][0],$ev[-1][1]-$ev[0][1],'audio'); # event,duration
	}

	return;
    };
}

1;
