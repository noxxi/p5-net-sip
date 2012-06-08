#!/usr/bin/perl
use strict;
use warnings;
use Getopt::Long qw(:config posix_default bundling);

sub usage {
	print STDERR <<USAGE;

Usage: $0 [-duration] events ..
generates audio data in PCMU/8000 format for dial codes and
prints them to STDOUT

 duration: time in ms, default 100
 events:   string of dial codes 0123456789*#ABCD
           any other string will be used as pause of duration

duration and events can be given multiple times.


}


my $speed = 8000;

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
	my @costab;
	my @ulaw_expandtab;
	my @ulaw_compresstab;

	sub dtmftone {
		my $event = shift;

		my $f = $event2f{$event};
		if ( ! $f ) {
			# generate silence
			return sub { return pack('C',128) x shift() }
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
			my $len = shift;
			my $buf = '';
			while ( $len-- > 0 ) {
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
			return $buf;
		}
	}
}


##### MAIN
my $duration = 100;
my $samples4ms = $speed/1000;
for my $arg (@ARGV) {
	if ( $arg =~m{^-(\d+)$} ) {
		$duration = $1;
	} else {
		for my $ev (split('',$arg)) {
			my $sub = dtmftone($ev);
			my $samples = $duration * $samples4ms;
			for( my $i=0;$i<$samples;$i+=160 ) {
				print $sub->(160);
			}
		}
	}
}




