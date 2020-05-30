#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Net::SIP::DTMF qw(dtmf_generator dtmf_extractor);

my $duration = 10;
my @symbols = split //, '0123456789*#ABCD';
my %types = (pcmu => 0, pcma => 8);

foreach my $codec (qw(pcmu pcma)) {
	my @got;
	my $ext = dtmf_extractor(audio_type => $types{$codec});
	foreach my $symbol (@symbols, undef) {
		my $gen = dtmf_generator($symbol, $duration, audio_type => $types{$codec});
		my $seq = 0;
		while (my $rtp = $gen->($seq++, $seq*$duration/8000, 0)) {
			my ($event) = $ext->($rtp);
			push @got, $event if defined $event;
		}
	}
	is_deeply(\@got, \@symbols, "DTMF audio generator and extractor for codec $codec works");
}

done_testing();
