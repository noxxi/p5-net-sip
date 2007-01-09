#!/usr/bin/perl

use strict;
use warnings;
use Test::Simple 'no_plan';

use Net::SIP;

my $uac = Net::SIP::Simple->new(
	domain => 'example.com',
);
