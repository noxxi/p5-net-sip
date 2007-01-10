#!/usr/bin/perl

use strict;
use warnings;

use Test::Simple tests => 1;

eval "use Net::SIP";
ok( !$@, 'loading Net::SIP' );
