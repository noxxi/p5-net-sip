#!/usr/bin/perl

use strict;
use warnings;

use Test::Simple tests => 1;

eval "use Net::SIP; use Net::SIP::NATHelper";
ok( !$@, 'loading Net::SIP' );
