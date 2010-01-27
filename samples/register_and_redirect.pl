#!/usr/bin/perl 

# sample program which allows anybody to register and then
# redirects any INVITES to the registered addresses

use strict;
use warnings;
use Net::SIP qw(:alias);

my $loop = Dispatcher_Eventloop->new;
my $leg =  Leg->new(addr => $ARGV[0] || '192.168.178.3:5060');
my $disp = Dispatcher->new( [ $leg ], $loop);

# Authorize
# only user is looser|secret
my $auth = Authorize->new(
	dispatcher => $disp,
	realm => 'net-sip.example.com',
	user2pass => { looser => 'secret' }
);

# Registrar, accepts registration for every domain
my $reg  = Registrar->new(
	dispatcher => $disp
);

# handles invites and redirects them to the contacts
# provided by the registrar
my $redir = Redirect->new(
	dispatcher => $disp,
	registrar => $reg,
);

my $chain = ReceiveChain->new( [$auth,$redir,$reg]);
$disp->set_receiver($chain);
$loop->loop;

