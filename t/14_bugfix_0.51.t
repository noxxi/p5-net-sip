#!/usr/bin/perl

use strict;
use warnings;
use Test::More tests => 12;
do './testlib.pl' || do './t/testlib.pl' || die "no testlib";

use Net::SIP ':all';
use Net::SIP::SDP;
use Data::Dumper;

my $HOST = '127.0.0.1';

my ($luac,$luas,$lproxy);
for ( $luac,$luas,$lproxy) {
    my ($sock,$addr) = create_socket_to( $HOST );
    $_ = { sock => $sock, addr => $addr };
}

diag( "UAS   on $luas->{addr} " );
diag( "UAC   on $luac->{addr} " );
diag( "PROXY on $lproxy->{addr} " );

# start Proxy
my $proxy = fork_sub( 'proxy', $lproxy );
fd_grep_ok( 'Listening',$proxy );

# start UAS
my $uas = fork_sub( 'uas', $luas, $lproxy->{addr} );
fd_grep_ok( 'Listening',$uas );

# start UAC once UAS is ready
my $uac = fork_sub( 'uac', $luac, $lproxy->{addr} );
fd_grep_ok( 'Started',$uac );
fd_grep_ok( 'Call accepted',$uas );

# then re-invite
fd_grep_ok( 'Starting ReInvite', $uas );
fd_grep_ok( 'Got ReInvite', $uac );

# BYE from UAS
fd_grep_ok( 'Send BYE',$uas );
fd_grep_ok( 'Received BYE',$uac );
fd_grep_ok( 'BYE done',$uas );

killall();

# --------------------------------------------------------------
#            PROXY
# --------------------------------------------------------------
sub proxy {
    my $lsock = shift;
    my $proxy = Net::SIP::Simple->new( leg => $lsock );
    $proxy->create_chain([
	$proxy->create_registrar,
	$proxy->create_stateless_proxy,
    ]);
    print "Listening\n";
    $proxy->loop;
}

# --------------------------------------------------------------
#            UAC
# --------------------------------------------------------------

sub uac {
    my ($lsock,$paddr) = @_;

    my $ua = Simple->new(
	leg => $lsock,
	outgoing_proxy => $paddr,
	from => "sip:uac\@$paddr",
    );
    print "Started\n";

    my ($call,$reinvite);
    $ua->invite( "sip:uas\@$paddr", cb_established => sub {
	(undef,$call) = @_;
	$reinvite = 1;
    }) || die;

    # wait for reinvite done
    $reinvite = 0;
    $ua->loop( 10,\$reinvite );
    $reinvite || die;
    print "Got ReInvite\n";

    # wait for BYE
    $call->set_param( recv_bye => \( my $recv_bye ));
    $ua->loop( 5,\$recv_bye );
    print "Received BYE\n" if $recv_bye;
}

# --------------------------------------------------------------
#            UAS
# --------------------------------------------------------------

sub uas {
    my ($lsock,$paddr) = @_;
    my $ua = Simple->new(
	domain => $paddr,
	registrar => $paddr,
	outgoing_proxy => $paddr,
	leg => $lsock,
	from => "sip:uas\@$paddr",
    );

    # registration
    $ua->register;
    die "registration failed: ".$ua->error if $ua->error;

    # accept call and send some data, set $stop once
    # the call was established
    my $stop = 0;
    my $call;
    $ua->listen( cb_established => sub {
	(undef,$call) = @_;
	$stop = 1
    });
    print "Listening\n";
    $ua->loop( \$stop );
    print "Call accepted\n";

    # Reinvite
    print "Starting ReInvite\n";
    $stop = 0;
    $call->reinvite( cb_final => \$stop );
    $ua->loop( 10,\$stop );

    # Bug fixed in 0.51:
    # to of context should be uas, from should be uac, context should be incoming
    die "from is $call->{ctx}{from}" if $call->{ctx}{from} !~m{uac\@};
    die "from is $call->{ctx}{to}" if $call->{ctx}{to} !~m{uas\@};
    die "ctx is not incoming" if ! $call->{ctx}{incoming};

    # and bye
    print "Send BYE\n";
    $call->bye( cb_final => \( my $bye_ok ));
    $ua->loop( 10,\$bye_ok );
    print "BYE done\n" if $bye_ok;
}
