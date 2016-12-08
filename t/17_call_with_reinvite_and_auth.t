#!/usr/bin/perl

use strict;
use warnings;
use Test::More tests => 11*6;
do './testlib.pl' || do './t/testlib.pl' || die "no testlib";

use Net::SIP ':all';

my @tests;
for my $transport (qw(udp tcp tls)) {
    for my $family (qw(ip4 ip6)) {
	push @tests, [ $transport, $family ];
    }
}

for my $t (@tests) {
    my ($transport,$family) = @$t;
    SKIP: {
	if (my $err = test_use_config($family,$transport)) {
	    skip $err,11;
	    next;
	}

	note("------- test with family $family transport $transport");

	my ($csock,$caddr) = create_socket($transport);
	my ($ssock,$saddr) = create_socket($transport);

	# start UAS
	my $uas = fork_sub( 'uas',$ssock,$caddr,$saddr );
	fd_grep_ok( 'Listening',$uas );

	# start UAC once UAS is ready
	my $uac = fork_sub( 'uac',$csock,$caddr,$saddr );
	fd_grep_ok( 'Started',$uac );
	fd_grep_ok( 'Call accepted',$uas );

	# then re-invite
	fd_grep_ok( 'Starting ReInvite', $uac );
	fd_grep_ok( 'ReInvite accepted',$uas );
	fd_grep_ok( 'ReInvite done', $uac );

	# BYE from UAC
	fd_grep_ok( 'Send BYE',$uac );
	fd_grep_ok( 'Received BYE',$uas );
	fd_grep_ok( 'BYE done',$uac );
    }
}

killall();


#############################################################################
#            UAC
#############################################################################

sub uac {
    my ($lsock,$laddr,$peer) = @_;
    my $ua = Net::SIP::Simple->new(
	from => 'me\@$laddr',
	auth => [ 'me','secret' ],
	leg => Net::SIP::Leg->new(
	    sock => $lsock,
	    test_leg_args('caller.sip.test'),
	)
    );

    print "Started\n";
    my $call = $ua->invite(test_sip_uri("me\@$peer")) or die;

    sleep(1);
    print "Starting ReInvite\n";
    my $reinvite_ok;
    $call->reinvite( cb_final => \$reinvite_ok ) or die;
    $ua->loop( 10,\$reinvite_ok );
    print "ReInvite done\n" if $reinvite_ok;

    sleep(1);
    # and bye
    print "Send BYE\n";
    $call->bye( cb_final => \( my $bye_ok ));
    $ua->loop( 10,\$bye_ok );
    $ua->cleanup;
    print "BYE done\n" if $bye_ok;


}


#############################################################################
#            UAS
#############################################################################

sub uas {
    my ($lsock,$laddr,$peer) = @_;
    my $ua = Net::SIP::Simple->new(
	from => "me\@$laddr",
	leg => Net::SIP::Leg->new(
	    sock => $lsock,
	    test_leg_args('listen.sip.test'),
	)
    ) || die $!;

    # accept call
    my $invite = my $reinvite = my $bye = 0;
    $ua->listen(
	auth_user2pass => { 'me' => 'secret' },
	cb_established => sub { $reinvite++ if $invite++ },
	cb_cleanup     => \$bye,
    );
    print "Listening\n";
    $ua->loop( \$invite );
    print "Call accepted\n";
    $ua->loop( \$reinvite );
    print "ReInvite accepted\n";


    # wait until I got BYE
    $ua->loop( 10, \$bye );
    $ua->cleanup;
    print "Received BYE\n" if $bye;
}
