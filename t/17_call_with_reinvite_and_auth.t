#!/usr/bin/perl

use strict;
use warnings;
use Test::More tests => 11;
do './testlib.pl' || do './t/testlib.pl' || die "no testlib";

use Net::SIP ':all';

my ($csock,$caddr) = create_socket();
my ($ssock,$saddr) = create_socket();

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


killall();


#############################################################################
#            UAC
#############################################################################

sub uac {
    my ($lsock,$laddr,$peer) = @_;
    my $ua = Simple->new(
	leg => $lsock,
	from => "sip:me\@$laddr",
	auth => [ 'me','secret' ],
    );

    print "Started\n";
    my $call = $ua->invite( "sip:me\@$peer") or die;

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
    print "BYE done\n" if $bye_ok;


}


#############################################################################
#            UAS
#############################################################################

sub uas {
    my ($lsock,$laddr,$peer) = @_;
    my $ua = Simple->new(
	leg => $lsock,
	from => "sip:me\@$laddr",
    );

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
    print "Received BYE\n" if $bye;
}
