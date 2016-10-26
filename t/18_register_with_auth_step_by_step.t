#!/usr/bin/perl

#############################################################################
# test Authorize in front of Registrar inside a ReceiveChain
# to authorize REGISTER requests
#############################################################################

use strict;
use warnings;
use Test::More tests => 8*2;
do './testlib.pl' || do './t/testlib.pl' || die "no testlib";

use Net::SIP ':all';
use Digest::MD5 'md5_hex';

for my $proto (qw(ip4 ip6)) {
    SKIP: {
	if ($proto eq 'ip6' && !do_ipv6()) {
	    skip "no IPv6 support",8;
	    next;
	}

	note("------ testing with $proto");

	my ($csock,$caddr) = create_socket();
	my ($ssock,$saddr) = create_socket();

	# start Registrar
	my $registrar = fork_sub( 'registrar',$ssock,$saddr );
	fd_grep_ok( 'Listening',$registrar );

	# start UAC once Registrar is ready
	my $uac = fork_sub( 'uac',$csock,$caddr,$saddr );
	fd_grep_ok( 'Started',$uac );
	fd_grep_ok( 'got 401 response',$uac );
	fd_grep_ok( 'Registered wolf (REALM.example.com)',$uac );
	fd_grep_ok( 'Registered 007 (REALM.example.com)',$uac );
	fd_grep_ok( 'Registered noauth ()',$uac );
    }
}

killall();


#############################################################################
# UAC
# Try to register me@example.com with auth wolf:lobo and 007:secret.
# In both cases authorization should be required.
# Then register noauth@example.com in which case no authorization should
# be required (see sub registrar)
# auth is done with callback so that we see if the authorization was required
#############################################################################

sub uac {
    my ($lsock,$laddr,$peer) = @_;
    my $ua = Simple->new(
	leg => $lsock,
	from => 'sip:me@example.com',
    );
    print "Started\n";

    # first registration w/o auth
    my $resp40x;
    $ua->register(
	registrar => $peer,
	cb_final => sub {
	    my ($what,%args) = @_;
	    die if $what ne 'FAIL';
	    $resp40x = $args{packet} or die;
	},
    );
    $ua->loop(\$resp40x);
    print "got ".$resp40x->code." response\n";

    # then issue another registration based on auth response from
    # last failed registration
    my $realm = '';
    $ua->register(
	registrar => $peer,
	auth => sub {
	    $realm = shift;
	    return [ 'wolf','lobo' ],
	},
	resp40x => $resp40x,
    ) || die;
    print "Registered wolf ($realm)\n";

    $realm = '';
    $ua->register(
	registrar => $peer,
	auth => sub {
	    $realm = shift;
	    return [ '007','secret' ],
	},
    ) || die;
    print "Registered 007 ($realm)\n";

    $realm = '';
    $ua->register(
	from => 'sip:noauth@example.com',
	registrar => $peer,
	auth => sub {
	    $realm = shift;
	    return [ '007','secret' ],
	},
    ) || die;
    print "Registered noauth ($realm)\n";

}


#############################################################################
# Registrar with Authorize in front
# The $auth_chain consists of an ReceiveChain with a Authorize object
# inside. The ReceiveChain has a filter so that only requests with
# contact info !~ noauth\@ will be forwarded to the Authorize object
# Then $auth_chain is put in front of the Registrar object into a chain
# which then handles all packets
# The result is, that all requests must be authorized, except the ones
# where contact matches noauth\@
#############################################################################

sub registrar {
    my ($lsock,$laddr,$peer) = @_;
    my $ua = Simple->new( leg => $lsock );
    my $auth = Authorize->new(
	dispatcher => $ua->{dispatcher},
	user2a1   => { '007' => md5_hex('007:REALM.example.com:secret') },
	user2pass => sub { $_[0] eq 'wolf' ? 'lobo' : 'no-useful-password' },
	realm => 'REALM.example.com',
	opaque => 'HumptyDumpty',
	i_am_proxy => 0,
    );
    my $auth_chain = ReceiveChain->new(
	[ $auth ],
	filter => sub {
	    my ($packet,$leg,$from) = @_;
	    # no auth for responses and noauth@...
	    return if $packet->is_response;
	    my $need_auth = $packet->get_header( 'contact' ) !~m{noauth\@};
	    return $need_auth;
	}
    );
    my $reg = Registrar->new(
	dispatcher => $ua->{dispatcher},
	domain => 'example.com',
    );
    $ua->create_chain( [ $auth_chain,$reg ] );
    print "Listening\n";
    $ua->loop
}
