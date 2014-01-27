#!/usr/bin/perl

use strict;
use warnings;
use Getopt::Long qw(:config posix_default bundling);
use Net::SIP ':all';

##############################################################
#
# Implements 3pcc according to RFC 3725,4.1 'Flow I'
#
##############################################################

# Usage
# -------------------------------------------------------------
sub usage {
    print STDERR "ERROR: @_\n" if @_;
    print STDERR <<EOS;

Implements 3rd Party control according to RFC 3625,4.1 'Flow I'

Usage: $0 [ options ] laddr from to
Options:
  -d|--debug [level]           Enable debugging
  -h|--help                    Help (this info)

Example:
  $0 -d 192.168.178.3:5090 \
    sip:me\@192.168.178.3:5070 \
    sip:me\@192.168.178.3:5080

EOS
    exit( @_ ? 1:0 );
}

# get options
# -------------------------------------------------------------
my $debug;
GetOptions(
    'd|debug:i' => \$debug,
    'h|help' => sub { usage() },
) || usage( 'bad options' );
Debug->level($debug || 1) if defined $debug;

my ($laddr,$from,$to) = @ARGV;
$to || usage( "no TO given" );

# create Dispatcher
# -------------------------------------------------------------
my $loop = Dispatcher_Eventloop->new;
my $leg = Leg->new( addr => $laddr );
my $disp = Dispatcher->new(
    [ $leg ],
    $loop,
    do_retransmits => 0
) || die;
$disp->set_receiver( \&receive );
my $me = ($disp->get_legs())[0]->{contact};


# create initial invite without SDP with
# To: $to, From: $from, Contact: $me
# put these info in call-id to be stateless
# -------------------------------------------------------------
# assume no '|' is in $from and $to
my $callid = "$from|$to|0|". sprintf( "%08x",rand(2**16));

my $invite = Request->new( "INVITE",$from, {
    from      => $to,
    to        => $from,
    contact   => $me,
    'call-id' => $callid,
    cseq      => '1 INVITE',
});
$disp->deliver( $invite, do_retransmits => 1 );

# and loop
# -------------------------------------------------------------
my $stop_loop;
$loop->loop( undef, \$stop_loop );
$loop->loop(1) if $stop_loop; # some time to forward remaining stuff


###############################################################
#
#   callback for incoming packets:
#
# - there are two calls which slightly different call-id, with
#   a simple way one can get the other call-id from one call-id.
# - responses are for me if there is only one via header, and
#   that's me -> handle to make requests (INVITE,ACK) from it
# - all other responses get forwarded. If last via has a cseq
#   parameter they get forwarded after changing the cseq
# - requests are for me if the URI is the contact of the local leg
#   -> forward to other call, but add "cseq" parameter to last
#   via so that the cseq of the calling uac gets saved for
#   responses
# - all requests I get should be for me, because a contact header
#   is explicitly added
#
###############################################################
sub receive {
    my ($packet,$leg,$from_addr) = @_;

    # extract info from call-id
    my $callid = $packet->callid() or do {
	DEBUG( 1,"no callid in packet. DROP" );
	return;
    };
    my ($from,$to,$dir,$random) = split( qr{\|}, $callid );
    my $new_callid = join( '|',$from,$to, $dir?0:1, $random );

    my ( $request,$response ) = $packet->is_response
	? ( undef,$packet )
	: ( $packet, undef );

    if ( $response ) {
	# ------------------------------------------------------------------
	# Handle Responses:
	# - if it has only one via (and this is myself) it is a response
	#   to a request which originated locally. In this case make
	#   the appropriate request from it and forward it to the other side
	# - if it has more than one via just forward it to the other side
	# ------------------------------------------------------------------

	# top via must be me
	my @via = $response->get_header( 'via' );
	$leg->check_via($response) or do {
	    DEBUG( 5, "top via isn't me: $via[0]" );
	    return;
	};

	# exactly one via ?
	my $cseq = $response->cseq;
	my ($num,$method) = split( ' ',$cseq );
	if ( @via == 1 ) {

	    # cancel retransmits
	    $disp->cancel_delivery( $response->tid );

	    if ( $method eq 'INVITE' && $dir == 0 ) {
		# ---------------------------------------------------------
		# response to initial INVITE  ME->FROM
		# on success create INVITE ME->TO with SDP from response
		# ---------------------------------------------------------
		my $code = $response->code;
		if ( $code < 200 ) {
		    # preliminary response, ignore and don't reply
		    DEBUG( 10,"ignoring preliminary reply to initial invite" );
		    return;
		} elsif ( $code >= 300 ) {
		    # non successful response (we don't care about redirects)
		    # send ACK and ignore
		    $disp->deliver( Request->new( 'ACK',$from, {
			'call-id' => $callid,
			cseq      => "$num ACK",
			to        => scalar($response->get_header('from')),
			from      => scalar($response->get_header('to')),
			contact   => $me,
		    }));
		} else {
		    # success: extract SDP and forward in INVITE to
		    # other party
		    DEBUG( 10,"got success to initial INVITE" );
		    my $sdp = $response->sdp_body or do {
			DEBUG( 1,"no SDP in response to INVITE from $from" );
			return;
		    };
		    $disp->deliver( Request->new( 'INVITE', $to,
			{
			    from => scalar($response->get_header( 'to' )),
			    to => scalar($response->get_header( 'from' )),
			    'call-id' => $new_callid,
			    contact   => $me,
			    cseq => "$num INVITE",
			},
			$sdp,
		    ));
		}
	    } elsif ( $method eq 'INVITE' && $dir == 1 ) {
		# ---------------------------------------------------------
		# response from $to to the initial INVITE
		# on success create ACK
		# ---------------------------------------------------------
		my $code = $response->code;
		if ( $code < 200 ) {
		    # preliminary response, ignore and don't reply
		    DEBUG( 10,"ignoring preliminary reply from TO to initial invite" );
		    return;
		}

		# create ACK to TO
		$disp->deliver( Request->new( 'ACK', $to, {
		    from => scalar($response->get_header( 'from' )),
		    to   => scalar($response->get_header( 'to' )),
		    'call-id' => $callid,
		    contact   => $me,
		    cseq => "$num ACK",
		}));

		if ( $code >= 300 ) {
		    # non successful response (we don't care about redirects)
		    # cancel initial call [ME,FROM]
		    DEBUG( 10,"got code $code on INVITE 'TO'" );
		    $disp->deliver( Request->new( 'CANCEL',$from, {
			'call-id' => $new_callid,
			cseq      => "$num INVITE",
			from => scalar($response->get_header( 'to' )),
			to   => scalar($response->get_header( 'from' )),
			contact   => $me,
		    }));

		} else {
		    DEBUG( 10,"got success on INVITE 'TO'" );
		    # success: extract SDP and forward in ACK to FROM
		    my $sdp = $response->sdp_body or do {
			DEBUG( 1,"no SDP in response to INVITE from $to" );
			return;
		    };
		    $disp->deliver( Request->new( 'ACK', $from,
			{
			    from => scalar($response->get_header( 'to' )),
			    to   => scalar($response->get_header( 'from' )),
			    'call-id' => $new_callid,
			    contact   => $me,
			    cseq => "$num ACK",
			},
			$sdp,
		    ));
		}
	    }
	} else {
	    # ---------------------------------------------------------
	    # response for forwarded request
	    # change call-id and forward
	    # ---------------------------------------------------------

	    # get addr from next via
	    my ($data) = sip_hdrval2parts( via => $via[1] );
	    my ($addr,$port) = $data =~m{([\w\-\.]+)(?::(\d+))?\s*$};
	    $port ||= 5060; # FIXME: not for sips!

	    $response->set_header( contact => $me );
	    $leg->forward_incoming( $response );
	    $response->set_header( 'call-id' => $new_callid );

	    # check if the last via header had a cseq attribute.
	    # in this case forward the response with the given cseq
	    my ($via) = $response->get_header( 'via' );
	    my (undef,$param) = sip_hdrval2parts( via => $via );
	    if ( defined( my $num = $param->{cseq} )) {
		my $cseq = $response->cseq;
		$cseq =~s{^(\d+)}{$num};
		$response->set_header( cseq => $cseq );
	    }

	    # if this was response to BYE end this program
	    $stop_loop = 1 if $method eq 'BYE';

	    $leg->forward_outgoing( $response,$leg );
	    $disp->deliver( $response, leg => $leg, dst_addr => "$addr:$port" );

	}

    } else {
	# ------------------------------------------------------------------
	# Handle requests from one of the parties
	# change call-id and cseq (because I have to use one of my cseqs)
	# and forward
	# ------------------------------------------------------------------

	if ( $request->uri eq $leg->{contact} ) {
	    # this is for me
	    # could be CANCEL or BYE
	    my $m = $request->method;
	    if ( $m ne 'BYE' and $m ne 'CANCEL' ) {
		DEBUG( 10,"will not forward request to me with method $m" );
		return;
	    }

	    # set URI to other party
	    # if we were stateful we could store Contact infos from
	    # older packets and use them here instead.
	    $request->set_uri( $dir ? $from : $to );
	}

	my ($num,$method) = split( ' ',$request->cseq );

	# we just add 20 to the cseq we got from the uac
	# this is higher then every other locally generated cseq on
	# this side (we only used "1" until now for the first INVITE)
	$request->set_header( cseq => ( $num + 20 ).' '.$method );

	$request->set_header( contact => $me );
	$leg->forward_incoming( $request );
	$request->set_header( 'call-id' => $new_callid );

	# add cseq param to last via header because both calls maintain
	# different cseq spaces and we must know with which cseq we
	# need to forward the response
	if ( my @via = $request->get_header( 'via' ) ) {
	    my ($data,$param) = sip_hdrval2parts( via => $via[0] );
	    $param->{cseq} = $num;
	    $via[0] = sip_parts2hdrval( 'via',$data,$param );
	    $request->set_header( via => \@via );
	}

	$leg->forward_outgoing( $request,$leg );
	$disp->deliver( $request )
    }

}
