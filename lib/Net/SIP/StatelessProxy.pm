###########################################################################
# Net::SIP::StatelessProxy
# implements a simple stateless proxy
# all packets will be forwarded between Leg#1 to Leg#2. If there is
# only one leg it will use only this leg.
###########################################################################

use strict;
use warnings;

package Net::SIP::StatelessProxy;
use fields qw( dispatcher rewrite_contact nathelper force_rewrite respcode );

use Net::SIP::Util ':all';
use Digest::MD5 qw(md5);
use Carp 'croak';
use List::Util 'first';
use Hash::Util 'lock_ref_keys';
use Net::SIP::Debug;

###########################################################################
# creates new stateless proxy
# Args: ($class,%args)
#   %args
#     dispatcher: the Net::SIP::Dispatcher object managing the proxy
#     rewrite_contact: callback to rewrite contact header. If called with from header
#        it should return a string of form \w+. If called
#        again with this string it should return the original header back.
#        if called on a string without @ which cannot rewritten back it
#        should return undef. If not given a reasonable default will be
#        used.
#     rewrite_crypt: function(data,dir,add2mac) which will encrypt(dir>0) or
#        decrypt(dir<0) data. Optional add2mac is added in MAC. Will return
#        encrypted/decrypted data or undef if decryption failed because
#        MAC did not match
#     nathelper: Net::SIP::NAT::Helper used for rewrite SDP bodies.. (optional)
#     force_rewrite: if true rewrite contact even if incoming and outgoing
#         legs are the same
# Returns: $self
###########################################################################
sub new {
    my ($class,%args) = @_;
    my $self = fields::new( $class );

    my $disp = $self->{dispatcher} =
	delete $args{dispatcher} || croak 'no dispatcher given';
    $self->{rewrite_contact} = delete $args{rewrite_contact} || do {
	my $crypt = $args{rewrite_crypt} || \&_stupid_crypt;
	[ \&_default_rewrite_contact, $crypt, $disp ];
    };
    $self->{nathelper} = delete $args{nathelper};
    $self->{force_rewrite} = delete $args{force_rewrite};

    return $self;
}


# default handler for rewriting, does simple XOR only,
# this is not enough if you need to hide internal addresses
sub _default_rewrite_contact {
    my ($crypt,$disp,$contact,$leg_in,$leg_out,$force_rewrite) = @_;

    my $legdict;
    my ($ileg_in,$ileg_out) = $disp->legs2i($leg_in,$leg_out,\$legdict);

    if ($force_rewrite or $contact =~m{\@}) {
	# needs to be rewritten - incorporate leg_in:leg_out
	$contact = pack("nna*",$ileg_in,$ileg_out,$contact);
	# add 'b' in front so it does not look like phone number
	my $new = 'b'._encode_base32($crypt->($contact,1,$legdict));
	DEBUG( 100,"rewrite $contact -> $new" );
	return $new;
    }

    if ( $contact =~m{^b([A-Z2-7]+)$} ) {
	# needs to be written back
	my $old = $crypt->(_decode_base32($1),-1,$legdict) or do {
	    DEBUG(10,"no rewriting of $contact - bad encryption");
	    return;
	};
	DEBUG(100,"rewrote back $contact -> $old");
	(my $iold_in,my $iold_out,$old) = unpack("nna*",$old);
	if ($ileg_in ne $iold_out) {
	    my ($old_out) = $disp->i2legs($iold_out);
	    if ($leg_in->{contact} ne $old_out->{contact}
		&& ! sip_uri_eq($leg_in->{contact},$old_out->{contact})) {
		DEBUG(10,
		    "no rewriting of %s - went out through %s, came in through %s",
		    $contact, $old_out->{contact}, $leg_in->{contact});
		return;
	    }
	}
	if ( ref($leg_out) eq 'SCALAR' ) {
	    # return the old_in as the new outgoing leg
	    ($$leg_out) = $disp->i2legs($iold_in) or do {
		DEBUG(10,"no rewriting of $contact - cannot find leg $iold_in");
		return;
	    }
	} elsif ($leg_out) {
	    # check that it is the expected leg
	    if ($ileg_out ne $iold_in) {
		my ($old_in) = $disp->i2legs($iold_in);
		if ($leg_out->{contact} ne $old_in->{contact}
		    && ! sip_uri_eq($leg_out->{contact},$old_in->{contact})) {
		    DEBUG(10,
			"no rewriting of %s - went in through %s, should got out through %s",
			$contact, $old_in->{contact}, $leg_out->{contact});
		    return;
		}
	    }
	}
	DEBUG( 100,"rewrite back $contact -> $old" );
	return $old;
    }

    # invalid format
    DEBUG( 100,"no rewriting of $contact" );
    return;
}

{
    # This is only a simple implementation which is in no way cryptographic safe
    # because it does use a broken cipher (RC4), pseudo-random keys and IV only
    # and short keys. Nonetheless, it is probably safe for this purpose and does
    # not depend on non-standard libs, but using openssl bindings might be both
    # more secure and faster for this.
    #
    # RC4 with seed + checksum, picks random key on first use
    # dir: encrypt(1),decrypt(-1), otherwise symmetric w/o seed and checksum
    my (@k,$mackey);
    sub _stupid_crypt {
	my ($in,$dir,$add2mac) = @_;
	$add2mac = '' if ! defined $add2mac;

	if (!@k) {
	    # create random key
	    @k = map { rand(256) } (0..20);
	    $mackey = pack("N",rand(2**32));
	}

	if ($dir>0) {
	    $in = pack("N",rand(2**32)).$in;  # add seed
	} else {
	    # remove checksum and verify it
	    my $cksum = substr($in,-4,4,'');
	    substr(md5($in.$add2mac.$mackey),0,4) eq $cksum
		or return;  # does not match
	}

	# apply RC4 for encryption/decryption
	my $out = '';
	my @s = (0..255);
	my $x = my $y = 0;
	for(0..255) {
	    $y = ( $k[$_%@k] + $s[$x=$_] + $y ) % 256;
	    @s[$x,$y] = @s[$y,$x];
	}
	$x = $y = 0;
	for(unpack('C*',$in)) {
            $x++;
	    $y = ( $s[$x%=256] + $y ) % 256;
	    @s[$x,$y] = @s[$y,$x];
	    $out .= pack('C',$_^=$s[($s[$x]+$s[$y])%256]);
	}

	if ($dir>0) {
	    # add checksum
	    $out .= substr(md5($out.$add2mac.$mackey),0,4);
	} else {
	    substr($out,0,4,'');  # remove seed
	}
	return $out;
    }

    sub _encode_base32 {
	my $data = shift;
	$data = unpack('B*',$data);
	my $text;
	my $padsize =
	$data .= '0' x ((5 - length($data) % 5) % 5); # padding
	$data =~s{(.....)}{000$1}g;
	$data = pack('B*',$data);
	$data =~tr{\000-\037}{A-Z2-7};
	return $data;
    }

    sub _decode_base32 {
	my $data = shift;
	$data =~ tr{A-Z2-7a-z}{\000-\037\000-\031};
	$data = unpack('B*',$data);
	$data =~s{...(.....)}{$1}g;
	$data = substr($data,0,8*int(length($data)/8));
	return pack('B*',$data);
    }
}

###########################################################################
# handle incoming packets
# Args: ($self,$packet,$leg,$from)
#    $packet: Net::SIP::Packet
#    $leg: incoming leg
#    $from: ip:port where packet came from
# Returns: TRUE if packet was fully handled
###########################################################################
sub receive {
    my Net::SIP::StatelessProxy $self = shift;
    my ($packet,$incoming_leg,$from) = @_;
    DEBUG( 10,"received ".$packet->dump );

    # Prepare for forwarding, e.g adjust headers
    # (add record-route)
    if ( my $err = $incoming_leg->forward_incoming( $packet )) {
	my ($code,$text) = @$err;
	DEBUG( 10,"ERROR while forwarding: $code, $text" );
	return;
    }

    my $rewrite_contact = $self->{rewrite_contact};
    my $disp = $self->{dispatcher};

    # find out how to forward packet

    my %entry = (
	packet => $packet,
	incoming_leg => $incoming_leg,
	from => $from,
	outgoing_leg => [],
	dst_addr => [],
	nexthop => undef,
    );

    if ( $packet->is_response ) {
	# find out outgoing leg by checking (and removing) top via
	if ( my ($via) = $packet->get_header( 'via' )) {
	    my ($data,$param) = sip_hdrval2parts( via => $via );
	    my $branch = $param->{branch};
	    if ( $branch ) {
		my @legs = $self->{dispatcher}->get_legs( sub => sub {
		    my $lb = shift->{branch};
		    $lb eq substr($branch,0,length($lb));
		});
		if (@legs) {
		    $entry{outgoing_leg} = \@legs;
		    # remove top via, see Leg::forward_incoming
		    my $via;
		    $packet->scan_header( via => [ sub {
			my ($vref,$hdr) = @_;
			if ( !$$vref ) {
			    $$vref = $hdr->{value};
			    $hdr->remove;
			}
		    }, \$via ]);
		}
	    }
	}

	$self->{respcode} = $packet->code;
	__forward_response( $self, \%entry );

    } else {

	# check if the URI was handled by rewrite_contact
	# this is the case where the Contact-Header was rewritten
	# (see below) and a new request came in using the new
	# contact header. In this case we need to rewrite the URI
	# to reflect the original contact header

	my ($to) = sip_hdrval2parts( uri => $packet->uri );
	$to = $1 if $to =~m{<(\w+:\S+)>};
	if ( my ($pre,$name) = $to =~m{^(sips?:)(\S+)?\@} ) {
	    my $outgoing_leg;
	    if ( my $back = invoke_callback( 
		$rewrite_contact,$name,$incoming_leg,\$outgoing_leg )) {
		$to = $pre.$back;
		DEBUG( 10,"rewrote URI from '%s' back to '%s'", $packet->uri, $to );
		$packet->set_uri( $to );
		$entry{outgoing_leg} = [ $outgoing_leg ] if $outgoing_leg;
	    }
	}

	$self->__forward_request_getleg( \%entry );
    }
}

###########################################################################
# Get destination address from Via: header in response
# Calls __forward_response_1 either directly or after resolving hostname
# of destination to IP
###########################################################################
sub __forward_response {
    my Net::SIP::StatelessProxy $self = shift;
    my $entry = shift;
    my $packet = $entry->{packet};

    # find out where to send packet by parsing the upper via
    # which should contain the addr of the next hop

    my ($via) = $packet->get_header( 'via' ) or do {
	DEBUG( 10,"no via header in packet. DROP" );
	return;
    };
    my ($first,$param) = sip_hdrval2parts( via => $via );
    $first =~m{^SIP/\d\.\d(?:/(\S+))?\s+(.*)};
    my $proto = lc($1) || 'udp';
    my ($host,$port,$family) = ip_string2parts($2);
    my $addr = $family && $host;
    $port ||= $proto eq 'tls' ? 5061 : 5060;
    if (my $alt_addr = $param->{received} || $param->{maddr}) {
	my $alt_fam = ip_is_v46($alt_addr);
	if ($alt_fam) {
	    $addr = $alt_addr;
	    $family = $alt_fam;
	} else {
	    DEBUG(10,"ignoring maddr/received because of invalid IP $alt_addr");
	}
    }
    $port = $param->{rport} if $param->{rport}; # where it came from
    my $nexthop = lock_ref_keys({
	proto  => $proto,
	host   => $host || $addr,
	addr   => $addr,
	port   => $port,
	family => $family
    });
    if ($addr) {
	@{$entry->{dst_addr}} = $nexthop;
	$DEBUG && DEBUG(50, "get dst_addr from via header: %s -> %s",
	    $first, ip_parts2string($nexthop));
	return __forward_response_1($self,$entry);
    }

    return $self->{dispatcher}->resolve_uri(
	sip_sockinfo2uri($nexthop),
	$entry->{dst_addr},
	$entry->{outgoing_leg},
	[ \&__forward_response_1,$self,$entry ],
	undef,
    );
}

###########################################################################
# Called from _forward_response directly or indirectly after resolving
# hostname of destination.
# Calls __forward_packet_final at the end to deliver packet
###########################################################################
sub __forward_response_1 {
    my Net::SIP::StatelessProxy $self = shift;
    my $entry = shift;
    if (@_) {
	$DEBUG && DEBUG( 10,"cannot resolve address %s: @_",
	    ip_parts2string($entry->{dst_addr}[0]));
	return;
    }
    $self->__forward_packet_final($entry);
}


###########################################################################
# Forwards request
# try to find outgoing_leg from Route header
# if there are more Route headers it picks the destination address from next
###########################################################################
sub __forward_request_getleg {
    my Net::SIP::StatelessProxy $self = shift;
    my $entry = shift;

    # if the top route header points to a local leg we use this as outgoing leg
    my @route = $entry->{packet}->get_header('route');
    if ( ! @route ) {
	DEBUG(50,'no route header');
	return $self->__forward_request_getdaddr($entry)
    }

    my $route = $route[0] =~m{<([^\s>]+)>} && $1 || $route[0];
    my $ol = $entry->{outgoing_leg};
    if ( $ol && @$ol ) {
	if ( sip_uri_eq( $route,$ol->[0]{contact})) {
	    DEBUG(50,"first route header matches choosen leg");
	    shift(@route);
	} else {
	    DEBUG(50,"first route header differs from choosen leg");
	}
    } else {
	my ($data,$param) = sip_hdrval2parts( route => $route );
	my ($proto, $addr, $port, $family) =
	    sip_uri2sockinfo($data, $param->{maddr} ? 1:0);
	$port ||= $proto eq 'tls' ? 5061 : 5060;
	my @legs = $self->{dispatcher}->get_legs(
	    addr => $addr, port => $port, family => $family);
	if ( ! @legs and $param->{maddr} ) {
	    @legs = $self->{dispatcher}->get_legs( 
		addr => $param->{maddr}, 
		port => $port 
	    );
	}
	if ( @legs ) {
	    DEBUG( 50,"setting leg from our route header: $data -> ".$legs[0]->dump );
	    $entry->{outgoing_leg} = \@legs;
	    shift(@route);
	} else {
	    DEBUG( 50,"no legs which can deliver to $addr:$port (route)" );
	}
    }
    if ( @route ) {
	# still routing infos. Use next route as nexthop
	my ($data,$param) = sip_hdrval2parts( route => $route[0] );
	$entry->{nexthop} = $data;
	DEBUG(50, "setting nexthop from route $route[0] to $entry->{nexthop}");
    }

    return $self->__forward_request_getdaddr($entry)
}

###########################################################################
# Forwards request
# try to find dst addr
# if it does not have destination address tries to resolve URI and then
# calls __forward_request_1
###########################################################################
sub __forward_request_getdaddr {
    my Net::SIP::StatelessProxy $self = shift;
    my $entry = shift;

    return __forward_request_1( $self,$entry )
	if @{ $entry->{dst_addr}};

    $entry->{nexthop} ||= $entry->{packet}->uri,
    DEBUG(50,"need to resolve $entry->{nexthop}");
    return $self->{dispatcher}->resolve_uri(
	$entry->{nexthop},
	$entry->{dst_addr},
	$entry->{outgoing_leg},
	[ \&__forward_request_1,$self,$entry ],
	undef,
    );
}

###########################################################################
# should have dst_addr now, but this might be still with non-IP hostname
# resolve it and go to __forward_request_2 or directly to __forward_packet_final
###########################################################################
sub __forward_request_1 {
    my Net::SIP::StatelessProxy $self = shift;
    my $entry = shift;

    if (@_) {
	DEBUG(10,"failed to resolve URI %s: @_",$entry->{nexthop});
	return;
    }

    my $dst_addr = $entry->{dst_addr};
    if ( ! @$dst_addr ) {
	DEBUG( 10,"cannot find dst for uri ".$entry->{packet}->uri );
	return;
    }
    my %hostnames;
    foreach (@$dst_addr) {
	ref($_) or Carp::confess("expected reference: $_");
	$hostnames{$_->{host}} = $_->{host} if ! $_->{addr};
    }
    if ( %hostnames ) {
	$self->{dispatcher}->dns_host2ip(
	    \%hostnames,
	    [ \&__forward_request_2,$self,$entry ]
	);
    } else {
	$self->__forward_packet_final($entry);
    }
}


###########################################################################
# called after hostname for destination address got resolved
# calls __forward_packet_final
###########################################################################
sub __forward_request_2 {
    my Net::SIP::StatelessProxy $self = shift;
    my ($entry,$errno,$host2ip) = @_;
    my $dst_addr = $entry->{dst_addr};
    while ( my ($host,$ip) = each %$host2ip ) {
	unless ( $ip ) {
	    DEBUG( 10,"cannot resolve address $host" );
	    @$dst_addr = grep { $_->{host} ne $host } @$dst_addr;
	    next;
	} else {
	    DEBUG( 50,"resolved $host -> $ip" );
	    $_->{addr} = $ip for grep { $_->{host} eq $host } @$dst_addr;
	}
    }

    return unless @$dst_addr; # nothing could be resolved

    $self->__forward_packet_final($entry);
}


###########################################################################
# dst_addr is known and IP
# if no legs given use the one which can deliver to dst_addr
# if there are more than one try to pick best based on protocol
# but finally pick simply the first
# rewrite contact header
# call forward_outgoing on the outgoing_leg
# and finally deliver the packet
###########################################################################
sub __forward_packet_final {
    my ($self,$entry) = @_;

    my $dst_addr = $entry->{dst_addr};
    my $legs = $entry->{outgoing_leg};
    if ( !@$legs == @$dst_addr ) {
	# get legs from dst_addr
	my @all_legs = $self->{dispatcher}->get_legs;
	@$legs = ();
	my @addr;
	foreach my $addr (@$dst_addr) {
	    my $leg = first { $_->can_deliver_to(%$addr) } @all_legs;
	    if ( ! $leg ) {
		DEBUG( 50,"no leg for $addr" );
		next;
	    }
	    push @addr,$addr;
	    push @$legs,$leg
	}
	@$dst_addr = @addr;
	@$legs or do {
	    DEBUG( 10,"cannot find any legs" );
	    return;
	};
    }

    my $incoming_leg = $entry->{incoming_leg};
    if ( @$legs > 1 ) {
	if ( $incoming_leg->{proto} eq 'tcp' ) {
	    # prefer tcp legs
	    my @tcp_legs = grep { $_->{proto} eq 'tcp' } @$legs;
	    @$legs = @tcp_legs if @tcp_legs;
	}
    }

    # pick first
    my $outgoing_leg = $legs->[0];
    $dst_addr = $dst_addr->[0];

    my $packet = $entry->{packet};
    # rewrite contact header if outgoing leg is different to incoming leg
    if ( ( $outgoing_leg != $incoming_leg or $self->{force_rewrite} ) and
	(my @contact = $packet->get_header( 'contact' ))) {

	my $rewrite_contact = $self->{rewrite_contact};
	foreach my $c (@contact) {

	    # rewrite all sip(s) contacts
	    my ($data,$p) = sip_hdrval2parts( contact => $c );
	    my ($pre,$addr,$post) =
		$data =~m{^(.*<sips?:)([^>\s]+)(>.*)}i ? ($1,$2,$3) :
		$data =~m{^(sips?:)([^>\s]+)$}i ? ($1,$2,'') :
		next;

	    # if contact was rewritten rewrite back
	    if ( $addr =~m{^(\w+)(\@.*)} and my $newaddr = invoke_callback( 
		$rewrite_contact,$1,$incoming_leg,$outgoing_leg)) {
		my $cnew = sip_parts2hdrval( 'contact', $pre.$newaddr.$post, $p );
		DEBUG( 50,"rewrote back '$c' to '$cnew'" );
		$c = $cnew;

	    # otherwise rewrite it
	    } else {
		$addr = invoke_callback($rewrite_contact,$addr,$incoming_leg,
		    $outgoing_leg,1);
		$addr .= '@'.$outgoing_leg->laddr(2);
		my $cnew = sip_parts2hdrval( 'contact', $pre.$addr.$post, $p );
		DEBUG( 50,"rewrote '$c' to '$cnew'" );
		$c = $cnew;
	    }
	}
	$packet->set_header( contact => \@contact );
    }

    if ( $outgoing_leg != $incoming_leg and $packet->is_request ) {
	$incoming_leg->add_via($packet);
    }

    # prepare outgoing packet
    if ( my $err = $outgoing_leg->forward_outgoing( $packet,$incoming_leg )) {
	my ($code,$text) = @$err;
	DEBUG( 10,"ERROR while forwarding: ".( defined($code) ? "$code, $text" : $text ));
	return;
    }

    if ( my $err = $self->do_nat( $packet,$incoming_leg,$outgoing_leg ) ) {
	my ($code,$text) = @$err;
	DEBUG( 10,"ERROR while doing NAT: $code, $text" );
	return;
    }

    # Just forward packet via the outgoing_leg
    $self->{dispatcher}->deliver( $packet,
	leg => $outgoing_leg,
	dst_addr => $dst_addr,
	do_retransmits => 0
    );
}

############################################################################
# If a nathelper is given try to rewrite SDP bodies. If this fails
# (not enough resources) just drop packet, the sender will retry later
# (FIXME: this is only true in case of UDP, but not TCP)
#
# Args: ($self,$packet,$incoming_leg,$outgoing_leg)
#  $packet: packet to forward
#  $incoming_leg: where packet came in
#  $outgoing_leg: where packet will be send out
# Returns: $error
#  $error: undef | [ $code,$text ]
############################################################################
sub do_nat {
    my Net::SIP::StatelessProxy $self = shift;
    my ($packet,$incoming_leg,$outgoing_leg) = @_;

    my $nathelper = $self->{nathelper} || do {
	DEBUG( 100, "no nathelper" );
	return;
    };

    # no NAT if outgoing leg is same as incoming leg
    if ( $incoming_leg == $outgoing_leg ) {
	DEBUG( 100,"no NAT because incoming leg is outgoing leg" );
	return;
    }


    my $body = eval { $packet->cseq =~m{\b(?:INVITE|ACK)\b} 
	&& $packet->sdp_body };
    if ( $@ ) {
	DEBUG( 10, "malformed SDP body" );
	return [ 500,"malformed SDP body" ];
    }

    my ($request,$response) = $packet->is_request
	? ( $packet,undef )
	: ( undef,$packet )
	;
    my $method = $request ? $request->method : '';

    # NAT for anything with SDP body
    # activation and close of session will be done on ACK|CANCEL|BYE
    unless ( $body
	or $method eq 'ACK'
	or $method eq 'CANCEL'
	or $method eq 'BYE' ) {
	DEBUG( 100, "no NAT because no SDP body and method is $method" );
	return;
    }


    # find NAT data for packet:
    # $idfrom and $idto are the IDs for FROM|TO which consist of
    # the SIP address + (optional) Tag + Contact-Info from responsable
    # Leg, delimited by "\0"
    my ($idfrom,$idto);

    for([from => \$idfrom], [to => \$idto]) {
	my ($k,$idref) = @$_;
	if (my $v = $packet->get_header($k) ) {
	    my ($uri,$param) = sip_hdrval2parts(from => $v);
	    my ($dom,$user,$proto) = sip_uri2parts($uri);
	    $$idref = "$proto:$user\@$dom\0".($param->{tag} || '');
	} else {
	    return [ 0,'no '.uc($k).' header in packet' ]
	}
    }


    # side is either 0 (request) or 1 (response)
    # If a request comes in 'from' points to the incoming_leg while
    # 'to' points to the outgoing leg. For responses it's the other
    # way around

    my $side;
    my $ileg = $incoming_leg->laddr(1);
    my $oleg = $outgoing_leg->laddr(1);
    if ( $request ) {
	$idfrom .= "\0".$ileg;
	$idto   .= "\0".$oleg;
	$side = 0;
    } else {
	$idfrom .= "\0".$oleg;
	$idto   .= "\0".$ileg;
	$side = 1;
    }

    my ($cseq) = $packet->get_header( 'cseq' ) =~m{^(\d+)}
	or return [ 0,'no CSEQ in packet' ];
    my $callid = $packet->callid;

    # CANCEL|BYE will be handled first to close session
    # no NAT will be done, even if the packet contains SDP (which makes no sense)
    if ( $method eq 'CANCEL' ) {
	# keep cseq for CANCEL
	DEBUG( 50,"close session $callid|$cseq because of CANCEL" );
	$nathelper->close_session( $callid,$cseq,$idfrom,$idto );
	return;
    } elsif ( $method eq 'BYE' ) {
	# no cseq for BYE, eg close all sessions in call
	DEBUG( 50,"close call $callid because of BYE" );
	$nathelper->close_session( $callid,undef,$idfrom,$idto );
	return;
    }

    if ( $body ) {
	DEBUG( 100,"need to NAT SDP body: ".$body->as_string );

	my $new_media = $nathelper->allocate_sockets(
	    $callid,$cseq,$idfrom,$idto,$side,$outgoing_leg->laddr(0),
	    scalar( $body->get_media) );
	if ( ! $new_media ) {
	    DEBUG( 10,"allocation of RTP session failed for $callid|$cseq $idfrom|$idto|$side" );
	    return [ 0,'allocation of RTP sockets failed' ];
	}

	$body->replace_media_listen( $new_media );
	$packet->set_body( $body );
	DEBUG( 100, "new SDP body: ".$body->as_string );
    }

    # Try to activate session as early as possible (for early data).
    # In a lot of cases this will be too early, because I only have one
    # site, but only in the case of ACK an incomplete session is invalid.

    if ( ! $nathelper->activate_session( $callid,$cseq,$idfrom,$idto ) ) {
	if ( $method eq 'ACK' ) {
	    if ($self->{respcode} < 400) {
		DEBUG( 50,"session $callid|$cseq $idfrom -> $idto still incomplete in ACK" );
		return [ 0,'incomplete session in ACK' ]
	    } else {
		# ignore problem, ACK to response with error code
		DEBUG( 100, "session $callid|$cseq $idfrom -> ACK to failure response" );
	    }
	} else {
	    # ignore problem, session not yet complete
	    DEBUG( 100, "session $callid|$cseq $idfrom -> $idto not yet complete" );
	}
    } else {
	DEBUG( 50,"activated session $callid|$cseq $idfrom -> $idto" )
    }

    return;
}

############################################################################
# convert idside (idfrom,idto) to hash
# Args: ?$class,$idside
# Returns: \%hash
#  %hash: extracted info with keys address (sip address), tag, leg (ip:port)
############################################################################
sub idside2hash {
    my $idside = pop;
    my %hash;
    @hash{qw/ address tag leg /} = split( "\0",$idside,3 );
    return \%hash;
}


1;
