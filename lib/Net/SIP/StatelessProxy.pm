###########################################################################
# Net::SIP::StatelessProxy
# implements a simple stateless proxy
# all packets will be forwarded between Leg#1 to Leg#2. If there is
# only one leg it will use only this leg.
###########################################################################

use strict;
use warnings;

package Net::SIP::StatelessProxy;
use fields qw( dispatcher rewrite_contact nathelper force_rewrite );

use Net::SIP::Util ':all';
use Digest::MD5 'md5_hex';
use Carp 'croak';
use List::Util 'first';
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
	$self->{rewrite_contact} = delete $args{rewrite_contact}
		|| [ \&_default_rewrite_contact, $self ];
	$self->{nathelper} = delete $args{nathelper};
	$self->{force_rewrite} = delete $args{force_rewrite};

	return $self;
}

# default handler for rewriting, does simple XOR only,
# this is not enough if you need to hide internal addresses
sub _default_rewrite_contact {
	my ($self,$contact) = @_;
	my $secret = md5_hex(
		sort { $a cmp $b }
		map { $_->{proto}.':'.$_->{addr}.':'.$_->{port} }
		$self->{dispatcher}->get_legs
	);

	my $new;
	if ( $contact =~m{\@} ) {
		# needs to be rewritten
		$contact .= "MARKER";
		my $lc = length($contact);
		$secret = substr( $secret x int( $lc/length($secret) +1 ), 0,$lc );
		# add 'r' in front of hex so it does not look like phone number
		$new = 'r'.unpack( 'H*',( $contact ^ $secret ));
		DEBUG( 100,"rewrite $contact -> $new" );
	} elsif ( $contact =~m{^r([0-9a-f]+)$}i ) {
		# needs to be written back
		$new = pack( 'H*',$1 );
		my $lc = length($new);
		$secret = substr( $secret x int( $lc/length($secret) +1 ), 0,$lc );
		$new = $new ^ $secret;
		$new =~s{MARKER$}{} || return;
		DEBUG( 100,"rewrite back $contact -> $new" );
	} else {
		# invalid format
		DEBUG( 100,"no rewriting of $contact" );
	}
	return $new;
}

###########################################################################
# handle incoming requests
# Args: ($self,$packet,$leg,$from)
#    $packet: Net::SIP::Request
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

		__forward_response( $self, \%entry );

	} else {

		# check if the URI was handled by rewrite_contact
		# this is the case where the Contact-Header was rewritten
		# (see below) and a new request came in using the new
		# contact header. In this case we need to rewrite the URI
		# to reflect the original contact header

		my ($to) = sip_hdrval2parts( uri => $packet->uri );
		$to = $1 if $to =~m{<(\w+:\S+)>};
		my ($pre,$name) = $to =~m{^(sips?:)(\S+)?\@};
		if ( $name && ( my $back = invoke_callback( $rewrite_contact,$name ) )) {
			$to = $pre.$back;
			DEBUG( 10,"rewrote URI from '%s' back to '%s'", $packet->uri, $to );
			$packet->set_uri( $to )
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
	my ($addr,$port) = $first =~m{([\w\-\.]+)(?::(\d+))?\s*$};
	$port ||= 5060; # FIXME default for sip, not sips!
	$addr = $param->{maddr} if $param->{maddr};
	$addr = $param->{received} if $param->{received}; # where it came from
	$port = $param->{rport} if $param->{rport}; # where it came from
	@{ $entry->{dst_addr}} = ( "$addr:$port" );
	DEBUG( 50,"get dst_addr from via header: $first -> $addr:$port" );

	if ( $addr !~m{^[0-9\.]+$} ) {
		$self->{dispatcher}->dns_host2ip(
			$addr,
			[ \&__forward_response_1,$self,$entry ]
		);
	} else {
		__forward_response_1($self,$entry);
	}
}

###########################################################################
# Called from _forward_response directly or indirectly after resolving
# hostname of destination.
# Calls __forward_packet_final at the end to deliver packet
###########################################################################
sub __forward_response_1 {
	my Net::SIP::StatelessProxy $self = shift;
	my $entry = shift;
	if ( @_ ) {
		my ($errno,$ip) = @_;
		unless ( $ip ) {
			DEBUG( 10,"cannot resolve address $entry->{dst_addr}[0]" );
			return;
		}
		# replace host part in dst_addr with ip
		$entry->{dst_addr}[0] =~s{^(udp:|tcp:)?([^:]+)}{$1$ip};
	}

	__forward_packet_final( $self,$entry );
}


###########################################################################
# Forwards request
# try to find outgoing_leg from Route header
# if there are more Route headers it picks the destination address from next
###########################################################################
sub __forward_request_getleg {
	my Net::SIP::StatelessProxy $self = shift;
	my $entry = shift;
	return $self->__forward_request_getdaddr($entry)
		if @{$entry->{outgoing_leg}};

	my $packet = $entry->{packet};
	my $disp = $self->{dispatcher};

	# if the top route header points to a local leg we use this as outgoing leg
	if ( my @route = $packet->get_header( 'route' ) ) {
		$route[0] =~s{.*<}{} && $route[0] =~s{>.*}{};
		my ($data,$param) = sip_hdrval2parts( route => $route[0] );
		my ($addr,$port) = $data =~m{([\w\-\.]+)(?::(\d+))?\s*$};
		$port ||= 5060; # FIXME sips
		my @legs = $disp->get_legs( addr => $addr, port => $port );
		if ( ! @legs ) {
			$addr = $param->{maddr} if $param->{maddr};
			@legs = $disp->get_legs( addr => $addr, port => $port );
		}
		if ( @legs ) {
			DEBUG( 50,"setting leg from our route header: $data -> ".$legs[0]->dump );
			$entry->{outgoing_leg} = \@legs;
			shift(@route);
		} else {
			DEBUG( 50,"no legs which can deliver to $addr:$port (route)" );
		}
		if ( @route ) {
			# still routing infos. Use next route as dst_addr
			$route[0] =~s{.*<}{} && $route[0] =~s{>.*}{};
			my ($data,$param) = sip_hdrval2parts( route => $route[0] );
			my ($addr,$port) = $data =~m{([\w\-\.]+)(?::(\d+))?\s*$};
			$port ||= 5060; # FIXME sips
			if ( my $m = $param->{maddr} ) {
				$addr = $m;
				DEBUG( 50, "setting dst_addr from route $data;maddr=$m to $addr:$port" );
			} else {
				DEBUG( 50, "setting dst_addr from route $data to $addr:$port" );
			}
			@{ $entry->{dst_addr} } = ( "$addr:$port" );
		}
	} else {
		DEBUG( 50,'no route header' );
	}

	$self->__forward_request_getdaddr($entry);
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
		if @{ $entry->{dst_addr}};;

	my $proto = $entry->{incoming_leg}{proto} eq 'tcp' ? [ 'tcp','udp' ]:undef;
	my $packet = $entry->{packet};
	my $disp = $self->{dispatcher};
	DEBUG( 50,"need to resolve ".$packet->uri." proto=".( $proto ||'') );
	return $disp->resolve_uri(
		$packet->uri,
		$entry->{dst_addr},
		$entry->{outgoing_leg},
		[ \&__forward_request_1,$self,$entry ],
		$proto,
	);
}

###########################################################################
# should have dst_addr now, but this might be still with non-IP hostname
# resolve it and go to __forward_request_2 or directly to __forward_packet_final
###########################################################################
sub __forward_request_1 {
	my Net::SIP::StatelessProxy $self = shift;
	my $entry = shift;

	my $dst_addr = $entry->{dst_addr};
	if ( ! @$dst_addr ) {
		DEBUG( 10,"cannot find dst for uri ".$entry->{packet}->uri );
		return;
	}
	my %hostnames;
	foreach (@$dst_addr) {
		my ($addr) = m{^(?:udp:|tcp:)?([^:]+)};
		$hostnames{$addr} = undef if $addr !~m{^[0-9\.]+$};
	}
	if ( %hostnames ) {
		$self->{dispatcher}->dns_host2ip(
			\%hostnames,
			[ \&__forward_request_2,$self,$entry ]
		);
	} else {
		__forward_packet_final($self,$entry);
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
			@$dst_addr = grep { !m{^(?:\w*:)?\Q$host\E(?::)?} } @$dst_addr;
			next;
		} else {
			DEBUG( 50,"resolved $host -> $ip" );
			s{^(\w*:)?\Q$host\E(:)?}{$1$ip$2} for (@$dst_addr);
		}
	}

	return unless @$dst_addr; # nothing could be resolved

	__forward_packet_final( $self,$entry );
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
			my $leg = first { $_->can_deliver_to( $addr ) } @all_legs;
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
			if ( $addr =~m{^(\w+)(\@.*)} &&
				( my $back = $1 && invoke_callback($rewrite_contact,$1))) {
				$addr = $back;
				my $cnew = sip_parts2hdrval( 'contact', $pre.$addr.$post, $p );
				DEBUG( 50,"rewrote back '$c' to '$cnew'" );
				$c = $cnew;

			# otherwise rewrite it
			} else {
				$addr = invoke_callback( $rewrite_contact,$addr);
				$addr .= '@'.$outgoing_leg->{addr}.':'.$outgoing_leg->{port};
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


	my $body = eval { $packet->sdp_body };
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

	if ( my $from = $packet->get_header( 'from' ) ) {
		my ($data,$param) = sip_hdrval2parts( from => $from );
		my $tag = $param->{tag} || '';
		$idfrom = "$data\0$tag";
	} else {
		return [ 0,'no FROM header in packet' ]
	}

	if ( my $to = $packet->get_header( 'to' ) ) {
		my ($data,$param) = sip_hdrval2parts( from => $to );
		my $tag = $param->{tag} || '';
		$idto = "$data\0$tag";
	} else {
		return [ 0,'no TO header in packet' ]
	}

	# side is either 0 (request) or 1 (response)
	# If a request comes in 'from' points to the incoming_leg while
	# 'to' points to the outgoing leg. For responses it's the other
	# way around

	my $side;
	my $ileg = join( ':', @{ $incoming_leg }{qw(addr port)} );
	my $oleg = join( ':', @{ $outgoing_leg }{qw(addr port)} );
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
			$callid,$cseq,$idfrom,$idto,$side,$outgoing_leg->{addr},
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
			DEBUG( 50,"session $callid|$cseq $idfrom -> $idto still incomplete in ACK" );
			return [ 0,'incomplete session in ACK' ]
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
