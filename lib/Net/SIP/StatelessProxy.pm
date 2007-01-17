###########################################################################
# Net::SIP::StatelessProxy
# implements a simple stateless proxy
# all packets will be forwarded between Leg#1 to Leg#2. If there is
# only one leg it will use only this leg.
# FIXME: there is no support yet for more than one legs, eg it needs
#   to know which leg to use as outgoing leg
###########################################################################

use strict;
use warnings;

package Net::SIP::StatelessProxy;
use fields qw( dispatcher registrar rewrite_contact );

use Net::SIP::Util ':all';
use Net::SIP::Registrar;
use Digest::MD5 'md5_hex';
use Carp 'croak';
use List::Util 'first';
use Net::SIP::Debug;

###########################################################################
# creates new stateless proxy
# Args: ($class,%args)
#   %args
#     dispatcher: the Net::SIP::Dispatcher object managing the proxy
#     registrar: \%hash with args for Net::SIP::Registrar
#        if registrar is given it will try to handle all REGISTER
#        requests using the registrar and fall back to the normal
#        behavior if registrar cannot handle the request.
#        can also be an existing Net::SIP::Registrar object
#     rewrite_contact: callback to rewrite contact header. If called with from header
#        it should return a string of form \w+. If called
#        again with this string it should return the original header back.
#        if called on a string without @ which cannot rewritten back it
#        should return undef. If not given a reasonable default will be
#        used.
# Returns: $self
###########################################################################
sub new {
	my ($class,%args) = @_;
	my $self = fields::new( $class );

	my $disp = $self->{dispatcher} = 
		delete $args{dispatcher} || croak 'no dispatcher given';
	if ( my $r = delete $args{registrar} ) {
		if ( UNIVERSAL::can( $r,'receive' )) {
			$self->{registrar} = $r;
		} else {
			$self->{registrar} = Net::SIP::Registrar->new(
				dispatcher => $disp,
				%$r
			);
		}
	}
	$self->{rewrite_contact} ||= [ \&_default_rewrite_contact, $self ];

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
		$new = unpack( 'H*',( $contact ^ $secret ));
		DEBUG( 50,"rewrite $contact -> $new" );
	} elsif ( $contact =~m{^[0-9a-f]+$} ) {
		# needs to be written back
		$new = pack( 'H*',$contact );
		my $lc = length($new);
		$secret = substr( $secret x int( $lc/length($secret) +1 ), 0,$lc );
		$new = $new ^ $secret;
		DEBUG( 50,"rewrite back $contact -> $new" );
		$new =~s{MARKER$}{} || return;
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
# Returns: bool
#    true if successfully handeled, false if not handled
###########################################################################
sub receive {
	my ($self,$packet,$incoming_leg,$from) = @_;
	DEBUG( 10,"received ".$packet->dump );

	if ( ( my $reg = $self->{registrar} ) 
		and $packet->is_request
		and $packet->method eq 'REGISTER' ) {
		# try to handle by builtin registrar
		# this might fail if it is not responsable for domain
		$reg->receive( $packet,$incoming_leg,$from ) 
			&& return;
	}

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
	my $dst_addr;
	if ( $packet->is_response ) {
		# find out where to send packet by parsing the upper via
		# which should contain the addr of the next hop

		my ($via) = $packet->get_header( 'via' ) or do {
			DEBUG( 10,"no via header in packet. DROP" );
			return;
		};
		my ($first,$param) = sip_hdrval2parts( via => $via );
		my ($addr,$port) = $first =~m{([\w\-\.]+)(?::(\d+))?\s*$};
		$port ||= 5060; # FIXME default for sip, not sips!
		$dst_addr = "$addr:$port";
		DEBUG( 100,"get dst_addr from header: $first -> $dst_addr" );

	} else {
		# check if the URI was handled by rewrite_contact
		# this is the case where the Contact-Header was rewritten
		# (see below) and a new request came in using the new
		# contact header. In this case we need to rewrite the URI
		# to reflect the original contact header

		my ($to) = sip_hdrval2parts( uri => $packet->uri );
		$to = $1 if $to =~m{<(\w+:\S+)>};
		if ( $to =~m{^(.*?)(\w+)(\@.*)} 
			&& ( my $back = invoke_callback( $rewrite_contact,$2 ) )) {
			$to = $1.$back;
			DEBUG( 10,"rewrote URI from '%s' to '%s'", $packet->uri, $to );
			$packet->set_uri( $to )
		}
	}

	# FIXME: if it's a response use $param->{received} to find out 
	# the leg through which the request got send
	# instead of simply using the other leg
	my $outgoing_leg = first { $_ != $incoming_leg } $disp->get_legs;
	$outgoing_leg ||= $incoming_leg; # if only one leg is used

	# rewrite contact header
	if ( my @contact = $packet->get_header( 'contact' ) ) {

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

	# prepare outgoing packet
	if ( my $err = $outgoing_leg->forward_outgoing( $packet,$incoming_leg )) {
		my ($code,$text) = @$err;
		DEBUG( 10,"ERROR while forwarding: $code, $text" );
		return;
	}

	# Just forward packet via the outgoing_leg
	$disp->deliver( $packet, 
		leg => $outgoing_leg, 
		dst_addr => $dst_addr, 
		do_retransmits => 0 
	);
}

1;
