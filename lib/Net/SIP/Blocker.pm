###########################################################################
# package Net::SIP::Blocker
###########################################################################

use strict;
use warnings;


package Net::SIP::Blocker;

use fields qw( dispatcher block );
use Carp 'croak';
use Net::SIP::Debug;


###########################################################################
# creates new Blocker object
# Args: ($class,%args)
#   %args
#     block: \%hash where the blocked method is the key and its value
#       is a number with three digits with optional message
#       e.g. { 'SUBSCRIBE' => 405 }
#     dispatcher: the Net::SIP::Dispatcher object
# Returns: $self
###########################################################################
sub new {
	my ($class,%args) = @_;
	my $self = fields::new( $class );

	my $map = delete $args{block}
		or croak("no mapping between method and code");
	while (my ($method,$code) = each %$map) {
		$method = uc($method);
		($code, my $msg) = $code =~m{^(\d\d\d)(?:\s+(.+))?$} or
			croak("block code for $method must be DDD [text]");
		$self->{block}{$method} = defined($msg) ? [$code,$msg]:[$code];
	}

	$self->{dispatcher} = delete $args{dispatcher}
		or croak('no dispatcher given');

	return $self;
}


###########################################################################
# Blocks methods not wanted and sends a response back over the same leg
# with the Error-Message of the block_code
# Args: ($self,$packet,$leg,$from)
#   args as usual for sub receive
# Returns: block_code | NONE
###########################################################################
sub receive {
	my Net::SIP::Blocker $self = shift;
	my ($packet,$leg,$from) = @_;

	$packet->is_request or return;

	my $method = $packet->method;
	if ( $method eq 'ACK' && $self->{block}{INVITE} ) {
		return $self->{dispatcher}->cancel_delivery($packet->tid);
	}

	my $block = $self->{block}{$method} or return;

	DEBUG( 10,"block $method with code @$block" );
	$self->{dispatcher}->deliver(
		$packet->create_response(@$block),
		leg => $leg,
		dst_addr => $from
	);
	return $block->[0]
}

1;
