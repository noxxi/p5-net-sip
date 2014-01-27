###########################################################################
# package Net::SIP::ReceiveChain
# used to put Authorize, Registrar, StatelessProxy etc together so that
# the object first in chain will try to handle the packets first and
# pass them only to the next object if it was not fully handled by the
# previous object
# each object in chain returns TRUE from method receive if it handled
# the packet fully
###########################################################################

use strict;
use warnings;

package Net::SIP::ReceiveChain;
use fields qw( objects filter );
use Net::SIP::Util 'invoke_callback';

###########################################################################
# creates new ReceiveChain object
# Args: ($class,$objects,%args)
#   $objects: \@list of objects which it should put in the chain
#   %args:
#      filter: callback invoked on each packet to find out if it should
#         be processed by this chain
#      methods: \@list of methods, used if no filter is given
# Returns: $self
###########################################################################
sub new {
    my ($class,$objects,%args) = @_;
    my $self = fields::new( $class );
    if ( ! ( $self->{filter} = $args{filter} )) {
	if ( my $m = $args{methods} ) {
	    # predefined filter to filter based on method
	    my %m = map { $_ => 1 } @$m;
	    my $method_filter = sub {
		my ($hm,$packet) = @_;
		return $hm->{ $packet->method }
	    };
	    $self->{filter} = [ $method_filter, \%m ];
	}
    }
    $self->{objects} = $objects;
    return $self;
}

###########################################################################
# handle packet, called from Net::SIP::Dispatcher on incoming requests
# Args: ($self,$packet,$leg,$addr)
#  $packet: Net::SIP::Packet
#  $leg: Net::SIP::Leg where request came in (and response gets send out)
#  $addr: ip:port where request came from and response will be send
# Returns: TRUE if it handled the packet
###########################################################################
sub receive {
    my Net::SIP::ReceiveChain $self = shift;
    my ($packet,$leg,$addr) = @_;

    if ( my $f = $self->{filter} ) {
	# check if packet should be handled by filter
	return if ! invoke_callback($f,$packet,$leg,$addr);
    }
    foreach my $object (@{ $self->{objects} }) {
	my $handled = $object->receive($packet,$leg,$addr);
	return $handled if $handled;
    }
    return; # not handled
}

1;
