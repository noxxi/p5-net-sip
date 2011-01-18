
=head1 NAME

Net::SIP::Dropper - drops SIP messages based on callback

=head1 SYNOPSIS

	use Net::SIP::Dropper::ByIpPort;
	my $drop_by_ipport = Net::SIP::Dropper::ByIpPort->new(
		database => '/path/to/database.drop',
		methods => [ 'REGISTER', '...', '' ],
		attempts => 10,
		interval => 60,
	);

	use Net::SIP::Dropper::ByField;
	my $drop_by_field = Net::SIP::Dropper::ByField->new(
		methods => [ 'REGISTER', '...', '' ],
		'From' => qr/sip(?:vicious|sscuser)/,
		'User-Agent' => qr/^friendly-scanner$/,
	);

	my $drop_subscribe = sub {
		my ($packet,$leg,$from) = @_;
		# drop all subscribe requests and responses
		return $packet->method eq 'SUBSCRIBE' ? 1:0;
	};

	my $dropper = Net::SIP::Dropper->new(
		cbs => [ $drop_by_ipport, $drop_by_field, $drop_subscribe ]);

	my $chain = Net::SIP::ReceiveChain->new(
		[ $dropper, ... ]
	);

=head1 DESCRIPTION

Drops messages. This means, does no further processing in the Net::SIP chain
and does not send something back if the incoming message match the
settings.

Some useful droppers are defined in L<Net::SIP::Dropper::ByIpPort> and
L<Net::SIP::Dropper::ByField>.

=head1 CONSTRUCTOR

=over 4

=item new ( ARGS )

ARGS is a hash with key C<cb> I<or> C<cbs>. C<cb> is a single callback to be
processed, C<cbs> is an arrayref with callbacks. If one of the callbacks returns
true the message will be dropped. If all callbacks return false the message will
be forwarded in the chain.

Returns a new dropper object to be used in the chain.


=back

=cut

use strict;
use warnings;

package Net::SIP::Dropper;

use fields qw( cbs );
use Carp 'croak';
use Net::SIP::Util qw( invoke_callback );


################################################################################
# creates new Dropper object
# Args: ($class,%args)
#   %args:
#     One of cb or cbs must be set.
#     cb:  A single callback. Will be ignored if cbs is also set.
#     cbs: An arrayref with callbacks.
# Returns: Net::SIP::Dropper object
################################################################################
sub new {
    my ($class, %args) = @_;
    my Net::SIP::Dropper $self = fields::new($class);

    croak('argument cb or cbs must exist') unless $args{cb} || $args{cbs};
    $self->{cbs} = $args{cbs} || [ $args{cb} ];
    return $self;
}


################################################################################
# Drops SIP-messages excluded by the settings
# Args: ($self,$packet,$leg,$from)
#   args as usual for sub receive
# Returns: 1 (stop chain) | <undef> (proceed in chain)
################################################################################
sub receive {
    my Net::SIP::Dropper $self = shift;
    my ($packet, $leg, $from) = @_;

    for (@{ $self->{cbs} }) {
		return 1 if invoke_callback($_, $packet, $leg, $from);
    }
    return;
}



1;
