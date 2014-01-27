
=head1 NAME

Net::SIP::Dropper::ByField - drops SIP messages based on fields in SIP header

=head1 SYNOPSIS

    my $drop_by_field = Net::SIP::Dropper::ByField->new(
	methods => [ 'REGISTER', '...', '' ],
	'From' => qr/sip(?:vicious|sscuser)/,
	'User-Agent' => qr/^friendly-scanner$/,
    );

    my $dropper = Net::SIP::Dropper->new( cb => $drop_by_field );
    my $chain = Net::SIP::ReceiveChain->new([ $dropper, ... ]);

=head1 DESCRIPTION

With C<Net::SIP::Dropper::ByField> one can drop packets based on the contents of
the fields in the SIP header. This can be used to drop specific user agents.

=cut


use strict;
use warnings;

package Net::SIP::Dropper::ByField;
use Net::SIP::Util 'invoke_callback';
use Net::SIP::Debug;
use fields qw(fields methods);

=head1 CONSTRUCTOR

=over 4

=item new ( ARGS )

ARGS is a hash with the following keys:

=over 8

=item methods

Optional argument to restrict dropping to specific methods.

Is array reference of method names, if one of the names is empty also responses
will be considered. If not given all packets will be checked.

=item field-name

Any argument other then C<methods> will be considered a field name.
The value is a callback given to C<invoke_callback>, like for instance a Regexp.

=back

=back

=cut

sub new {
    my ($class,%fields) = @_;
    my $methods  = delete $fields{methods}; # optional

    # initialize object
    my Net::SIP::Dropper::ByField $self = fields::new($class);
    $self->{methods} = $methods;
    $self->{fields} = [ map { ($_,$fields{$_}) } keys %fields ];

    return $self
}

=head1 METHODS

=over 4

=item run ( PACKET, LEG, FROM )

This method is called as a callback from the L<Net::SIP::Dropper> object.
It returns true if the packet should be dropped, e.g. if at least one
of the in the constructor specified fields matches the specified value.

=back

=cut

sub run {
    my Net::SIP::Dropper::ByField $self = shift;
    my ($packet,$leg,$from) = @_;

    # check if the packet type/method fits
    if (my $m = $self->{methods}) {
	if ($packet->is_response) {
	    return if ! grep { !$_ } @$m
	} else {
	    my $met = $packet->method;
	    return if ! grep { $_ eq $met } @$m
	}
    };

    my $f = $self->{fields};
    for(my $i=0;$i<@$f;$i+=2) {
	my @v = $packet->get_header($f->[$i]) or next;
	if ( invoke_callback( $f->[$i+1],@v) ) {
	    DEBUG(1,"message dropped because of header field <$f->[$i]> =~ ".$f->[$i+1]);
	    return 1;
	}
    }
    return;
}

1;
