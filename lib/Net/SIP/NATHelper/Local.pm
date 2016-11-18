use strict;
use warnings;

############################################################################
#
#   Net::SIP::NATHelper::Local
#   wrapper around Net::SIP::NATHelper::Base to integrate into local mainloop
#
############################################################################

package Net::SIP::NATHelper::Local;
use Net::SIP::Debug;
use Net::SIP::NATHelper::Base;
use Net::SIP::Dispatcher::Eventloop;
use fields qw( helper loop callbacks );

sub new {
    my ($class,$loop) = @_;
    my $self = fields::new($class);
    my $helper = Net::SIP::NATHelper::Base->new;
    %$self = ( loop => $loop, helper => $helper, callbacks => [] );
    $loop->add_timer( 1, [ sub { shift->expire },$self ], 1, 'nat_expire' );
    return $self;
}

sub expire {
    my Net::SIP::NATHelper::Local $self = shift;
    my @expired = $self->{helper}->expire(@_);
    @expired && $self->_update_callbacks;
    return int(@expired);
}

sub allocate_sockets {
    my Net::SIP::NATHelper::Local $self = shift;
    my $media = $self->{helper}->allocate_sockets(@_) || return;
    #$self->_update_callbacks;
    return $media;
}

sub activate_session {
    my Net::SIP::NATHelper::Local $self = shift;
    my ($info,$duplicate) = $self->{helper}->activate_session(@_)
	or return;
    $self->_update_callbacks;
    return $duplicate ? -1:1;
}

sub close_session {
    my Net::SIP::NATHelper::Local $self = shift;
    my @info = $self->{helper}->close_session(@_) or return;
    $self->_update_callbacks;
    return scalar(@info);
}

sub _update_callbacks {
    my Net::SIP::NATHelper::Local $self = shift;
    my $cb_old = $self->{callbacks};
    my @cb_new = $self->{helper}->callbacks;
    $self->{callbacks} = \@cb_new;

    # hash by cbid for old callbacks
    my %old = map { $_->[2] => $_ } @{ $cb_old || [] };

    my $loop = $self->{loop};
    foreach my $cb ( @cb_new ) {
	my ($socket,$callback,$id) = @$cb;
	if ( delete $old{ $id } ) {
	    # unchanged
	} else {
	    # new callback
	    $loop->addFD($socket, EV_READ, $callback)
	}
    }
    # delete unused callbacks
    map { $loop->delFD( $_->[0] ) } values %old;
}

1;
