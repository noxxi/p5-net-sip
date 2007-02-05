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
	return @expired;
}

sub allocate_sockets {
	my Net::SIP::NATHelper::Local $self = shift;
	my $media = $self->{helper}->allocate_sockets(@_) || return;
	#$self->_update_callbacks;
	return $media
}

sub activate_session {
	my Net::SIP::NATHelper::Local $self = shift;
	my $success = $self->{helper}->activate_session(@_) || return;
	$self->_update_callbacks;
	return $success;
}

sub close_session {
	my Net::SIP::NATHelper::Local $self = shift;
	my @bytes = $self->{helper}->close_session(@_) or return;
	$self->_update_callbacks;
	return @bytes;
}

sub _update_callbacks {
	my Net::SIP::NATHelper::Local $self = shift;
	my @cb = $self->{helper}->callbacks;
	my $cb_old = $self->{callbacks};

	# FIXME: this should be optimized so that only the changes gets done
	my $loop = $self->{loop};
	DEBUG( 100, "oldcb=%d newcb=%d", int(@$cb_old),int(@cb) );
	map { $loop->delFD( $_->[0] ) } @$cb_old;
	map { $loop->addFD( $_->[0],$_->[1] ) } @cb;
}

1;
