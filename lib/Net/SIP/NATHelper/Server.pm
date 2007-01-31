use strict;
use warnings;

############################################################################
#
#   wrap Net::SIP::NATHelper::Base
#   read commands from socket and propagete them to NATHelper, send
#   replies back
#
# FIXME: integrate into other eventloops, do not build own
############################################################################

package Net::SIP::NATHelper::Server;
use Net::SIP;
use Net::SIP::Debug;
use Net::SIP::Util 'invoke_callback';
use Storable qw(thaw nfreeze);
use Data::Dumper;


############################################################################
# new NAThelper
# Args: ($class,@socket)
#  @socket: SOCK_STREAM sockets for communication SIP proxies
# Returns: $self
############################################################################
sub new {
	my ($class,@cfd) = @_;
	my $helper = Net::SIP::NATHelper::Base->new;
	return bless {
		helper => $helper,
		callbacks => [],
		cfd => \@cfd,
	},$class;
}

############################################################################
# read + execute command
# command is transported as [ $cmd,@args ] using Storable::nfreeze
# and reply is transported back using nfreeze too
# Args: $self
# Returns: NONE
############################################################################
sub do_command {
	my Net::SIP::NATHelper::Server $self = shift;
	my $cfd = shift;

	my $sock = $cfd->accept || do {
		DEBUG( 50,"accept failed: $!" );
		return;
	};
	$sock->autoflush;

	read( $sock,my $buf, 4 ) || do {
		DEBUG( 50, "read of 4 bytes len failed: $!" );
		return;
	};
	my $len = unpack( "N",$buf );
	DEBUG( 50, "len=$len" );
	if ( $len > 32768 ) {
		warn( "tooo much data to read, unbelievable len=$len" );
		return;
	}
	read( $sock,$buf, $len ) || do {
		DEBUG( 50,"read of $len bytes failed: $!" );
		return;
	};

	my ($cmd,@args) = eval { @{ thaw( $buf ) } } or do {
		DEBUG( 50,"thaw failed: $@" );
		return;
	};

	DEBUG( 100, "request=".Dumper([$cmd,@args]));
	my $reply =
		$cmd eq 'allocate' ? $self->allocate_sockets(@args) :
		$cmd eq 'activate' ? $self->activate_session(@args) :
		$cmd eq 'close'    ? $self->close_session(@args)    :
		do {
			DEBUG( 10,"unknown command: $cmd" );
			return;
		}
		;
	unless ( defined( $reply )) {
		DEBUG( 10, "no reply for $cmd" );
	}

	DEBUG( 100, "reply=".Dumper($reply));

	# nfreeze needs reference!
	print $sock pack( "N/a*",nfreeze(\$reply));
	close($sock);
}


############################################################################
# loop:
# * if received new command execute it
# * if receive data on RTP sockets forward them
# Args: $self
# Returns: NEVER
############################################################################
sub loop {
	my Net::SIP::NATHelper::Server $self = shift;

	my $rin; # select mask
	my $last_expire = 0;
	my $helper = $self->{helper};

	while (1) {

		# @$callbacks get set to empty in _update_callbacks which get
		# called if something on the sockets changed. In this case
		# recompute the callbacks. This is not the fastest method, but
		# easy to understand :)

		my $callbacks = $self->{callbacks};
		my $timeout = 1;
		if ( !@$callbacks ) {
			# recompute callbacks:
			# - add callbacks from NATHelper
			foreach ( $helper->callbacks ) {
				my ($fd,$cb) = @$_;
				$callbacks->[ fileno($fd) ] = $cb;
			}

			# if nothing to do on helper set timeout to infinite
			if ( !@$callbacks && ! $helper->number_of_calls ) {
				$timeout = undef;
				DEBUG( 50,"no RTP socks: set timeout to infinite" );
			}

			# - and for command sockets
			foreach my $cfd ( @{ $self->{cfd} } ) {
				$callbacks->[ fileno($cfd) ] = [ \&do_command, $self,$cfd ];
			}

			# recompute select mask
			$rin = '';
			for( my $i=0;$i<@$callbacks;$i++ ) {
				vec( $rin,$i,1 ) = 1 if $callbacks->[$i]
			}

		}

		# select which sockets got readable or timeout
		$rin || die;
		defined( select( my $rout = $rin,undef,undef,$timeout ) ) || die $!;
		my $now = time();

		# handle callbacks on sockets
		if ( $rout ) {
			for( my $i=0;$i<@$callbacks;$i++ ) {
				invoke_callback( $callbacks->[$i] ) if vec( $rout,$i,1 );
			}
		}

		# handle expires
		if ( $now - $last_expire >= 1 ) {
			$last_expire = $now;
			$self->expire;
			DEBUG( 100, $helper->dump );
		}
	}
}

############################################################################
# wrap methods in helper to call _update_callbacks when appropriate
############################################################################
sub expire {
	my Net::SIP::NATHelper::Server $self = shift;
	my $changed = $self->{helper}->expire;
	$changed && $self->_update_callbacks;
	return $changed;
}

sub allocate_sockets {
	my Net::SIP::NATHelper::Server $self = shift;
	my $media = $self->{helper}->allocate_sockets(@_) || return;
	#$self->_update_callbacks;
	return $media
}

sub activate_session {
	my Net::SIP::NATHelper::Server $self = shift;
	my $success = $self->{helper}->activate_session(@_) || return;
	$self->_update_callbacks;
	return $success;
}

sub close_session {
	my Net::SIP::NATHelper::Server $self = shift;
	my $success = $self->{helper}->close_session(@_) || return;
	$self->_update_callbacks;
	return $success;
}


sub _update_callbacks {
	my Net::SIP::NATHelper::Server $self = shift;
	@{ $self->{callbacks} } = ();
}

1;
