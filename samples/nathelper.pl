############################################################################
# 
#  Standalone nathelper which can be used with SIP proxy
#  for transferring RTP data between networks/through a firewall..
#
#  Communication is via sock_stream sockets (unix domain or tcp) and the
#  commands are are an array-ref consisting of the command name
#  and the arguments. Commands are 'allocate','activate' and 'close'.
#  For the arguments of the command and the return values see the
#  methods in Net::SIP::NATHelper.
#  For transport the requests and responses will be packet with 
#  Storable::nfreeze and prefixed with a long in network format containing
#  the length of the freezed packet (necessary, because stream sockets
#  are used).
#
############################################################################

use strict;
use warnings;
use Getopt::Long qw(:config posix_default bundling);
use File::Path;
use IO::Socket;
use Net::SIP ':debug';

############################################################################
#  USAGE
############################################################################

sub usage {
	print STDERR "ERROR: @_\n" if @_;
	print STDERR <<USAGE;

NAT Helper for SIP proxy.
Reads cmds from cmd-socket, allocates sockets for RTP and send
information about sockets back to caller, which then rewrites the
SDP bodies in the SIP packets.

$0 [options] cmd-socket+
Options:
    -d|--debug [level]           Enable debugging
	-h|--help                    Help (this info)
	-R|--chroot cage-dir         run chrooted (after opening sockets)

cmd-socket is a UNIX domain socket if it contains '/'. If it points
to an existing directory or contains a trailing '/' cmd-socket will be
interpreted as a directory name and a file 'socket' will be created below
the directory.
If the syntax is 'host:port' a TCP socket will be created.
Multiple cmd-sockets can be specified.

USAGE
	exit( @_ ? 1:0 );
}

############################################################################
#  Read Options
############################################################################

my ($debug,$chroot);
GetOptions(
	'd|debug:i' => \$debug,
	'h|help'    => sub { usage() },
	'R|chroot=s' => \$chroot,
) || usage( 'bad option' );
Net::SIP::Debug->level( $debug || 1 ) if defined $debug;

my @sockets = @ARGV;
@sockets or usage( "no command sockets" );

my @cfd;
foreach my $socket ( @sockets ) {
	DEBUG( $socket );
	if ( $socket =~ m{/} ) {
		if ( $socket =~m{/$} or -d $socket ) {
			-d $socket or mkpath( $socket, 0,0700 ) 
				or die $!;
			$socket = $socket."/socket";
		}
		push @cfd, IO::Socket::UNIX->new( Type => SOCK_STREAM, Local => $socket ) 
			|| die $!;
	} elsif ( $socket =~ m{^(.*):(\d+)$} ) {
		push @cfd, IO::Socket::INET->new( 
			LocalAddr => $1,
			LocalPort => $2,
			Listen => 10,
			Reuse => 1,
		) || die $!;
	}
}

# all sockets allocated, now we can change root
# if necessary
if ( $chroot ) {
	chdir( $chroot ) || die $!;
	chroot( '.' ) || die $!;
}

# create wrapper and run
wrapNATHelper->new( @cfd )->loop;


############################################################################
############################################################################
# 
#   wrap Net::SIP::NATHelper
#   read commands from socket and propagete them to NATHelper, send
#   replies back
# 
############################################################################
############################################################################

package wrapNATHelper;
use Net::SIP;
use Net::SIP::Debug;
use Net::SIP::Util 'invoke_callback';
use Storable qw(thaw nfreeze);
use Data::Dumper;

Net::SIP::Debug->level(100); # FIXME: remove when debugging done

# call to load before chrooting
eval { thaw() };
eval { nfreeze() };


############################################################################
# new NAThelper
# Args: ($class,@socket)
#  @socket: SOCK_STREAM sockets for communication SIP proxies
# Returns: $self
############################################################################
sub new {
	my ($class,@cfd) = @_;
	my $helper = Net::SIP::NATHelper->new;
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
	my wrapNATHelper $self = shift;
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
	my wrapNATHelper $self = shift;

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
	my wrapNATHelper $self = shift;
	my $changed = $self->{helper}->expire;
	$changed && $self->_update_callbacks;
	return $changed;
}

sub allocate_sockets {
	my wrapNATHelper $self = shift;
	my $media = $self->{helper}->allocate_sockets(@_) || return;
	#$self->_update_callbacks;
	return $media
}

sub activate_session {
	my wrapNATHelper $self = shift;
	my $success = $self->{helper}->activate_session(@_) || return;
	$self->_update_callbacks;
	return $success;
}

sub close_session {
	my wrapNATHelper $self = shift;
	my $success = $self->{helper}->close_session(@_) || return;
	$self->_update_callbacks;
	return $success;
}


sub _update_callbacks {
	my wrapNATHelper $self = shift;
	@{ $self->{callbacks} } = ();
}
	
