############################################################################
#
#  Standalone nathelper which can be used with SIP proxy
#  for transferring RTP data between networks/through a firewall..
#  uses Net::SIP::NAT::NATHelper::Server which communicates
#  with Net::SIP::NAT::NATHelper::Client
#
#  Communication is via sock_stream sockets (unix domain or tcp) and the
#  commands are are an array-ref consisting of the command name
#  and the arguments. Commands are 'allocate','activate' and 'close'.
#  For the arguments of the command and the return values see the
#  methods in Net::SIP::NATHelper::Base.
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
use Net::SIP::NATHelper::Server;

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

# all sockets allocated, now we can change root if necessary
if ( $chroot ) {
    # load Storable::* by eval if chroot
    eval { Storable::thaw() };
    eval { Storable::nfreeze() };

    chdir( $chroot ) || die $!;
    chroot( '.' ) || die $!;
}

# create wrapper and run
Net::SIP::NATHelper::Server->new( @cfd )->loop;
