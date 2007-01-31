use strict;
use warnings;

############################################################################
#
#   Net::SIP::NATHelper::Client
#   proxy for Net::SIP::NAT::Helper to communicate over sockets
#   with Net::SIP::NATHelper::Server
#   used in connection with bin/nathelper.pl
#
############################################################################

package Net::SIP::NATHelper::Client;

use Net::SIP::Debug;
use Net::SIP::Util 'invoke_callback';
use IO::Socket;
use Storable qw(nfreeze thaw);

sub new {
	my ($class,$socket) = @_;
	my $create_socket = $socket =~m{/}
		? [ \&__create_unix_socket, $socket ]
		: [ \&__create_tcp_socket, $socket ]
		;
	my $self = bless { create_socket => $create_socket },$class;
	return $self;
}

sub allocate_sockets {
	my Net::SIP::NATHelper::Client $self = shift;
	return $self->rpc( 'allocate',@_ );
}

sub activate_session {
	my Net::SIP::NATHelper::Client $self = shift;
	return $self->rpc( 'activate',@_ );
}

sub close_session {
	my Net::SIP::NATHelper::Client $self = shift;
	return $self->rpc( 'close',@_ );
}

sub rpc {
	my Net::SIP::NATHelper::Client $self = shift;
	my ($method,@arg) = @_;
	my $sock = invoke_callback( $self->{create_socket} ) || die $!;
	$sock->autoflush;
	my $packet = pack( "N/a*", nfreeze([$method,@arg]));
	print $sock $packet;
	read( $sock, my $len,4 ) || die $!;
	$len = unpack( "N",$len );
	die if $len>32768;
	die $! unless $len == read( $sock, $packet, $len );
	my $ref = eval { thaw($packet) } || die $@;
	return $$ref;
}

sub __create_unix_socket {
	my $socket = shift;
	return IO::Socket::UNIX->new(
		Type => SOCK_STREAM,
		Peer => $socket
	);
}

sub __create_tcp_socket {
	my $socket = shift;
	return IO::Socket::INET->new( $socket );
}

1;
