use strict;
use warnings;
use IO::Socket;

############################################################################
#
#    small test lib for common tasks:
#
############################################################################

# small implementations if not used from Test::More (09_fdleak.t)
if ( ! defined &ok ) {
	no strict 'refs';
	*{'ok'} = sub {
		my ($bool,$desc) = @_;
		print $bool ? "ok ":"not ok ", '# ',$desc || '',"\n";
	};
	*{'diag'} = sub { print "# @_\n"; };
	*{'like'} = sub {
		my ( $data,$rx,$desc ) = @_;
		ok( $data =~ $rx ? 1:0, $desc );
	};
}

$SIG{ __DIE__ } = sub {
	ok( 0,"@_" );
	killall();
	exit(1);
};

############################################################################
# kill all process collected by fork_sub
# Args: ?$signal
#  $signal: signal to use, default 9
# Returns: NONE
############################################################################
my @pids;
sub killall {
	my $sig = shift || 9;
	kill $sig, @pids;
	#diag( "killed @pids with $sig" );
	while ( wait() >= 0 ) {} # collect all
	@pids = ();
}


############################################################################
# fork named sub with args and provide fd into subs STDOUT
# Args: ($name,@args)
#  $name: name or ref to sub, if name it will be used for debugging
#  @args: arguments for sub
# Returns: $fh
#  $fh: file handle to read STDOUT of sub
############################################################################
my %fd2name; # associated sub-name for file descriptor to subs STDOUT
sub fork_sub {
	my ($name,@arg) = @_;
	my $sub = ref($name) ? $name : UNIVERSAL::can( 'main',$name ) || die;
	pipe( my $rh, my $wh ) || die $!;
	defined( my $pid = fork() ) || die $!;
	if ( ! $pid ) {
		# CHILD, exec sub
		close($rh);
		open( STDOUT,'>&'.fileno($wh) ) || die $!;
		close( $wh );
		STDOUT->autoflush;
		print "OK\n";
		Debug->set_prefix( "DEBUG($name):" );
		$sub->(@arg);
		exit(0);
	}

	push @pids,$pid;
	close( $wh );
	$fd2name{$rh} = $name;
	fd_grep_ok( 'OK',10,$rh ) || die 'startup failed';
	return $rh;
}

############################################################################
# grep within fd's for specified regex or substring
# Args: ($pattern,[ $timeout ],@fd)
#  $pattern: regex or substring
#  $timeout: how many seconds to wait for pattern, default 10
#  @fd: which fds to search, usually fds from fork_sub(..)
# Returns: $rv| ($rv,$name)
#  $rv: matched text if pattern is found, else undef
#  $name: name for file handle
############################################################################
my %fd2buf;  # already read data from fd
sub fd_grep {
	my $pattern = shift;
	my $timeout = 10;
	$timeout = shift if !ref($_[0]);
	my @fd = @_;
	$pattern = qr{\Q$pattern} if ! UNIVERSAL::isa( $pattern,'Regexp' );
	my $name = join( "|", map { $fd2name{$_} || "$_" } @fd );
	#diag( "look for $pattern in $name" );
	my @bad = wantarray ? ( undef,$name ):(undef);
	@fd || return @bad;
	my $rin = '';
	map { $_->blocking(0); vec( $rin,fileno($_),1 ) = 1 } @fd;
	my $end = defined( $timeout ) ? time() + $timeout : undef;

	while (@fd) {

		# check existing buf from previous reads
		foreach my $fd (@fd) {
			my $buf = \$fd2buf{$fd};
			$$buf || next;
			if ( $$buf =~s{\A(?:.*?)($pattern)(.*)}{$2}s ) {
				#diag( "found" );
				return wantarray ? ( $1,$name ) : $1;
			}
		}

		# if not found try to read new data
		$timeout = $end - time() if $end;
		return @bad if $timeout < 0;
		select( my $rout = $rin,undef,undef,$timeout );
		$rout || return @bad; # not found
		foreach my $fd (@fd) {
			my $name = $fd2name{$fd} || "$fd";
			my $buf = \$fd2buf{$fd};
			my $fn = fileno($fd);
			my $n;
			if ( defined ($fn)) {
				vec( $rout,$fn,1 ) || next;
				my $l = $$buf && length($$buf) || 0;
				$n = sysread( $fd,$$buf,8192,$l );
			}
			if ( ! $n ) {
				#diag( "$name >CLOSED<" );
				delete $fd2buf{$fd};
				@fd = grep { $_ != $fd } @fd;
				close($fd);
				next;
			}
			diag( "$name >> ".substr( $$buf,-$n ). "<<" );
		}
	}
	return @bad;
}

############################################################################
# like Test::Simple::ok, but based on fd_grep, same as
# ok( fd_grep( pattern,... ), "[$subname] $pattern" )
# Args: ($pattern,[ $timeout ],@fd) - see fd_grep
# Returns: $rv - like in fd_grep
# Comment: if !$rv and wantarray says void it will die()
############################################################################
sub fd_grep_ok {
	my $pattern = shift;
	my ($rv,$name) = fd_grep( $pattern, @_ );
	local $Test::Builder::Level = $Test::Builder::Level || 0 +1;
	ok( $rv,"[$name] $pattern" );
	die "fatal error" if !$rv && ! defined wantarray;
	return $rv;
}

############################################################################
# dump media information on SIP packet to STDOUT
# Args: (@prefix,$packet,$from)
# Returns: NONE
############################################################################
sub sip_dump_media {
	my $from = pop;
	my $packet = pop;
	my $dump = @_ ? "@_ ":'';
	$dump .= "$from ";
	if ( $packet->is_request ) {
		$dump .= sprintf "REQ(%s) ",$packet->method;
	} else {
		$dump .= sprintf "RSP(%s,%s) ",$packet->method,$packet->code;
	}
	if ( my $sdp = $packet->sdp_body ) {
		$dump .= "SDP:";
		foreach my $m ( $sdp->get_media ) {
			$dump .= sprintf " %s=%s:%d/%d", @{$m}{qw( media addr port range )};
		}
	} else {
		$dump .= "NO SDP";
	}
	print $dump."\n";
}

############################################################################
# create isocket on IP
# return socket and ip:port
############################################################################
sub create_socket {
	my ($addr,$port,$proto) = @_;
	$addr ||= '127.0.0.1';
	$proto ||= 'udp';
	$port ||= 0;
	my $sock = IO::Socket::INET->new(
		Proto => $proto,
		$proto eq 'tcp' ? ( Listen => 10 ):(),
		LocalAddr => $addr,
		LocalPort => $port,
	) || die $!;
	($port,$addr) = unpack_sockaddr_in( getsockname($sock) );
	return wantarray ? ( $sock, inet_ntoa($addr).':'.$port ) : $sock;
}

############################################################################
# redefined Leg for Tests:
# - can have explicit destination
# - can intercept receive and deliver for printing out packets
############################################################################
package TestLeg;
use base 'Net::SIP::Leg';
use fields qw( can_deliver_to dump_incoming dump_outgoing );
use Net::SIP 'invoke_callback';

sub new {
	my ($class,%args) = @_;
	my @lfields = qw( can_deliver_to dump_incoming dump_outgoing );
	my %largs = map { $_ => delete $args{$_} } @lfields;
	my $self = $class->SUPER::new( %args );
	if ( my $ct = delete $largs{can_deliver_to} ) {
		$self->{can_deliver_to} = _parse_addr($ct);
	}
	%$self = ( %$self, %largs );
	return $self;
}
sub can_deliver_to {
	my $self = shift;
	my $spec = @_ == 1 ? _parse_addr( $_[0] ) : { @_ };
	my $ct = $self->{can_deliver_to};
	if ( $ct ) {
		foreach (qw( addr proto port )) {
			next if ! $spec->{$_} || ! $ct->{$_};
			return if $spec->{$_} ne $ct->{$_};
		}
	}
	return $self->SUPER::can_deliver_to( @_ );
}

sub _parse_addr {
	my $addr = shift;
	$addr =~m{^(?:(udp|tcp):)?([\w\.-]+)(?::(\d+))?$} || die $addr;
	return { proto => $1, addr => $2, port => $3 }
}

sub receive {
	my $self = shift;
	my @rv = $self->SUPER::receive(@_) or return;
	invoke_callback( $self->{dump_incoming},@rv );
	return @rv;
}

sub deliver {
	my ($self,$packet,$to,$callback) = @_;
	invoke_callback( $self->{dump_outgoing},$packet,$to );
	return $self->SUPER::deliver( $packet,$to,$callback );
}



1;
