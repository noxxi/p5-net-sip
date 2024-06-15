# Collection of sockets associated with a Leg:
# This gets attached to an IO-Loop so that a common callback will be called with
# (packet,from) which then can be processed by the Leg and Dispatcher.
# Sending through the SocketPool is done by automatically selecting or creating
# the appropriate socket based on target and/or packet->tid.

use strict;
use warnings;
package Net::SIP::SocketPool;
use fields qw(loop ipproto tls dst fds tids cb timeout_timer);

use Errno qw(ETIMEDOUT);
use Net::SIP::Util ':all';
use Net::SIP::Packet;
use Net::SIP::Debug;
use Net::SIP::Dispatcher::Eventloop;
use Socket qw(SOL_SOCKET SO_ERROR);
use Scalar::Util 'weaken';

# RFC does not specify some fixed limit for the SIP header and body so we have
# to make up some limits we think are useful.
my $MAX_SIP_HEADER = 2**14;   # 16k header
my $MAX_SIP_BODY   = 2**16;   # 64k body

# how many requests we can associate with a socket at the same time
my $MAX_TIDLIST = 30;

my $MIN_EXPIRE = 15;      # wait at least this time before closing on inactivity
my $MAX_EXPIRE = 120;     # wait at most this time
my $CONNECT_TIMEOUT = 10; # max time for TCP connect
my $TCP_READSIZE = 2**16; # size of TCP read

sub import {
    my %m = (
	MAX_SIP_HEADER  => \$MAX_SIP_HEADER,
	MAX_SIP_BODY    => \$MAX_SIP_BODY,
	MAX_TIDLIST     => \$MAX_TIDLIST,
	MIN_EXPIRE      => \$MIN_EXPIRE,
	MAX_EXPIRE      => \$MAX_EXPIRE,
	CONNECT_TIMEOUT => \$CONNECT_TIMEOUT,
	TCP_READSIZE    => \$TCP_READSIZE,
    );
    for(my $i=1;$i<@_;$i+=2) {
	my $ref = $m{$_[$i]} or die "no such config key '$_[$i]'";
	$$ref = $_[$i+1];
    }
}

my %TLSClientDefault = (SSL_verifycn_scheme => 'sip');
my %TLSServerDefault = ();

# will be defined on first use of SSL depending if IO::Socket::SSL is available
my $CAN_TLS;
my $SSL_REUSE_CTX;
my ($SSL_WANT_READ, $SSL_WANT_WRITE, $SSL_VERIFY_PEER, 
    $SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
our $SSL_ERROR;


###########################################################################
# create a new SocketPool
# Args: ($class,$proto,$fd,$peer,$connected,$tls)
#  $proto: udp|tcp|tls
#  $fd: the file descriptor for the master socket (i.e. listener)
#  $peer: optional hash with addr,port,family of destination if restricted
#  $connected: true if $fd is connected to $peer (useful with UDP only)
#  $tls: \%options for IO::Socket::SSL when proto is tls
# Returns: $self
###########################################################################
sub new {
    my ($class,$proto,$fd,$peer,$connected,$tls) = @_;
    my $self = fields::new($class);
    if ($proto eq 'tls') {
	# the underlying proto is still TCP and we remember to use TLS by
	# having a true self.tls
	$self->{ipproto} = 'tcp';
	$CAN_TLS //= eval "use IO::Socket::SSL;1" && eval {
	    # 1.956 defines the 'sip' scheme for hostname validation
	    IO::Socket::SSL->VERSION >= 1.956
		or die "need at least version 1.956";
	    $SSL_WANT_READ  = IO::Socket::SSL::SSL_WANT_READ();
	    $SSL_WANT_WRITE = IO::Socket::SSL::SSL_WANT_WRITE();
	    $SSL_VERIFY_PEER = IO::Socket::SSL::SSL_VERIFY_PEER();
	    $SSL_VERIFY_FAIL_IF_NO_PEER_CERT =
		IO::Socket::SSL::SSL_VERIFY_FAIL_IF_NO_PEER_CERT();
	    *SSL_ERROR = \$IO::Socket::SSL::SSL_ERROR;
	    # 1.969 fixed name validation when reusing context
	    $SSL_REUSE_CTX = IO::Socket::SSL->VERSION >= 1.969;
	    1;
	} || die "no SSL support using IO::Socket::SSL: $@";

	# create different contexts for [m]aster and [c]lient
	$tls ||= {};
	my $verify_client = delete $tls->{verify_client};
	$self->{tls}{c} = { %TLSClientDefault, %$tls };
	$self->{tls}{m} = {
	    %TLSServerDefault,
	    %$tls,
	    SSL_server => 1,
	    # request client certificate?
	    ! $verify_client ? ():
	    $verify_client == -1 ? (SSL_verify_mode => $SSL_VERIFY_PEER) :
	    $verify_client ==  1 ? (SSL_verify_mode =>
		$SSL_VERIFY_PEER|$SSL_VERIFY_FAIL_IF_NO_PEER_CERT) :
	    die "invalid setting for SSL_verify_client: $verify_client"
	};
	if ($SSL_REUSE_CTX) {
	    for(qw(m c)) {
		$self->{tls}{$_}{SSL_reuse_ctx} and next;
		my $ctx = IO::Socket::SSL::SSL_Context->new($self->{tls}{$_})
		    || die "failed to create SSL context: $SSL_ERROR";
		$self->{tls}{$_}{SSL_reuse_ctx} = $ctx;
	    }
	}
    } else {
	$self->{ipproto} = $proto || die "no protocol given";
    }

    $self->{fds}   = {};
    $self->{tids}  = {};
    if (!$connected) {
	$self->{dst} = $peer;
	$peer = undef;
    }
    _add_socket($self,{
	fd => $fd,
	$peer ? (peer => $peer, rbuf => '', wbuf => '') : (),
	master => 1,
    });
    return $self;
}

sub DESTROY {
    my Net::SIP::SocketPool $self = shift;
    # detach from current loop 
    if ($self->{loop}) {
	for(values %{$self->{fds}}) {
	    $self->{loop}->delFD($_->{fd} || next);
	}
    }
}

###########################################################################
# attaches SocketPool to EventLoop
# Args: ($self,$loop,$callback)
#  $loop: Net::SIP::Dispatcher::Eventloop or API compatible
#  $callback: should be called for each new SIP packet received
# Comment:
#  If $loop is empty it just detaches from the current loop
###########################################################################
sub attach_eventloop {
    my Net::SIP::SocketPool $self = shift;
    my ($loop,$cb) = @_;
    if ($self->{loop}) {
	for(values %{$self->{fds}}) {
	    $self->{loop}->delFD($_->{fd});
	}
	if ($self->{timeout_timer}) {
	    $self->{timeout_timer}->cancel;
	    undef $self->{timeout_timer};
	}
    }
    if ($self->{loop} = $loop) {
	$self->{cb} = $cb;
	_addreader2loop($self,$_) for values %{$self->{fds}};
    }
}

###########################################################################
# returns master socket
# Args: $self
# Returns: $fd
#  $fd: master socket
###########################################################################
sub master {
    my Net::SIP::SocketPool $self = shift;
    my @fo = grep { $_->{master} } values %{$self->{fds}};
    die "no master" if ! @fo;
    die "multiple master" if @fo>1;
    return $fo[0]{fd};
}

###########################################################################
# send packet via SocketPool
# Args: ($self,$packet,$dst,$callback)
#  $packet: Net::SIP::Packet
#  $dst: where to send as hash with addr,port,family
#  $callback: callback to call on definite successful delivery (TCP/TLS only)
#    or on error
###########################################################################
sub sendto {
    my Net::SIP::SocketPool $self = shift;
    my ($packet,$dst,$callback) = @_;
    if ($self->{dst}) {
	$dst = $self->{dst}; # override destination
    } elsif (!ref($dst)) {
	$dst = ip_string2parts($dst);
    }

    # select all sockets which are connected to the target
    # if we have multiple connected reduce further by packets tid
    # take one socket

    my $fos = [ values %{$self->{fds}} ];
    if (@$fos>1) {
	my $match = 0;
	# any socket associated with tid?
	if ($packet->is_response and my $fo = $self->{tids}{$packet->tid}) {
	    if (my @s = grep { $_ == $fo } @$fos) {
		$match |= 1;
		$fos = \@s
	    }
	}
	if (@$fos>1) {
	    # any socket connected to dst?
	    if ( my @s = grep {
		$_->{peer} &&
		$_->{peer}{addr} eq $dst->{addr} &&
		$_->{peer}{port} == $dst->{port}
	    } @$fos) {
		$match |= 2;
		$fos = \@s;
	    }
	}
	if (!$match) {
	    # use master
	    $fos = [ grep { $_->{master} } @$fos ];
	}
    }

    my $fo = $fos->[0];
    my $data = $packet->as_string;
    if ($self->{ipproto} eq 'udp') {
	if ($fo->{peer}) {
	    # send over connected UDP socket
	    my $rv = send($fo->{fd},$data,0);
	    invoke_callback($callback, $!) if ! defined($rv);
	    return;
	} else {
	    # sendto over unconnected UDP socket
	    my $rv = send($fo->{fd},$data,0, ip_parts2sockaddr($dst));
	    invoke_callback($callback, $!) if ! defined($rv);
	    return;
	}
    }

    if ($self->{ipproto} eq 'tcp') {
	if ($fo && $fo->{peer}) {
	    $DEBUG && DEBUG(40,"send tcp data to %s via %s",
		ip_parts2string($dst),
		ip_parts2string($fo->{peer}));
	    # send over this connected socket
	    $fo->{wbuf} .= $data;
	    weaken($fo->{error_cb} = $callback);
	    _tcp_send($self,$fo,$callback) if ! $fo->{inside_connect};
	    return;
	}

	# TCP listener: we need to create a new connected socket first
	$DEBUG && DEBUG(40,"need new tcp socket to %s",
	    ip_parts2string($dst));
	my $clfd = INETSOCK(
	    Proto => 'tcp',
	    Reuse => 1, ReuseAddr => 1,
	    LocalAddr => (ip_sockaddr2parts(getsockname($fo->{fd})))[0],
	    Blocking => 0,
	);
	my %h = (
	    fd => $clfd,
	    peer => $dst,
	    rbuf => '',
	    wbuf => $data,
	    didit => $self->{loop}->looptime,
	    inside_connect => 1,
	    error_cb => $callback,
	);
	weaken($h{error_cb});
	$fo = $self->_add_socket(\%h);
	_tcp_connect($self,$fo,ip_parts2sockaddr($dst),$callback);
	return;
    }

    die "unknown type $self->{ipproto}";
}


sub _add_socket {
    my Net::SIP::SocketPool $self = shift;
    my $fo = shift;
    $fo->{fd}->blocking(0);
    $self->{fds}{ fileno($fo->{fd}) } = $fo;
    _addreader2loop($self,$fo) if $self->{loop} && ! $fo->{inside_connect};
    $self->_timeout_sockets if ! $self->{timeout_timer} && $fo->{didit};
    return $fo;
}

sub _del_socket {
    my Net::SIP::SocketPool $self = shift;
    my $fo = shift;
    $self->_error(@_) if @_;
    $self->{loop}->delFD($fo->{fd}) if $self->{loop};
    delete $self->{fds}{ fileno($fo->{fd}) };
    if ($fo->{tids}) {
	delete $self->{tids}{$_} for @{$fo->{tids}};
    }
    return;
}

sub _timeout_sockets {
    my Net::SIP::SocketPool $self = shift;
    my $fds = $self->{fds};
    goto disable_timer if keys(%$fds) <= 1;
    return if ! $self->{loop};

    DEBUG(99,"timeout sockets");

    # the more sockets we have open the faster expire
    my $expire = $MIN_EXPIRE + ($MAX_EXPIRE - $MIN_EXPIRE)/(keys(%$fds)-1);
    my ($time,$need_timer);
    for (values %$fds) {
	my $tdiff = -($_->{didit} || next) + ($time||= $self->{loop}->looptime);
	if ($tdiff>$expire) {
	    $self->_del_socket($_);
	} elsif ($_->{inside_connect} && $tdiff > $CONNECT_TIMEOUT) {
	    invoke_callback($_->{error_cb}, ETIMEDOUT) if $_->{error_cb};
	    $self->_del_socket($_,"connect timed out");
	} else {
	    $need_timer = 1;
	}
    }
    if ($need_timer) {
	return if $self->{timeout_timer};
	DEBUG(99,"timeout sockets - need timer");
	$self->{timeout_timer} = $self->{loop}->add_timer(
	    int($MIN_EXPIRE/2)+1,
	    [ \&_timeout_sockets, $self ],
	    int($MIN_EXPIRE/2)+1,
	    'socketpool-timeout'
	);
	return;
    }
    disable_timer:
    DEBUG(99,"timer cancel");
    ($self->{timeout_timer} || return)->cancel;
    undef $self->{timeout_timer};
}

sub _error {
    my Net::SIP::SocketPool $self = shift;
    my $msg = shift;
    $msg = sprintf($msg,@_) if @_;
    DEBUG(1,$msg);
    return;
}

{
    my %type2cb = (
	# unconnected UDP socket: receive and send
	udp_m  => sub { 
	    my Net::SIP::SocketPool $self = shift;
	    return $self->{dst}
		? sub { _handle_read_udp(@_,1) }
		: sub { _handle_read_udp(@_) }
	},
	# connected UDP socket: receive and send with fixed peer
	udp_co => sub { 
	    return \&_handle_read_udp 
	},
	# unconnected TCP socket: listen, accept and create tcp_co
	tcp_m  => sub { 
	    return \&_handle_read_tcp_m 
	},
	# connected TCP socket: receive and send with fixed peer
	tcp_co => sub { 
	    my (undef,$fd) = @_;
	    my $from = getpeername($fd);
	    return sub { _handle_read_tcp_co(@_,$from) }
	}
    );
    sub _addreader2loop {
	my Net::SIP::SocketPool $self = shift;
	my $fo = shift;
	# proto_co: connected socket, proto_m: (unconnected) master socket
	my $type = $self->{ipproto} . ($fo->{peer} ? '_co':'_m');
	$self->{loop}->addFD($fo->{fd}, EV_READ, [
	    $type2cb{$type}($self,$fo->{fd}),
	    $self
	]);
    }
}

sub _check_from {
    my Net::SIP::SocketPool $self = shift;
    my $dst = $self->{dst} or return;
    my ($ip,$port) = ip_sockaddr2parts(shift());
    if ($ip ne $dst->{addr} or $port ne $dst->{port}) {
	$DEBUG && DEBUG(1,
	    "drop packet received from %s since expecting only from %s",
	    ip_parts2string($ip,$port),
	    ip_parts2string($dst)
	);
	return 0;
    }
    return 1;
}

sub _handle_read_udp {
    my Net::SIP::SocketPool $self = shift;
    my $fd = shift;
    my $fo = $self->{fds}{ fileno($fd) } or die;
    my $from = recv($fd, my $buf, 2**16, 0) or return;

    # packet must be at least 13 bytes big (first line incl version
    # + final crlf crlf). Ignore anything smaller, probably keep-alives
    if ( length($buf)<13 ) {
        DEBUG(11,"ignored packet with len ".length($buf)." because to small (keep-alive?)");
        return;
    }

    # check dst on unconnected UDP sockets
    shift() && ! _check_from($self,$from) && return;

    my $pkt = eval { Net::SIP::Packet->new_from_string($buf) } or
	return $self->_error(
	    "drop invalid packet received from %s: %s",
	    ip_sockaddr2string($from), $@
	);

    invoke_callback($self->{cb},$pkt, {
	%{ ip_sockaddr2parts($from) },
	proto => 'udp',
	socket => $fd,
    });
}

# read from unconnected TCP socket:
# - accept new connection
# - check against dst
# - setup new connection to receive data
sub _handle_read_tcp_m {
    my Net::SIP::SocketPool $self = shift;
    my $srvfd = shift;
    my $srvfo = $self->{fds}{ fileno($srvfd) } or die;
    my $from = accept(my $clfd, $srvfd) or return;
    $self->{dst} && ! _check_from($self,$from) && return;
    my $clfo = $self->_add_socket({
	fd => $clfd,
	peer => scalar(ip_sockaddr2parts($from)),
	rbuf => '',
	wbuf => '',
	didit => $self->{loop}->looptime,
	inside_connect => $self->{tls} && 1,
    });
    _tls_accept($self,$clfo) if $self->{tls};
}


# read from connected TCP socket:
# Since TCP is a stream SIP messages might be split over multiple reads or
# a single read might contain more than one message.
sub _handle_read_tcp_co {
    my Net::SIP::SocketPool $self = shift;
    my ($fd,$from) = @_;
    my $fo = $self->{fds}{ fileno($fd) } or die "no fd for read";

    $DEBUG && $fo->{rbuf} ne '' && DEBUG(20,
	"continue reading SIP packet, offset=%d",length($fo->{rbuf}));

    retry:
    my $n = sysread($fd, $fo->{rbuf},
	# read max size of TLS frame when tls so that we don't get any awkward
	# effects with user space buffering in TLS stack and select(2)
	$self->{tls} ? 2**14 : $TCP_READSIZE,
	length($fo->{rbuf}));
    if (!defined $n) {
	goto retry if $!{EINTR};
	return if $!{EAGAIN} || $!{EWOULDBLOCK};
	return $self->_del_socket($fo,
	    "error while reading from %s: %s",
	    ip_sockaddr2string($from), $!);
    }
    if (!$n) {
	# peer closed
	return $self->_del_socket($fo);
    }

    process_packet:
    # ignore any leading \r\n according to RFC 3261 7.5
    if ($fo->{rbuf} =~s{\A((?:\r\n)+)}{}) {
	$DEBUG && DEBUG(20,"skipped over newlines preceding packet, size=%d",
	    length($1));
    }

    my $hdrpos = index($fo->{rbuf},"\r\n\r\n");
    if ($hdrpos<0 && length($fo->{rbuf}) > $MAX_SIP_HEADER
	or $hdrpos > $MAX_SIP_HEADER) {
	return $self->_del_socket($fo,
	    "drop packet from %s since SIP header is too big",
	    ip_sockaddr2string($from));
    }
    if ($hdrpos<0) {
	$DEBUG && DEBUG(20,"need more data for SIP header");
	return;
    }
    $hdrpos += 4; # after header
    my %clen = map { $_ => 1 } 
	substr($fo->{rbuf},0,$hdrpos) =~m{\n(?:l|Content-length):\s*(\d+)\s*\n}ig;
    if (!%clen) {
	return $self->_del_socket($fo,
	    "drop invalid SIP packet from %s: missing content-length",
	    ip_sockaddr2string($from));
    }
    if (keys(%clen)>1) {
	return $self->_del_socket($fo,
	    "drop invalid SIP packet from %s: conflicting content-length",
	    ip_sockaddr2string($from));
    }
    my $clen = (keys %clen)[0];
    if ($clen > $MAX_SIP_BODY) {
	return $self->_del_socket($fo,
	    "drop packet from %s since SIP body is too big: %d>%d",
	    ip_sockaddr2string($from), $clen, $MAX_SIP_BODY);
    }
    if ($hdrpos + $clen > length($fo->{rbuf})) {
	$DEBUG && DEBUG(20,"need %d more bytes for SIP body",
	    $hdrpos + $clen - length($fo->{rbuf}));
	return;
    }

    my $pkt = eval { 
	Net::SIP::Packet->new_from_string(substr($fo->{rbuf},0,$hdrpos+$clen,'')) 
    } or return $self->_del_socket($fo,
	"drop invalid packet received from %s: %s",
	ip_sockaddr2string($from), $@);

    if ($pkt->is_request) {
	# associate $pkt->tid with this socket
	my $tidlist = $fo->{tids} ||= [];
	push @$tidlist, $pkt->tid;
	while (@$tidlist > $MAX_TIDLIST) {
	    my $tid = shift(@$tidlist);
	    delete $self->{tids}{$tid};
	}
	$self->{tids}{ $tidlist->[-1] } = $fo;
    }

    $fo->{didit} = $self->{loop}->looptime if $self->{loop};
    invoke_callback($self->{cb},$pkt, {
	%{ ip_sockaddr2parts($from) },
	proto => $self->{tls} ? 'tls' : 'tcp',
	socket => $fd,
    });

    # continue with processing any remaining data in the buffer
    goto process_packet if $fo->{rbuf} ne '';
}

sub _tcp_connect {
    my Net::SIP::SocketPool $self = shift;
    my ($fo,$peer,$callback,$xxfd) = @_;

    while (!$xxfd) {
	# direct call, no connect done yet
	$fo->{didit} = $self->{loop}->looptime;
	my $rv = connect($fo->{fd},$peer);
	$DEBUG && DEBUG(100,"tcp connect: ".($rv || $!));
	if ($rv) {
	    # successful connect
	    return _tls_connect($self,$fo,$callback) if $self->{tls};
	    delete $fo->{inside_connect};
	    last;
	}
	next if $!{EINTR};
	if ($!{EALREADY} || $!{EINPROGRESS}) {
	    # insert write handler
	    $DEBUG && DEBUG(100,"tcp connect: add write handler for async connect");
	    $self->{loop}->addFD($fo->{fd}, EV_WRITE,
		[ \&_tcp_connect, $self,$fo,$peer,$callback ]);
	    return;
	}
	# connect permanently failed
	my $err = $!;
	$self->_del_socket($fo,
	    "connect to ".ip_sockaddr2string($peer)." failed: $!");
	invoke_callback($callback,$err);
	return;
    }

    if ($xxfd) {
	# we are called from loop and hopefully async connect was succesful:
	# use getsockopt to check
	my $err = getsockopt($xxfd, SOL_SOCKET, SO_ERROR);
	$err = $err ? unpack('i',$err) : $!;
	if ($err) {
	    # connection failed
	    $! = $err;
	    $self->_del_socket($fo,
		"connect to ".ip_sockaddr2string($peer)." failed: $!");
	    invoke_callback($callback,$err);
	    return;
	}

	# connect done: remove write handler
	$self->{loop}->delFD($xxfd, EV_WRITE);
	return _tls_connect($self,$fo,$callback) if $self->{tls};
	delete $fo->{inside_connect};
    }

    _addreader2loop($self,$fo);
    
    # if we have something to write continue in _tcp_send
    return _tcp_send($self,$fo,$callback) if $fo->{wbuf} ne '';

    # otherwise signal success via callback
    invoke_callback($callback,0)
}

sub _tcp_send {
    my Net::SIP::SocketPool $self = shift;
    my ($fo,$callback,$xxfd) = @_;
    while ($fo->{wbuf} ne '') {
	$fo->{didit} = $self->{loop}->looptime;
	if (my $n = syswrite($fo->{fd},$fo->{wbuf})) {
	    substr($fo->{wbuf},0,$n,'');
	    next;
	}

	next if $!{EINTR};
	if ($!{EAGAIN} || $!{EWOULDBLOCK}) {
	    return if $xxfd; # called from loop: write handler already set up
	    # insert write handler
	    $self->{loop}->addFD($fo->{fd}, EV_WRITE,
		[ \&_tcp_send, $self,$fo,$callback ]);
	    return;
	}

	# permanently failed to write
	my $err = $!;
	$self->_del_socket($fo, "write failed: $!");
	invoke_callback($callback,$err);
	return;
    }

    # write done: remove write handler if we are called from loop
    $DEBUG && DEBUG(90,"everything has been sent");
    $self->{loop}->delFD($xxfd, EV_WRITE) if $xxfd;

    # signal success via callback
    invoke_callback($callback,0)
}

sub _tls_accept {
    my Net::SIP::SocketPool $self = shift;
    my ($fo,$xxfd) = @_;
    if (!$xxfd) {
	$DEBUG && DEBUG(40,"upgrade to SSL server");
	IO::Socket::SSL->start_SSL($fo->{fd},
	    %{$self->{tls}{m}},
	    SSL_startHandshake => 0,
	) or die "upgrade to SSL socket failed: $SSL_ERROR";
    }

    if ($fo->{fd}->accept_SSL()) {
	if ($DEBUG) {
	    my $peer_cert = $fo->{fd}->peer_certificate;
	    DEBUG(40,"TLS accept success, %s", $peer_cert 
		? "peer="._dump_certificate($peer_cert) 
		: 'no peer certificate');
	}
	delete $fo->{inside_connect};
	$self->{loop}->delFD($xxfd, EV_WRITE) if $xxfd;
	_addreader2loop($self,$fo);
	return;
    }

    if ($SSL_ERROR == $SSL_WANT_READ) {
	$DEBUG && DEBUG(40,"TLS accept - want read");
	$self->{loop}->delFD($xxfd, EV_WRITE) if $xxfd;
	$self->{loop}->addFD($fo->{fd}, EV_READ, [ \&_tls_accept, $self, $fo ]);
    } elsif ($SSL_ERROR == $SSL_WANT_WRITE) {
	$DEBUG && DEBUG(40,"TLS accept - want write");
	$self->{loop}->delFD($xxfd, EV_READ) if $xxfd;
	$self->{loop}->addFD($fo->{fd}, EV_WRITE,
	    [ \&_tls_accept, $self, $fo ]);
    } else {
	# permanent error
	_del_socket($self, $fo,
	    "SSL accept failed: $SSL_ERROR");
    }
}


sub _tls_connect {
    my Net::SIP::SocketPool $self = shift;
    my ($fo,$callback,$xxfd) = @_;
    if (!$xxfd) {
	$DEBUG && DEBUG(40,"upgrade to SSL client");
	IO::Socket::SSL->start_SSL($fo->{fd},
	    SSL_verifycn_name => $fo->{peer}{host},
	    SSL_hostname => $fo->{peer}{host} =~m{^[\d\.]+|:}
		? undef : $fo->{peer}{host},
	    %{$self->{tls}{c}},
	    SSL_startHandshake => 0,
	) or die "upgrade to SSL socket failed: $SSL_ERROR";
    }

    if ($fo->{fd}->connect_SSL()) {
	$DEBUG && DEBUG(40,"TLS connect success peer cert=%s",
	    _dump_certificate($fo->{fd}->peer_certificate));
	delete $fo->{inside_connect};
	$self->{loop}->delFD($xxfd, EV_WRITE) if $xxfd;
	_addreader2loop($self,$fo);
	return _tcp_send($self,$fo,$callback) if $fo->{wbuf} ne '';
	invoke_callback($callback,0);
	return;
    }

    if ($SSL_ERROR == $SSL_WANT_READ) {
	$DEBUG && DEBUG(40,"TLS connect - want read");
	$self->{loop}->delFD($xxfd, EV_WRITE) if $xxfd;
	$self->{loop}->addFD($fo->{fd}, EV_READ,
	    [ \&_tls_connect, $self, $fo, $callback ]);
    } elsif ($SSL_ERROR == $SSL_WANT_WRITE) {
	$DEBUG && DEBUG(40,"TLS connect - want write");
	$self->{loop}->delFD($xxfd, EV_READ) if $xxfd;
	$self->{loop}->addFD($fo->{fd}, EV_WRITE,
	    [ \&_tls_connect, $self, $fo, $callback ]);
    } else {
	# permanent error
	_del_socket($self, $fo,
	    "SSL connect failed: $SSL_ERROR");
	invoke_callback($callback,"SSL connect failed: $SSL_ERROR");
    }
}


sub _dump_certificate {
    my $cert = shift or return '';
    my $issuer = Net::SSLeay::X509_NAME_oneline( Net::SSLeay::X509_get_issuer_name($cert));
    my $subject = Net::SSLeay::X509_NAME_oneline( Net::SSLeay::X509_get_subject_name($cert));
    return "s:$subject i:$issuer";
}

1;
