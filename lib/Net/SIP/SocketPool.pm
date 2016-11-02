# Collection of sockets associated with a Leg:
# This gets attached to an IO-Loop so that a common callback will be called with
# (packet,from) which then can be processed by the Leg and Dispatcher.
# Sending through the SocketPool is done by automatically selecting or creating
# the appropriate socket based on target and/or packet->tid.

use strict;
use warnings;
package Net::SIP::SocketPool;
use fields qw(loop proto dst fds tids cb timeout_timer);

use Net::SIP::Util ':all';
use Net::SIP::Packet;
use Net::SIP::Debug;

# RFC does not specify some fixed limit for the SIP header and body so we have
# to make up some limits we think are useful.
my $MAX_SIP_HEADER = 2**14;   # 16k header
my $MAX_SIP_BODY   = 2**16;   # 64k body

# how many requests we can associate with a socket at the same time
my $MAX_TIDLIST = 30;

my $MIN_EXPIRE = 5;      # wait at least this time before closing on inactivity
my $MAX_EXPIRE = 120;    # wait at most this time
my $CONNECT_TIMEOUT = 5; # max time for TCP connect

sub import {
    my %m = (
	MAX_SIP_HEADER  => \$MAX_SIP_HEADER,
	MAX_SIP_BODY    => \$MAX_SIP_BODY,
	MAX_TIDLIST     => \$MAX_TIDLIST,
	MIN_EXPIRE      => \$MIN_EXPIRE,
	MAX_EXPIRE      => \$MAX_EXPIRE,
	CONNECT_TIMEOUT => \$CONNECT_TIMEOUT,
    );
    for(my $i=1;$i<@_;$i+=2) {
	my $ref = $m{$_[$i]} or die "no such config key '$_[$i]'";
	$$ref = $_[$i+1];
    }
}

sub new {
    my ($class,$proto,$fd,$peer,$connected) = @_;
    $proto eq 'tls' and die "TLS not supported yet";
    my $self = fields::new($class);
    $self->{proto} = $proto || die "no protocol given";
    $self->{fds}   = {};
    $self->{tids}  = {};
    if (!$connected) {
	$self->{dst} = $peer;
	$peer = undef;
    }
    _add_socket($self,{
	fd => $fd,
	$peer ? (peer => $peer) : (),
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

sub master {
    my Net::SIP::SocketPool $self = shift;
    my @fo = grep { $_->{master} } values %{$self->{fds}};
    die "no master" if ! @fo;
    die "multiple master" if @fo>1;
    return $fo[0]{fd};
}

sub sendto {
    my Net::SIP::SocketPool $self = shift;
    my ($packet,$dst,$callback) = @_;
    if ($self->{dst}) {
	$dst = $self->{dst}; # override destination
    } elsif (!ref($dst)) {
	$dst = [ ip_string2parts($dst) ];
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
		$_->{peer}[0] eq $dst->[0] &&    # ip
		$_->{peer}[1] == $dst->[1]       # port
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
    if ($self->{proto} eq 'udp') {
	if ($fo->{peer}) {
	    # send over connected UDP socket
	    my $rv = send($fo->{fd},$data,0);
	    invoke_callback($callback, defined($rv) ? $! : 0);
	    return;
	} else {
	    # sendto over unconnected UDP socket
	    my $rv = send($fo->{fd},$data,0, ip_parts2sockaddr(@$dst[0,1,2]));
	    invoke_callback($callback, defined($rv) ? $! : 0);
	    return;
	}
    }

    if ($self->{proto} eq 'tcp') {
	if ($fo->{peer}) {
	    $DEBUG && DEBUG(40,"send tcp data to @$dst via @{$fo->{peer}}");
	    # send over this connected socket
	    $fo->{wbuf} .= $data;
	    _tcp_send($self,$fo,$callback);
	    return;
	}

	# TCP listener: we need to ceate a new connected socket first
	$DEBUG && DEBUG(40,"need new tcp socket to @$dst");
	my $clfd = INETSOCK(
	    Proto => 'tcp',
	    Reuse => 1,
	    LocalAddr => (ip_sockaddr2parts(getsockname($fo->{fd})))[0],
	    Blocking => 0,
	);
	$fo = $self->_add_socket({
	    fd => $clfd,
	    peer => $dst,
	    rbuf => '',
	    wbuf => $data,
	    didit => $self->{loop}->looptime,
	    inside_connect => 1,
	});
	_tcp_connect($self,$fo,ip_parts2sockaddr(@{$dst}[0,1,2]),$callback);
	return;
    }

    die "unknown type $self->{proto}";
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
	udp_m  => sub { 
	    my Net::SIP::SocketPool $self = shift;
	    return $self->{dst}
		? sub { _handle_read_udp(@_,1) }
		: sub { _handle_read_udp(@_) }
	},
	udp_co => sub { 
	    return \&_handle_read_udp 
	},
	tcp_m  => sub { 
	    return \&_handle_read_tcp_m 
	},
	tcp_co => sub { 
	    my (undef,$fd) = @_;
	    my $from = getpeername($fd);
	    return sub { _handle_read_tcp_co(@_,$from) }
	}
    );
    sub _addreader2loop {
	my Net::SIP::SocketPool $self = shift;
	my $fo = shift;
	my $type = $self->{proto} . ($fo->{peer} ? '_co':'_m');
	$self->{loop}->addFD($fo->{fd}, 0, [
	    $type2cb{$type}($self,$fo->{fd}) || die, 
	    $self
	]);
    }
}

sub _check_from {
    my Net::SIP::SocketPool $self = shift;
    my $dst = $self->{dst} or return;
    my ($ip,$port) = ip_sockaddr2parts(shift());
    if ($ip ne $dst->[0] or $port ne $dst->[1]) {
	$DEBUG && DEBUG(1,
	    "drop packet received from %s since expecting only from %s",
	    ip_parts2string($ip,$port),
	    ip_parts2string(@{$dst}[0,1])
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

    invoke_callback($self->{cb},$pkt,
	[$self->{proto}, ip_sockaddr2parts($from)]);
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
    $self->_add_socket({
	fd => $clfd,
	peer => [ ip_sockaddr2parts($from) ],
	rbuf => '',
	wbuf => '',
	didit => $self->{loop}->looptime,
    });
}


# read from connected TCP socket:
# Since TCP is a stream SIP messages might be split over multiple reads or
# a single read might contain more than one message.
sub _handle_read_tcp_co {
    my Net::SIP::SocketPool $self = shift;
    my ($fd,$from) = @_;

    my $fo = $self->{fds}{ fileno($fd) } or die;
    retry:
    my $n = sysread($fd, $fo->{rbuf}, 2**16, length($fo->{rbuf}));
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

    # ignore any leading \r\n according to RFC 3261 7.5
    $fo->{rbuf} =~s{\A(\r\n)+}{};

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
	substr($fo->{rbuf},0,$hdrpos) =~m{\nContent-length:\s*(\d+)\s*\n}ig;
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
    if ($hdrpos + $clen < length($fo->{rbuf})) {
	$DEBUG && DEBUG(20,"need more data for SIP body");
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
    invoke_callback($self->{cb},$pkt,
	[$self->{proto}, ip_sockaddr2parts($from)]);
}

sub _tcp_connect {
    my Net::SIP::SocketPool $self = shift;
    my ($fo,$peer,$callback,$xxfd) = @_;
    while (1) {
	$fo->{didit} = $self->{loop}->looptime;
	my $rv = connect($fo->{fd},$peer);
	$DEBUG && DEBUG(100,"tcp connect: ".($rv || $!));
	if ($rv) {
	    # successful connect
	    delete $fo->{inside_connect};
	    last;
	}
	next if $!{EINTR};
	if ($!{EALREADY} || $!{EINPROGRESS}) {
	    return if $xxfd; # called from loop: write handler already set up
	    # insert write handler
	    $DEBUG && DEBUG(100,"tcp connect: add write handler for async connect");
	    $self->{loop}->addFD($fo->{fd},1, 
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

    # connect done: remove write handler if we are called from loop
    $self->{loop}->delFD($xxfd,1) if $xxfd;

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
	    $self->{loop}->addFD($fo->{fd},1, 
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
    $self->{loop}->delFD($xxfd,1) if $xxfd;

    # signal success via callback
    invoke_callback($callback,0)
}


1;
