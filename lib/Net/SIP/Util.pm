
###########################################################################
# Net::SIP::Util
# various functions for helping in SIP programs
###########################################################################

use strict;
use warnings;

package Net::SIP::Util;

use Digest::MD5 'md5_hex';
use Socket 1.95 qw(
    inet_ntop inet_pton
    AF_INET unpack_sockaddr_in pack_sockaddr_in
    getaddrinfo
);
use Net::SIP::Debug;
use Carp qw(confess croak);
use base 'Exporter';

BEGIN {
    my $mod6 = '';
    if (eval {
	require IO::Socket::IP;
	IO::Socket::IP->VERSION(0.31);
	Socket->import('AF_INET6');
	AF_INET6();
    }) {
	$mod6 = 'IO::Socket::IP';
	*INETSOCK = sub { return IO::Socket::IP->new(@_) }

    } elsif (eval {
	require IO::Socket::INET6;
	IO::Socket::INET6->VERSION(2.62);
	Socket->import('AF_INET6');
	AF_INET6();
    }) {
	$mod6 = 'IO::Socket::INET6';
	*INETSOCK = sub {
	    return IO::Socket::INET6->new(@_) if @_ == 1;
	    my %args = @_;
	    $args{Domain} = delete $args{Family} if exists $args{Family};
	    return IO::Socket::INET6->new(%args);
	};

    } else {
	*INETSOCK = sub { return IO::Socket::INET->new(@_) };
	no warnings 'redefine';
	*AF_INET6 = sub() { 10 }
    }

    *CAN_IPV6 = $mod6 ? sub() { 1 } : sub() { 0 };
    Socket->import(qw(unpack_sockaddr_in6 pack_sockaddr_in6)) if $mod6;
}

our @EXPORT = qw(INETSOCK);
our @EXPORT_OK = qw(
    sip_hdrval2parts sip_parts2hdrval
    sip_uri2parts sip_parts2uri sip_uri_eq sip_uri2sockinfo sip_sockinfo2uri
    laddr4dst create_socket_to create_rtp_sockets
    ip_string2parts ip_parts2string
    ip_parts2sockaddr ip_sockaddr2parts
    ip_sockaddr2string
    ip_is_v4 ip_is_v6 ip_is_v46
    ip_ptr ip_canonical
    hostname2ip
    CAN_IPV6
    invoke_callback
);
our %EXPORT_TAGS = ( all => [ @EXPORT_OK, @EXPORT ] );

our $RTP_MIN_PORT = 2000;
our $RTP_MAX_PORT = 12000;

###########################################################################
# creates hash from header val, e.g.
# 'Digest method="md5",qop="auth",...','www-authenticate' will result in
# ( 'Digest', { method => md5, qop => auth,... } )
# Args: ($key,$val)
#   $key: normalized key (lowercase, long)
#   $val: value
# Returns: ( $data,\%parameter )
#   $data: initial data
#   %parameter: additional parameter
###########################################################################
my %delimiter = (
    'www-authenticate' => ',',
    'proxy-authenticate' => ',',
    'authorization' => ',',
    'proxy-authorization' => ',',
);
sub sip_hdrval2parts {
    croak( "usage: sip_hdrval2parts( key => val )" ) if @_!=2;
    my ($key,$v) = @_;
    return if !defined($v);
    my $delim = $delimiter{$key} || ';';

    # split on delimiter (but not if quoted)
    my @v = ('');
    my $quoted = 0;
    my $bracket = 0;
    while (1) {
	if ( $v =~m{\G(.*?)([\\"<>$delim])}gc ) {
	    if ( $2 eq "\\" ) {
		$v[-1].=$1.$2.substr( $v,pos($v),1 );
		pos($v)++;
	    } elsif ( $2 eq '"' ) {
		$v[-1].=$1.$2;
		$quoted = !$quoted if ! $bracket;
	    } elsif ( $2 eq '<' ) {
		$v[-1].=$1.$2;
		$bracket = 1 if ! $bracket && ! $quoted;
	    } elsif ( $2 eq '>' ) {
		$v[-1].=$1.$2;
		$bracket = 0 if $bracket && ! $quoted;
	    } elsif ( $2 eq $delim ) {
		# next item if not quoted
		if ( ! $quoted && ! $bracket ) {
		    ( $v[-1].=$1 ) =~s{\s+$}{}; # strip trailing space
		    push @v,'' ;
		    $v =~m{\G\s+}gc; # skip space after $delim
		} else {
		    $v[-1].=$1.$2
		}
	    }
	} else {
	    # add rest to last from @v
	    $v[-1].= substr($v,pos($v)||0 );
	    last;
	}
    }

    # with delimiter ',' it starts 'Digest realm=...' so $v[0]
    # contains method and first parameter
    my $data = shift(@v);
    if ( $delim eq ',' ) {
	$data =~s{^(\S+)\s*(.*)}{$1};
	unshift @v,$2;
    }
    # rest will be interpreted as parameters with key|key=value
    my %hash;
    foreach my $vv (@v) {
	my ($key,$value) = split( m{\s*=\s*},$vv,2 );
	if ( defined($value) ) {
	    $value =~s{^"(.*)"$}{$1};  # unquote
	    # TODO Q: what's the meaning of "\%04", e.g. is it
	    # '%04' or "\\\004" ??
	    $value =~s{\\(.)}{$1}sg;   # unescape backslashes
	    $value =~s{%([a-fA-F][a-fA-F])}{ chr(hex($1)) }esg; # resolve uri encoding
	}
	$hash{lc($key)} = $value;
    }
    return ($data,\%hash);
}


###########################################################################
# reverse to sip_hdrval2parts
# Args: ($key,$data,\%parameter)
#   $key: normalized key (lowercase, long)
#   $data: initial data
#   %parameter: additional parameter
# Returns: $val
#   $val: value
###########################################################################
sub sip_parts2hdrval {
    my ($key,$data,$param) = @_;

    my $delim = $delimiter{$key} || ';';

    my $val = $data; # FIXME: need to escape $data?
    for my $k ( sort keys %$param ) {
	$val .= $delim.$k;
	my $v = $param->{$k};
	if ( defined $v ) {
	    # escape special chars
	    $v =~s{([%\r\n\t"[:^print:]])}{ sprintf "%%%02x",ord($1) }sg;
	    $v = '"'.$v.'"' if $v =~m{\s|$delim};
	    $val .= '='.$v
	}
    }
    return $val;
}


###########################################################################
# extract parts from SIP URI
# Args: $uri
# Returns: $domain || ($domain,$user,$proto,$param,$data)
#  $domain: SIP domain maybe with port
#  $user:   user part
#  $proto:  'sip'|'sips'
#  $param:  hashref with params, e.g { transport => 'udp',... }
#  $data:   full part before any params
###########################################################################
sub sip_uri2parts {
    my $uri = shift;
    $uri = $1 if $uri =~m{<([^>]+)>\s*$};
    my ($data,$param) = sip_hdrval2parts( uri => $uri );
    if ( $data =~m{^
	(?: (sips?)     : )?
	(?: ([^\s\@]*) \@ )?
	(
	    \[ [^\]\s]+ \] ( : \w+)?          # [ipv46_or_host]:port
	    | [^:\s]+ ( : \w+)?               # ipv4_or_host:port
	    | (?:[a-f\d]*:){2}[a-f\d\.:]*     # ipv6
	)
    $}ix ) {
	my ($proto,$user,$domain) = ($1,$2,$3);
	$domain = lc($domain);
	$proto ||= 'sip';
	return wantarray
	    ? ($domain,$user,lc($proto),$param,$data)
	    : $domain
    } else {
	return;
    }
}


###########################################################################
# reverse to sip_uri2parts, e.g. construct SIP URI
# Args: ($domain,$user,$proto,$param)
#  $domain: SIP domain maybe with port or [host,port,?family]
#  $user:   user part
#  $proto:  'sip'|'sips' - defaults to 'sip'
#  $param:  hashref with params, e.g { transport => 'udp',... }
# Args: $uri
###########################################################################
sub sip_parts2uri {
    my ($domain,$user,$proto,$param) = @_;
    my $uri = sip_parts2hdrval('uri',
	($proto || 'sip'). ':' 
	. ($user ? $user.'@' : '')
	. (ref($domain) ? ip_parts2string(@$domain) : $domain),
	$param
    );
    return $param && %$param ? "<$uri>" : $uri;
}

###########################################################################
# Extract the parts from a URI which are relevant for creating the socket, i.e
#   sips:host:port
#   sip:host;transport=TCP
# Args: $uri,?$opaque
#   $uri:  SIP URI
#   $opaque: don't enforce that host part of URI looks like hostname or IP
# Returns: ($proto,$host,$port,$family)
#   $proto: udp|tcp|tls|undef
#   $host: ip or hostname from URI
#   $port: port from URI
#   $family: family matching $host, i.e. AF_INET|AF_INET6|undef
###########################################################################
sub sip_uri2sockinfo {
    my ($domain,undef,$proto,$param)  = sip_uri2parts(shift())
	or return;
    $proto =
	($proto && $proto eq 'sips') ? 'tls' :           # sips -> tls
	$param->{transport} ? lc($param->{transport}) :  # transport -> tcp|udp
	undef;                                           # not restricted
    return ($proto, ip_string2parts($domain, shift()));
}

###########################################################################
# Reverse to sip_uri2sockinfo
# Args: ($proto,$host,$port,$family)
#   $proto: udp|tcp|tls|undef
#   $host: ip or hostname from URI
#   $port: port from URI
#   $family: family matching $host, i.e. AF_INET|AF_INET6|undef
# Returns: $uri
###########################################################################
sub sip_sockinfo2uri {
    my ($proto,$host,$port,$family) = @_;
    return sip_parts2uri(
	ip_parts2string($host,$port,$family),
	undef,
	!defined $proto ? ('sip',  {}) :
	$proto eq 'tls' ? ('sips', {}) :
	$proto eq 'tcp' ? ('sip',  { transport => 'TCP' }) :
	$proto eq 'udp' ? ('sip',  {}) :
	die "invalid proto: '$proto'"
    )
}

###########################################################################
# returns true if two URIs are the same
# Args: $uri1,$uri2
# Returns: true if both URI point to same address
###########################################################################
sub sip_uri_eq {
    my ($uri1,$uri2) = @_;
    return 1 if $uri1 eq $uri2; # shortcut for common case
    my ($d1,$u1,$p1) = sip_uri2parts($uri1);
    my ($d2,$u2,$p2) = sip_uri2parts($uri2);
    my $port1 = $d1 =~s{:(\d+)$|\[(\d+)\]$}{} ? $1||$2
	: $p1 eq 'sips' ? 5061 : 5060;
    my $port2 = $d2 =~s{:(\d+)$|\[(\d+)\]$}{} ? $1||$2
	: $p2 eq 'sips' ? 5061 : 5060;
    return lc($d1) eq lc($d2)
	&& $port1 == $port2
	&& ( defined($u1) ? defined($u2) && $u1 eq $u2 : ! defined($u2))
	&& $p1 eq $p2;
}

###########################################################################
# fid out local address which is used when connecting to destination
# Args: ($dst,@src)
#  $dst: target IP (or ip:port)
#  @src: optional list of source IP to try, if not given will use any source
# Return: $ip|($ip,$family) - source IP used when reaching destination
# Comment:
#  A UDP socket will be created and connected and then the local address
#  read from the socket. It is expected that the OS kernel will fill in
#  the local address when connecting even though no packets are actually
#  send to the peer
###########################################################################
sub laddr4dst {
    my ($dst,@src) = @_;
    my ($addr, $port, $fam) = ip_string2parts($dst);
    $fam or return;  # no IP destination
    for my $src (@src ? @src : (undef)) {
	my $sock = INETSOCK(
	    Proto => 'udp',
	    Family => $fam,
	    PeerAddr => $addr,
	    PeerPort => $port || 5060,
	    $src ? (LocalAddr => $src) : (),
	) or next;
	my @parts = ip_sockaddr2parts(getsockname($sock));
	return wantarray ? @parts[0,2] : $parts[0];
    }
    return; # no route
}

###########################################################################
# create socket preferable on port 5060 from which one might reach the given IP
# Args: ($dst_addr;$proto)
#  $dst_addr: the adress which must be reachable from this socket
#  $proto: udp|tcp|tls, default udp
# Returns: ($sock,$ip_port) || $sock || ()
#  $sock: the created socket
#  $ip_port: ip:port of socket, only given if called in array context
# Comment: the IP it needs to come from works by creating a udp socket
#  to this host and figuring out it's IP by calling getsockname. Then it
#  tries to create a socket on this IP using port 5060/5061 and if this does
#  not work it tries the port 5062..5100 and if this does not work too
#  it let the system use a random port
#  If creating of socket fails it returns () and $! is set
###########################################################################
sub create_socket_to {
    my ($dst_addr,$proto) = @_;
    $proto ||= 'udp';

    my ($laddr,$fam) = laddr4dst($dst_addr);
    DEBUG( "Local IP is $laddr" );

    # Bind to this IP
    # First try port 5060..5100, if they are all used use any port
    # I get from the system
    for my $p ( $proto eq 'tls' ? 5061:5060, 5062..5100, 0 ) {
	$DEBUG && DEBUG( "try to listen on %s",
	    ip_parts2string($laddr,$p,$fam));
	my $sock = INETSOCK(
	    Family => $fam,
	    LocalAddr => $laddr,
	    $p ? (LocalPort => $p) : (),
	    Proto => $proto eq 'tls' ? 'tcp' : $proto,
	) or next;

	my $port = $p || (ip_sockaddr2parts(getsockname($sock)))[1];
	$DEBUG && DEBUG("listen on %s",ip_parts2string($laddr,$port,$fam));
	return $sock if ! wantarray;
	return ($sock,ip_parts2string($laddr,$port,$fam));
    }
    die "even binding to port 0 failed: $!";
}

###########################################################################
# create RTP/RTCP sockets
# Args: ($laddr;$range,$min,$max,$tries)
#   $laddr: local addr
#   $range: how many sockets, 2 if not defined
#   $min: minimal port number, default $RTP_MIN_PORT
#   $max: maximal port number, default 10000 more than $min
#      or $RTP_MAX_PORT if $min not given
#   $tries: how many tries, default 100
# Returns: ($port,$rtp_sock,$rtcp_sock,@more_socks)
#   $port:      port of RTP socket, port for RTCP is port+1
#   $rtp_sock:  socket for RTP data
#   $rtcp_sock: socket for RTCP data
#   @more_socks: more sockets (if range >2)
###########################################################################
sub create_rtp_sockets {
    my ($laddr,$range,$min,$max,$tries) = @_;
    $range ||= 2;
    if ( ! $min ) {
	$min = $RTP_MIN_PORT;
	$max ||= $RTP_MAX_PORT;
    } else {
	$max ||= $min+10000;
    }
    $min += $min%2; # make even
    $tries ||= 1000;

    my $diff2 = int(($max-$min)/2) - $range +1;

    my (@socks,$port);
    my $fam = (ip_string2parts($laddr))[2];
    while ( $tries-- >0 ) {

	last if @socks == $range;
	close $_ for @socks;
	@socks = ();

	$port = 2*int(rand($diff2)) + $min;
	for( my $i=0;$i<$range;$i++ ) {
	    push @socks, INETSOCK(
		Family => $fam,
		Proto => 'udp',
		LocalAddr => $laddr,
		LocalPort => $port + $i,
	    ) || last;
	}
    }
    return if @socks != $range; # failed
    return ($port,@socks);
}

###########################################################################
# helper to call callback, set variable..
# Args: ($cb;@args)
#  $cb:  callback
#  @args: additional args for callback
# Returns: $rv
#  $rv: return value of callback
# Comment:
# callback can be
# - code ref: will be called with $cb->(@args)
# - object with method run, will be called with $cb->run(@args)
# - array-ref with [ \&sub,@myarg ], will be called with $sub->(@myarg,@args)
# - scalar ref: the scalar will be set to $args[0] if @args, otherwise true
# - regex: returns true if anything in @args matches regex
###########################################################################
sub invoke_callback {
    my ($cb,@more_args) = @_;
    if ( UNIVERSAL::isa( $cb,'CODE' )) {
	# anon sub
	return $cb->(@more_args)
    } elsif ( my $sub = UNIVERSAL::can( $cb,'run' )) {
	# Callback object
	return $sub->($cb,@more_args );
    } elsif ( UNIVERSAL::isa( $cb,'ARRAY' )) {
	my ($sub,@args) = @$cb;
	# [ \&sub,@arg ]
	return $sub->( @args,@more_args );
    } elsif ( UNIVERSAL::isa( $cb,'Regexp' )) {
	@more_args or return;
	for(@more_args) {
	    return 1 if m{$cb}
	}
	return 0;
    } elsif ( UNIVERSAL::isa( $cb,'SCALAR' ) || UNIVERSAL::isa( $cb,'REF' )) {
	# scalar ref, set to true
	$$cb = @more_args ? shift(@more_args) : 1;
	return $$cb;
    } elsif ( $cb ) {
	confess "unknown handler $cb";
    }
}

###########################################################################
# split string into host/ip, port and detect family (IPv4 or IPv6)
# Args: $addr;$opaque
#  $addr: ip_or_host, ipv4_or_host:port, [ip_or_host]:port
#  $opaque: optional argument, if true it will not enforce valid syntax
#     for the hostname and will not return canonicalized data
# Returns: (\%hash|$host,$port,$family)
#  $host:   canonicalized IP address or hostname
#  $port:   the port or undef if no port was given in string
#  $family: AF_INET or AF_INET6 or undef (hostname not IP given)
#  %hash:   hash with addr, port, family - used if !wantarray
###########################################################################
sub ip_string2parts {
    my ($addr,$opaque) = @_;
    my ($host,$port,$family);
    if ($addr =~m{:[^:\s]*(:)?}) {
	if (!$1) {
	    # (ipv4|host):port
	    ($host,$port) = split(':',$addr,2);
	    $family = AF_INET;
	} elsif ($addr =~m{^\[(?:(.*:.*)|([^:]*))\](?::(\w+))?\z}) {
	    $port = $3;
	    ($host,$family) = $1
		? ($1, AF_INET6) # [ipv6](:port)?
		: ($2, AF_INET); # [ipv4|host](:port)?
	} else {
	    # ipv6
	    ($host,$family) = ($addr, AF_INET6);
	}
    } else {
	# ipv4|host
	($host,$family) = ($addr, AF_INET);
    }

    # we now have:
    # AF_INET6 if it contains a ':', i.e. either valid IPv6 or smthg invalid
    # AF_INET  otherwise, i.e. IPv4 or hostname or smthg invalid

    # check if this is an IP address from the expected family
    if ($addr = inet_pton($family,$host)) {
	# valid IP address
	$addr = $opaque ? $host
	    : inet_ntop($family, $addr); # canonicalized form
    } elsif ($opaque) {
	# not a valid IP address - pass through because opaque
	$family = $addr = undef;
    } elsif ($host =~m{^[a-z\d\-\_]+(?:\.[a-z\d\-\_]+)*\.?\z}) {
	# not a valid IP address but valid hostname
	$family = $addr = undef;
    } else {
	# neither IP nor valid hostname
	Carp::confess("invalid hostname '$host' in '$_[0]'");
	die("invalid hostname '$host' in '$_[0]'");
    }

    # make sure that it looks like a valid hostname and return it lower case
    $host = lc($host) if ! $opaque;
    return ($host,$port,$family) if wantarray;
    return {
	host   => $host,
	addr   => $addr,
	port   => $port,
	family => $family
    };

}

###########################################################################
# concat ip/host and port to string, i.e. reverse to ip_string2parts
# Args: ($host;$port,$family,$ipv6_brackets)
#  $host:   the IP address or hostname
#  $port:   optional port
#  $family: optional, will be detected from $host if not given
#  $ipv6_brackets: optional, results in [ipv6] if true and no port given
# alternative Args: (\%hash,$ipv6_brackets)
#  %hash:   hash containing addr|host, port and family and opt. default_port
# Returns: $addr
#  $addr: ip_or_host, ipv4_or_host:port, [ipv6]:port,
#         [ipv6] (if ipv6_brackets)
###########################################################################
sub ip_parts2string {
    my ($host,$port,$fam,$ipv6_brackets);
    if (ref($_[0])) {
	(my $hash,$ipv6_brackets) = @_;
	$port = $hash->{port};
	$fam  = $hash->{family};
	$host = $hash->{addr} || $hash->{host};
	$port = 0 if exists $hash->{default_port}
	    && $port == $hash->{default_port};
    } else {
	($host,$port,$fam,$ipv6_brackets) = @_;
    }
    Carp::confess("empty") if ! $host;
    $host = lc($host);
    return $host if ! $port && !$ipv6_brackets;
    $fam ||= $host =~m{:} && AF_INET6;

    $host = "[$host]" if $fam && $fam != AF_INET;
    return $host if ! $port;
    return $host.':'.$port;
}

###########################################################################
# create sockaddr from IP, port (and family)
# Args: ($ip,$port;$family)
#  $ip:     the IP address
#  $port:   port
#  $family: optional, will be detected from $ip if not given
# alternative Args: \%hash
#  %hash: hash with addr, port, family
# Returns: $sockaddr
###########################################################################
sub ip_parts2sockaddr {
    my ($ip,$port,$fam);
    if (ref($_[0])) {
	$ip   = $_[0]->{addr};
	$port = $_[0]->{port};
	$fam  = $_[0]->{family};
    } else {
	($ip,$port,$fam) = @_;
    }
    $fam ||= $ip =~m{:} ? AF_INET6 : AF_INET;
    if ($fam == AF_INET) {
	return pack_sockaddr_in($port,inet_pton(AF_INET,$ip))
    } elsif (CAN_IPV6) {
	return pack_sockaddr_in6($port,inet_pton(AF_INET6,$ip))
    } else {
	die "no IPv6 support"
    }
}

###########################################################################
# create parts from sockaddr, i.e. reverse to ip_parts2sockaddr
# Args: $sockaddr;$family
#  $sockaddr: sockaddr as returned by getsockname, recvfrom..
#  $family: optional family, otherwise guessed based on size of sockaddr
# Returns: (\%hash | $ip,$port,$family)
#  $ip:     the IP address
#  $port:   port
#  $family: AF_INET or AF_INET6
#  %hash: hash with host, addr, port, family - if not wantarray
###########################################################################
sub ip_sockaddr2parts {
    my ($sockaddr,$fam) = @_;
    $fam ||= length($sockaddr)>=24 ? AF_INET6 : AF_INET;
    die "no IPv6 support" if $fam != AF_INET && !CAN_IPV6;
    my ($port,$addr) = $fam == AF_INET
	? unpack_sockaddr_in($sockaddr)
	: unpack_sockaddr_in6($sockaddr);
    $addr = inet_ntop($fam,$addr);
    return ($addr,$port,$fam) if wantarray;
    return {
	host   => $addr,
	addr   => $addr,
	port   => $port,
	family => $fam,
    };
}

###########################################################################
# gets string from sockaddr, i.e. like ip_parts2string(ip_sockaddr2parts(..))
# Args: $sockaddr;$family
#  $sockaddr: sockaddr as returned by getsockname, recvfrom..
#  $family: optional family, otherwise guessed based on size of sockaddr
# Returns: $string
###########################################################################
sub ip_sockaddr2string {
    my ($sockaddr,$fam) = @_;
    $fam ||= length($sockaddr)>=24 ? AF_INET6 : AF_INET;
    if ($fam == AF_INET) {
	my ($port,$addr) = unpack_sockaddr_in($sockaddr);
	return inet_ntop(AF_INET,$addr) . ":$port";
    } else {
	my ($port,$addr) = unpack_sockaddr_in6($sockaddr);
	return '[' . inet_ntop(AF_INET6,$addr) . "]:$port";
    }
}

###########################################################################
# return name for PTR lookup of given IP address
# Args: $ip;$family
#  $ip: IP address
#  $family: optional family
# Returns: $ptr_name
###########################################################################
sub ip_ptr {
    my ($ip,$family) = @_;
    $family ||= $ip=~m{:} ? AF_INET6 : AF_INET;
    if ($family == AF_INET) {
	return join('.', reverse(unpack("C*",inet_pton(AF_INET,$ip))))
	    . 'in-addr.arpa';
    } else {
	return join('.', reverse(split('',
	    unpack("H*", inet_pton(AF_INET6,$ip)))))
	    . 'ip6.arpa';
    }
}

###########################################################################
# convert IP address into canonical form suitable for comparison
# Args: $ip;$family
#  $ip: IP address
#  $family: optional family
# Returns: $ip_canonical
###########################################################################
sub ip_canonical {
    my ($ip,$family) = @_;
    $family ||= $ip=~m{:} ? AF_INET6 : AF_INET;
    return inet_ntop($family, inet_pton($family, $ip));
}

###########################################################################
# get IP addresses for hostname
# Args: ($name;$family)
#  $name: hostname
#  $family: optional family to restrict result to IPv4/IPv6
# Returns: @ip | $ip - i.e. list of IP or first of the list
###########################################################################
sub hostname2ip {
    my ($name,$family) = @_;
    $family = AF_INET if ! $family && ! CAN_IPV6;
    my ($err,@result) = getaddrinfo($name,undef,
	$family ? ({ family => $family }):() );
    return if $err || ! @result;
    @result = $result[0] if ! wantarray;
    ($_) = ip_sockaddr2parts($_->{addr},$_->{family}) for @result;
    return wantarray ? @result : $result[0]
}

###########################################################################
# check if address is valid IPv4 or IPv6 address
# Args: $ip
# Returns: true|false
###########################################################################
sub ip_is_v4  { inet_pton(AF_INET,  $_[0]) }
sub ip_is_v6  { inet_pton(AF_INET6, $_[0]) }

###########################################################################
# check if address is valid IP address
# Args: $ip
# Returns: AF_INET|AF_INET6|undef
###########################################################################
sub ip_is_v46 {
    return
	inet_pton(AF_INET,  $_[0]) ? AF_INET  :
	inet_pton(AF_INET6, $_[0]) ? AF_INET6 :
	undef;
}

1;
