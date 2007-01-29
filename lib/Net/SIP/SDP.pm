###########################################################################
# Net::SIP::SDP
# parse and manipulation of SDP packets in the context relevant for SIP
# Spec:
# RFC2327 - base RFC for SDP
# RFC3264 - offer/answer model with SDP (used in SIP RFC3261)
# RFC3266 - IP6 in SDP
# RFC3605 - "a=rtcp:port" Attribut. UNSUPPORTED!!!!
###########################################################################

use strict;
use warnings;
package Net::SIP::SDP;
use Hash::Util qw(lock_keys);
use Net::SIP::Debug;


###########################################################################
# create new Net::SIP::SDP packet from string or parts
# Args: see new_from_parts|new_from_string
# Returns: $self
###########################################################################
sub new {
	my $class = shift;
	return $class->new_from_parts(@_) if @_>1;
	my $data = shift;
	return ( !ref($data) || UNIVERSAL::isa( $data,'ARRAY' ))
		?  $class->new_from_string( $data )
		: $class->new_from_parts( $data );
}

###########################################################################
# create new Net::SIP::SDP packet from parts
# Args: ($class,$global,@media)
#   $global: \%hash of (key,val) for global section, val can be
#       scalar or array-ref (for multiple val). keys can be the
#       on-letter SDP keys and the special key 'addr' for constructing
#       a connection-field
#   @media: list of \%hashes. val in hash can be scalar or array-ref
#       (for multiple val), keys can be on-letter SDP keys or the special
#       keys addr (for connection-field), port,range,proto,media,fmt (for
#       media description)
# Returns: $self
###########################################################################
sub new_from_parts {
	my ($class,$global,@media) = @_;

	my %g = %$global;
	my $g_addr = delete $g{addr};
	die "no support for time rates" if $g{r};
	$g{c} = "IN IP4 $g_addr" if $g_addr && !$g{c};
	$g{t} = "0 0" if !$g{t};

	my @gl;
	my %global_self = ( lines => \@gl, addr => $g_addr );
	lock_keys(%global_self);

	my @media_self;
	my $self = bless {
		global => \%global_self,
		addr => $g_addr,
		media => \@media_self
	},$class;
	lock_keys(%$self);

	# first comes the version
	push @gl,[ 'v',delete($g{v}) || 0 ];

	# then the origin
	my $o = delete($g{o});
	if ( !$o ) {
		my $t = time();
		$o = "anonymous $t $t IN IP4 ".( $g_addr || '127.0.0.1' );
	}
	push @gl,[ 'o',$o ];

	# session name
	push @gl,[ 's', delete($g{s}) || 'session' ];

	# various headers in the right order
	foreach my $key (qw( i u e p c b t z k a )) {
		my $v = delete $g{$key};
		defined($v) || next;
		foreach ( ref($v) ? @$v:($v) ) {
			push @gl, [ $key,$_ ];
		}
	}

	# die on unknown keys
	die "bad keys in global: ".join( ' ',keys(%g)) if %g;

	# media descriptions
	foreach my $m (@media) {
		DEBUG_DUMP( $m );
		my %m = %$m;
		my @lines;
		my %m_self = ( lines => \@lines );

		# extract from 'm' line or from other args
		if ( my $mline = delete $m{m} ) {
			push @lines,[ 'm',$mline ];
			@m_self{qw(media port range proto fmt)} = _split_m( $mline );
		} else {
			foreach (qw( port media proto )) {
				defined( $m_self{$_} = delete $m{$_} )
					|| die "no $_ in media description";
			}
			$m_self{range} = delete($m{range})
				|| $m_self{proto} eq 'RTP/AVP' ? 2:1;
			defined( my $fmt = delete $m{fmt} )
				|| die "no fmt in media description";
			my $mline = _join_m( @m_self{qw(media port range proto)},$fmt );
			push @lines, [ 'm',$mline ];
		}

		# if no connection line given construct one, if addr ne g_addr
		if ( !$m{c} ) {
			if ( my $addr = delete $m{addr} ) {
				$m_self{addr} = $addr;
				$m{c} = _join_c($addr) if $addr ne $g_addr;
			} elsif ( $g_addr ) {
				$m_self{addr} = $g_addr;
			} else {
				die "neither local nor global address for media";
			}
		} else {
			$m_self{addr} = _split_c($m{c});
		}

		# various headers in the right order
		foreach my $key (qw( i c b k a )) {
			my $v = delete $m{$key};
			defined($v) || next;
			foreach ( ref($v) ? @$v:($v) ) {
				push @lines, [ $key,$_ ];
			}
		}
		# die on unknown keys
		die "bad keys in media: ".join( ' ',keys(%m)) if %m;

		lock_keys(%m_self);
		push @media_self,\%m_self;
	}

	return $self;
}


###########################################################################
# create new Net::SIP::SDP packet from string or lines
# Args: ($class,$string)
#    $string: either scalar or \@list_of_lines_in_string
# Returns: $self
###########################################################################
sub new_from_string {
	my ($class,$string) = @_;

	# split into lines
	Carp::confess('bla' ) if ref( $string ) eq 'HASH';
	my @lines = ref($string)
		? @$string
		: split( m{\r?\n}, $string );

	# split lines into key,val
	foreach my $l (@lines) {
		my ($key,$val) = $l=~m{^([a-z])=(.*)}
			or die "bad SDP line '$l'";
		$l = [ $key,$val ];
	}

	# SELF:
	# global {
	#   lines => [],
	#   addr     # globally defined addr (if any)
	# }
	# media [
	#   {
	#     lines => [],
	#     addr   # addr for ports
	#     port   # starting port
	#     range  # range of ports (1..)
	#     proto  # udp, RTP/AVP,..
	#     media  # audio|video|data...
	#   }
	# ]

	my (%global,@media);
	my $self = bless {
		global => \%global,
		addr => undef,
		session_id => undef,
		session_version => undef,
		media => \@media
	}, $class;
	lock_keys(%$self);
	my $gl = $global{lines} = [];

	# first line must be version
	my $line = shift(@lines);
	$line->[0] eq 'v' || die "missing version";
	$line->[1] eq '0' || die "bad SDP version $line->[1]";
	push @$gl,$line;

	# second line must be origin
	# "o=" username sess-id sess-version nettype addrtype addr
	$line = shift(@lines);
	$line->[0] eq 'o' || die "missing origin";
	(undef,$self->{session_id},$self->{session_version})
		= split( ' ',$line->[1] );
	push @$gl,$line;

	# skip until c or m line
	my $have_c =0;
	while ( $line = shift(@lines) ) {

		# end of global section, beginning of media section
		last if $line->[0] eq 'm';

		push @$gl,$line;
		if ( $line->[0] eq 'c' ) {
			# "c=" nettype addrtype connection-address
			$have_c++ && die "multiple global [c]onnection fields";
			$global{addr} = _split_c( $line->[1] );
		}
	}

	# parse media section(s)
	# $line has already first m-Element in it

	while ($line) {

		$line->[0] eq 'm' || die "expected [m]edia line";
		# "m=" media port ["/" integer] proto 1*fmt
		my ($media,$port,$range,$proto,$fmt) = _split_m( $line->[1] );

		my $ml = [ $line ];
		my %m = (
			lines => $ml,
			addr  => $global{addr},
			port  => $port,
			range => $range || 1,
			media => $media,
			proto => $proto,
			fmt   => $fmt,
		);
		lock_keys(%m);
		push @media,\%m;

		# find out connection
		my $have_c = 0;
		while ( $line = shift(@lines) ) {

			# next media section
			last if $line->[0] eq 'm';

			push @$ml,$line;
			if ( $line->[0] eq 'c' ) {
				# connection-field
				$have_c++ && die "multiple [c]onnection fields in media section $#media";
				$m{addr} = _split_c( $line->[1] );
			}
		}
	}

	return $self;
}


###########################################################################
# get SDP data as string
# Args: $self
# Returns: $string
###########################################################################
sub as_string {
	my $self = shift;
	my $data = '';
	foreach (@{ $self->{global}{lines}} ) {
		$data .= $_->[0].'='.$_->[1]."\r\n";
	}
	if ( my $media = $self->{media} ) {
		foreach my $m (@$media) {
			foreach (@{ $m->{lines} }) {
				$data .= $_->[0].'='.$_->[1]."\r\n";
			}
		}
	}
	return $data;
}

sub content_type { return 'application/sdp' };

###########################################################################
# extracts media infos
# Args: $self
# Returns: @media|$media
#  @media: list of hashes with the following keys:
#     addr:  IP4/IP6 addr
#     port:  the starting port number
#     range: number, how many ports starting with port should be allocated
#     proto: media proto, e.g. udp or RTP/AVP
#     media: audio|video|data|... from the media description
#     fmt:   format(s) from media line
#     lines: \@list with all lines from media description as [ key,value ]
#            useful to access [a]ttributes or encryption [k]eys
#  $media: \@media if in scalar context
# Comment: do not manipulate the result!!!
###########################################################################
sub get_media {
	my $self = shift;
	my $m = $self->{media} || [];
	return wantarray ? @$m : $m;
}

###########################################################################
# replace the addr and port (eg where it will listen) from the media in
# the SDP packet
# used for remapping by a proxy for NAT or inspection etc.
# Args: ($self,@replace)
#   @replace: @list of [ addr,port ] or list with single array-ref to such list
#      size of list must be the same like one gets from get_media, e.g.
#      there must be a mapping for each media
# Comment: die() on error
###########################################################################
sub replace_media_listen {
	my ($self,@replace) = @_;

	if (@replace == 1) {
		# check if [ $pair1,$pair2,.. ] instead of ( $pair1,.. )
		@replace = @{$replace[0]} if ref($replace[0][0]);
	}

	my $media = $self->{media} || [];
	die "media count mismatch in replace_media_listen" if @replace != @$media;

	my $global = $self->{global};
	my $g_addr = $global->{addr};

	# try to remap global connection-field
	if ( $g_addr ) {

		# find mappings old -> new
		my %addr_old2new;
		for( my $i=0;$i<@$media;$i++ ) {
			$addr_old2new{ $media->[$i]{addr} }{ $replace[$i][0] }++
		}
		my $h = $addr_old2new{ $g_addr };

		if ( $h && keys(%$h) == 1 ) {
			# there is a uniq mapping from old to new address
			my $new_addr = (keys(%$h))[0];
			if ( $g_addr ne $new_addr ) {
				$g_addr = $global->{addr} = $new_addr;

				# find connection-field and replace address
				foreach my $line (@{ $global->{lines} }) {
					if ( $line->[0] eq 'c' ) {
						$line->[1] = _join_c( $new_addr );
						last; # there is only one connection-field
					}
				}
			}

		} else {
			# the is no uniq mapping from old to new
			# this can be because old connection-field was never used
			# (because each media section had it's own) or that
			# different new addr gets used for the same old addr
			# -> remove global connection line

			$g_addr = $global->{addr} = undef;
			my $l = $global->{lines};
			@$l = grep { $_->[0] ne 'c' } @$l;
		}
	}

	# remap addr,port in each media section
	# if new addr is != $g_addr and I had no connection-field
	# before I need to add one
	for( my $i=0;$i<@$media;$i++ ) {

		my $m = $media->[$i];
		my $r = $replace[$i];

		# replace port in media line
		if ( $r->[1] != $m->{port} ) {
			$m->{port} = $r->[1];

			# [m]edia line should be the first
			my $line = $m->{lines}[0];
			$line->[0] eq 'm' || die "[m]edia line is not first";

			# media port(/range)...
			if ( $r->[1] ) {
				# port!=0: replace port only
				$line->[1] =~s{^(\S+\s+)\d+}{$1$r->[1]};
			} else {
				# port == 0: replace port and range with '0'
				$line->[1] =~s{^(\S+\s+)\S+}{${1}0};
			}
		}

		# replace addr in connection line
		if ( $r->[0] ne $m->{addr} ) {
			$m->{addr} = $r->[0];
			my $have_c = 0;
			foreach my $line (@{ $m->{lines} }) {
				if ( $line->[0] eq 'c' ) {
					$have_c++;
					$line->[1] = _join_c($r->[0]);
					last; # there is only one connection-field
				}
			}
			if ( !$have_c && ( ! $g_addr || $r->[0] ne $g_addr )) {
				# there was no connection-field before
				# and the media addr is different from the global
				push @{ $m->{lines} },[ 'c', _join_c( $r->[0] ) ];
			}
		}
	}
}


###########################################################################
# extract addr from [c]connection field and back
###########################################################################
sub _split_c {
	my ($ntyp,$atyp,$addr) = split( ' ',shift,3 );
	$ntyp eq 'IN'  or die "nettype $ntyp not supported";
	$atyp eq 'IP4' || $atyp eq 'IP6' or die "addrtype $atyp not supported";
	return $addr;
}
sub _join_c {
	my $addr = shift;
	my $atyp = $addr =~m{^[a-fA-F:\.]+$} ? 'IP6':'IP4';
	return "IN $atyp $addr";
}


###########################################################################
# extract data from [m]edia field and back
###########################################################################
sub _split_m {
	my $mline = shift;
	my ($media,$port,$range,$proto,$fmt) =
		$mline =~m{^(\w+)\s+(\d+)(?:/(\d+))?\s+(\S+)((?:\s+\S+)+)}
		or die "bad [m]edia: '$mline'";
	$range ||= 1;
	$range *=2 if $proto eq 'RTP/AVP'; # RTP+RTCP
	return ($media,$port,$range,$proto, [ split( ' ',$fmt) ]);
}

sub _join_m {
	my ($media,$port,$range,$proto,@fmt) = @_;
	@fmt = @{$fmt[0]} if @fmt == 1 && ref($fmt[0]);
	$range /= 2 if $proto eq 'RTP/AVP';
	$port .= "/$range" if $range>1;
	return join( ' ',$media,$port,$proto,@fmt );
}

1;
