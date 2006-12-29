
###########################################################################
# package Net::SIP::Packet
# SIP packets are either requests or responses
# the constructor can create objects from packet strings or from
# hash/array description, in both cases one can later retrieve 
# a string representation or a hash/array representation of the
# packet
# Packets can be manipulated, e.g add, delete or modify header
# elements or body.
###########################################################################

use strict;
use warnings;
package Net::SIP::Packet;
use Net::SIP::Debug;
use Storable;
use Net::SIP::SDP;

use fields qw( code text header lines body as_string );

# code: response code (numeric) or request method
# text: response text or request URI
# body: scalar with body
# as_string: string representation
# lines: array-ref or [ original_header_lines, number_of_parts ]
# header: array-ref of Net::SIP::HeaderPair




###########################################################################
# Constructor
# Creates new object. If there was only one argument it will interprete
# it as a string representation (see new_from_string), otherwise it will 
# assume a hash/array representation (see new_from_parts)
# Args: see new_from_string|new_from_parts
# Returns: $self
###########################################################################
sub new {
	my $class = shift;
	return @_>1 
		? $class->new_from_parts(@_) 
		: $class->new_from_string(@_);
}

###########################################################################
# create new object from parts
# Args: ($class,$code,$text,$header,$body)
#   $code:   Response code or request method
#   $text:   Response text or request URI
#   $header: Header representation as array or hash
#            either [ [key1 => val2],[key2 => val2],... ] where the same
#            key can occure multiple times 
#            or { key1 => val1, key2 => val2 } where val can be either
#            a scalar or an array-ref (if the same key has multiple values)
#   $body:   Body as string
# Returns: $self
# Comment:
# if $class is Net::SIP::Packet $self will be either Net::SIP::Request
# or Net::SIP::Response (both are subclasses from Net::SIP::Packet) depending
# if it is a request or response
###########################################################################
sub new_from_parts {
	my ($class,$code,$text,$header,$body) = @_;

	# header can be hash-ref or array-ref
	# if hash-ref convert it to array-ref sorted by key
	# (sort just to make the result predictable)
	if ( UNIVERSAL::isa( $header,'HASH' )) {
		my @hnew;
		foreach my $key ( sort keys %$header ) {
			my $v = $header->{$key};
			foreach my $value ( ref($v) ? @$v : ($v) ) {
				push @hnew,[ $key,$value ];
			}
		}
		$header = \@hnew;
	}

	my $self = fields::new($class);
	my $rebless;
	if ( $code =~m{^\d} ) {
		# Response
		$self->{code} = $code;
		$self->{text} = defined($text) ? $text:'';
		$rebless = 'Net::SIP::Response';
	} else {
		# Request
		$self->{code} = uc($code);                             # uppercase method
		$self->{text} = defined($text) ? $text:'';
		$rebless = 'Net::SIP::Request';
	}

	# rebless to Net::SIP::{Request,Response}
	bless $self,$rebless if $class eq 'Net::SIP::Packet';

	# $self->{header} is list of Net::SIP::HeaderPair which cares about normalized
	# keys while maintaining the original key, so that one can restore header
	# the elements from @$header can be either [ key,value ] or Net::SIP::HeaderPair's
	# but have to be all from the same type
	my @hnew;
	my $normalized = 0;
	for( my $i=0;$i<@$header;$i++ ) {
		my ($key,$value,$orig_key) = @{ $header->[$i] };
		defined($value) || next;
		if ( $orig_key ) {
			# assume it's already normalized
			push @hnew, $header->[$i];
			$normalized = 1;
		} else {
			die "mix between normalized and not normalized data in header" if $normalized;
			push @hnew, Net::SIP::HeaderPair->new( $key,$value ) ;
		}
	}

	$self->{header} = \@hnew;
	# as_string is still undef, it will be evaluated once we call as_string()

	if ( ref($body)) {
		if ( !$self->get_header( 'content-type' )) {
			$self->set_header( 'content-type' => $body->content_type )
		}
		$body = $body->as_string;
	}
	$self->{body}   = $body;

	return $self;
}

###########################################################################
# Create new packet from string
# Args: ($class,$string)
#    $string: String representation of packet
# Returns: $self
# Comment:
#    for the class of $self see comment in new_from_parts above
###########################################################################
sub new_from_string {
	my ($class,$string) = @_;
	my $self = fields::new($class);
	$self->{as_string} = $string;
	if ( $class eq 'Net::SIP::Packet' ) {
		# rebless
		# as a side effect is_request will parse string so that code,header etc
		# will be set
		bless $self,( $self->is_request ? 'Net::SIP::Request':'Net::SIP::Response' );
	}
	return $self;
}

###########################################################################
# Find out if it is a request
# Args: $self
# Returns: 1 if it's a request
###########################################################################
sub is_request {
	my $self = shift;
	$self->{code} || $self->as_parts();
	return $self->{code} !~m{^\d}
}

###########################################################################
# Find out if it is a response
# Args: $self
# Returns: 1 if it's a response
###########################################################################
sub is_response { 
	return ! shift->is_request() 
}


###########################################################################
# Return transaction Id of packet, consisting of the call-id and
# the CSeq num. Method is not included because ACK or CANCEL requests
# belong to the same transaction as the INVITE
# Responses have the same TID as the request
# Args: $self
# Returns: $tid
###########################################################################
sub tid {
	my Net::SIP::Packet $self = shift;
	$self->get_header( 'cseq' ) =~m{^(\d+)};
	return $self->get_header( 'call-id' ).' '.$1;
}

###########################################################################
# Accessors for Headerelements
###########################################################################

###########################################################################
# Access cseq Header
# Args: $self
# Returns: $cseq_value
###########################################################################
sub cseq { scalar( shift->get_header('cseq')) }

###########################################################################
# Access call-id Header
# Args: $self
# Returns: $callid
###########################################################################
sub callid { scalar( shift->get_header('call-id')) }

###########################################################################
# Access header
# Args: ($self; $key)
#  $key: (optional) which headerkey to access
# Returns: @val|\%header
#   @val: if key given returns all values for this key
#      die()s if in scalar context and I've more then one value for the key
#   \%header: if no key given returns hash with 
#      { key1 => \@val1, key2 => \@val2,.. }
###########################################################################
sub get_header {
	my ($self,$key) = @_;
	my $hdr = ($self->as_parts)[2];
	if ( $key ) {
		$key = _normalize_hdrkey($key);
		my @v;
		foreach my $h (@$hdr) {
			push @v,$h->{value} if $h->{key} eq $key;
		}
		return @v if wantarray;
		die "multiple values for $key" if @v>1;
		return $v[0];
	} else {
		my %result;
		foreach my $h (@$hdr) {
			push @{ $result{$h->{key}} }, $h->{value};
		}
		return \%result;
	}
}

###########################################################################
# get header as Net::SIP::HeaderVal
# like get_header, but instead of giving scalar values gives Net::SIP::HeaderVal
# objects which have various accessors, like extracting the parameters
# Args: ($self; $key)
#  $key: (optional) which headerkey to access
# Returns: @val|\%header
#   @val: if key given returns all values (Net::SIP::HeaderVal) for this key
#      die()s if in scalar context and I've more then one value for the key
#   \%header: if no key given returns hash with 
#      { key1 => \@val1, key2 => \@val2,.. } where val are Net::SIP::HeaderVal
###########################################################################
sub get_header_hashval {
	my ($self,$key) = @_;
	my $hdr = ($self->as_parts)[2];
	if ( $key ) {
		$key = _normalize_hdrkey($key);
		my @v;
		foreach my $h (@$hdr) {
			push @v,Net::SIP::HeaderVal->new( $h )
				if $h->{key} eq $key;
		}
		return @v if wantarray;
		die "multiple values for $key" if @v>1;
		return $v[0];
	} else {
		my %result;
		foreach my $h (@$hdr) {
			push @{ $result{$h->{key}} }, 
				Net::SIP::HeaderVal->new( $h );
		}
		return \%result;
	}
}

###########################################################################
# Add header to SIP packet, headers gets added after all other headers
# Args: ($self,$key,$val)
#   $key: Header key
#   $val: scalar or \@array which contains value(s)
###########################################################################
sub add_header {
	my ($self,$key,$val) = @_;
	my $hdr = ($self->as_parts)[2];
	foreach my $v ( ref($val) ? @$val:$val ) {
		### TODO: should add quoting to $v if necessary
		push @$hdr, Net::SIP::HeaderPair->new( $key,$v );
	}
	$self->_update_string();
}

###########################################################################
# Add header to SIP packet, header gets added before all other headers
# Args: ($self,$key,$val)
#   $key: Header key
#   $val: scalar or \@array which contains value(s)
###########################################################################
sub insert_header {
	my ($self,$key,$val) = @_;
	my $hdr = ($self->as_parts)[2];
	foreach my $v ( ref($val) ? @$val:$val ) {
		### TODO: should add quoting to $v if necessary
		unshift @$hdr, Net::SIP::HeaderPair->new( $key,$v );
	}
	$self->_update_string();
}

###########################################################################
# Delete all headers for a key
# Args: ($self,$key)
###########################################################################
sub del_header {
	my ($self,$key) = @_;
	$key = _normalize_hdrkey($key);
	my $hdr = ($self->as_parts)[2];
	@$hdr = grep { $_->{key} ne $key } @$hdr;
	$self->_update_string();
}

###########################################################################
# Set header for key to val, e.g. delete all remaining headers for key
# Args: ($self,$key,$val)
#   $key: Header key
#   $val: scalar or \@array which contains value(s)
###########################################################################
sub set_header {
	my ($self,$key,$val) = @_;
	$key = _normalize_hdrkey($key);
	# del_header
	my $hdr = ($self->as_parts)[2];
	@$hdr = grep { $_->{key} ne $key } @$hdr;
	# add_header
	foreach my $v ( ref($val) ? @$val:$val ) {
		### TODO: should add quoting to $v if necessary
		push @$hdr, Net::SIP::HeaderPair->new( $key,$v );
	}
	$self->_update_string();
}

###########################################################################
# set the body
# Args: ($self,$body)
#  $body: string or object with method as_string (like Net::SIP::SDP)
# Returns: NONE
###########################################################################
sub set_body {
	my ($self,$body) = @_;
	$body = $body->as_string if ref($body);
	$self->as_parts;
	$self->{body} = $body;
	$self->_update_string();
}

###########################################################################
# Iterate over all headers with sup and remove or manipulate them
# Args: ($self,@arg)
#  @arg: either $key => $sub or only $sub
#    if $key is given only headers for this key gets modified
#    $sub is either \&code or [ \&code, @args ]
#    code gets $pair (Net::SIP::HeaderPair) as last parameter
#    to remove header it should call $pair->remove, if it modify
#    header it should call $pair->set_modified
###########################################################################
sub scan_header {
	my Net::SIP::Packet $self = shift;
	my $key = _normalize_hdrkey(shift) if @_>1;
	my $sub = shift;

	($sub, my @args) = ref($sub) eq 'CODE' ? ($sub):@$sub;

	my $hdr = ($self->as_parts)[2];
	foreach my $h (@$hdr) {
		next if $key && $h->{key} ne $key;
		# in-place modify or delete (set key to undef)
		$sub->(@args,$h);
	}
	# remove deleted entries ( !key ) from @$hdr
	@$hdr = grep { $_->{key} } @$hdr;
	$self->_update_string();
}

###########################################################################
# Return packet as string
# tries to restore as much as possible from original packet (if created
# from string)
# Args: $self
# Returns: $packet_as_string
###########################################################################
sub as_string {
	my $self = shift;

	# check if content-length header is up-to-date
	my $body = $self->{body} || '';
	my $cl = $self->get_header( 'content-length' );
	if ( defined($cl) && $cl != length($body) ) {
		$self->set_header( 'content-length',length($body))
	}

	# return immediatly if request is up to date
	return $self->{as_string} if $self->{as_string}; 

	my $header = $self->{header};

	# check if the lines from the original packet (if created
	# from string, see as_parts) are up-to-date
	my @result;
	if ( my $lines = $self->{lines} ) {
		for (my $i=0;$i<@$lines;$i++ ) {
			my ($line,$count) = @{ $lines->[$i] || next };

			# check if $count entries for line-index $i in headers
			my @hi = grep { 
				my $line = $header->[$_]{line};
				( defined($line) && $line == $i ) ? 1:0;
			} (0..$#$header);
			if ( @hi == $count ) {
				# assume that line wasn't changed because the count is right
				$result[ $hi[0] ] = $line;
			} elsif ( @hi ) {
				# some parts from this line have been modified
				# place remaining parts back to same line
				my $v = join( ", ", map { $header->[$_]{value} } @hi );
				$v  =~s{\r?\n\s*}{\r\n }g; # \r?\n\s* -> \r\n + space for continuation lines
				my $r = $result[ $hi[0] ] = $header->[ $hi[0] ]{orig_key}.": ".$v;
				$lines->[$i] = [ $r,int(@hi) ]; # and update $lines
			} else {
				# nothing remaining from line $i, update lines
				delete $lines->[$i];
			}
		}
	}

	# all lines from $header which had a defined line index should have been
	# handled by the code above, now care about the lines w/o defined line
	foreach my $hi ( grep { !defined( $header->[$_]{line} ) } (0..$#$header) ) {

		my $v = $header->[$hi]{value};
		$v =~s{\r?\n\s*}{\r\n }g; # \r?\n\s* -> \r\n + space for continuation lines
		$result[$hi] = $header->[$hi]{key}.": ".$v;
	}

	# (re)build packet
	my $hdr_string = $self->{code} =~m{^\d}
		? "SIP/2.0 $self->{code} $self->{text}\r\n"   # Response
		: "$self->{code} $self->{text} SIP/2.0\r\n"   # Request
		;

	$hdr_string .= join( "\r\n", grep { $_ } @result )."\r\n";

	# add content-length header if there was none
	$hdr_string .= sprintf( "Content-length: %d\r\n", length( $body ))
		if !defined($cl);

	return ( $self->{as_string} = $hdr_string."\r\n".$body );
}

###########################################################################
# Return parts
# Args: ($self)
# Returns: ($code,$text,$header,$body)
#   $code:   Response code or request method
#   $text:   Response text or request URI
#   $header: Header representation as array 
#            [ [key1 => val2],[key2 => val2],... ] where the same
#            key can occure multiple times 
#   $body:   Body as string
# Comment:
# Output from this method is directly usable as input to new_from_parts
###########################################################################
sub as_parts {
	my $self = shift;
	
	# if parts are up to date return immediatly
	return @{$self}{qw(code text header body)} if $self->{code};

	# otherwise parse request
	my ($header,$body) = split( m{\r?\n\r?\n}, $self->{as_string},2 );
	my @header = split( m{\r?\n}, $header );

	if ( $header[0] =~m{^SIP/2.0\s+(\d+)\s+(\S.*?)\s*$} ) {
		# Response, e.g. SIP/2.0 407 Authorization required
		$self->{code} = $1;
		$self->{text} = $2;
	} elsif ( $header[0] =~m{^(\w+)\s+(\S.*?)\s+SIP/2\.0\s*$} ) {
		# Request, e.g. INVITE <sip:bla@fasel> SIP/2.0
		$self->{code} = $1;
		$self->{text} = $2;
	} else {
		die "bad request: starts with '$header[0]'";
	}
	shift(@header);

	$self->{body} = $body;
	
	my @hdr;
	my @lines;
	while (@header) {
		my ($k,$v) = $header[0] =~m{^([^\s:]+)\s*:\s*(.*)}
			or die "bad header line $header[0]";
		my $line = shift(@header);
		while ( @header && $header[0] =~m{^\s+(.*)} ) {
			# continuation line
			$v .= "\n$1";
			$line .= shift(@header);
		}
		my $nk = _normalize_hdrkey($k);

		my @v;
		if ( $nk eq 'www-authenticate'
			|| $nk eq 'proxy-authenticate'
			|| $nk eq 'authorization'
			|| $nk eq 'proxy-authorization' ) {
			# don't split on ','
			@v = $v;
		} else {
			# split on komma (but not if quoted)
			push @v,'';
			my $quoted = 0;
			while (1) {
				if ( $v =~m{\G(.*?)([\\",])}gc ) {
					if ( $2 eq "\\" ) {
						$v[-1].=$1.$2.substr( $v,pos($v),1 );
						pos($v)++;
					} elsif ( $2 eq '"' ) {
						$v[-1].=$1.$2;
						$quoted = !$quoted;
					} elsif ( $2 eq ',' ) {
						# next item if not quoted
						( $v[-1].=$1 ) =~s{\s+$}{}; # strip trailing space
						push @v,'' if !$quoted;
						$v =~m{\G\s+}gc; # skip space after ','
					}
				} else {
					# add rest to last from @v
					$v[-1].= substr($v,pos($v)||0 );
					last;
				}
			}
		}
		if ( @v>1 ) {
			for( my $i=0;$i<@v;$i++ ) {
				push @hdr, Net::SIP::HeaderPair->new( $k,$v[$i],scalar(@lines),$i );
			}
		} else {
			push @hdr, Net::SIP::HeaderPair->new( $k,$v[0],scalar(@lines) );
		}
		push @lines, [ $line, int(@v) ];
	}
	$self->{header} = \@hdr;
	$self->{lines}  = \@lines;

	return @{$self}{qw( code text header body )};
}

###########################################################################
# return SDP body
# Args: $self
# Returns: $body
#   $body: Net::SIP::SDP object if body exists and content-type is
#     application/sdp (or not defined)
###########################################################################
sub sdp_body {
	my Net::SIP::Packet $self = shift;
	my $ct = $self->get_header( 'content-type' );
	return if $ct && $ct ne 'application/sdp';
	my $body = ($self->as_parts)[3] || return;
	return Net::SIP::SDP->new( $body );
}

###########################################################################
# clone packet, so that modification does not affect the original
# Args: $self
# Returns: $clone
###########################################################################
sub clone {
	return Storable::dclone( shift );
}

###########################################################################
# Trigger updating parts, e.g. code, header...
# done by setting code as undef if as_string is set, so the next time
# I'll try to access code it will be recalculated from string
# Args: $self
###########################################################################
sub _update_parts {
	my $self = shift;
	$self->{code} = undef if $self->{as_string};
}

###########################################################################
# Trigger updating string
# done by setting as_string as undef if code is set, so the next time
# I'll try to access as_string it will be recalculated from the parts
# Args: $self
###########################################################################
sub _update_string {
	my $self = shift;
	$self->{as_string} = undef if $self->{code};
}

###########################################################################
# access _normalize_hdrkey function from Net::SIP::HeaderPair
# Args: $key
# Returns: $key_normalized
###########################################################################
sub _normalize_hdrkey { 
	goto &Net::SIP::HeaderPair::_normalize_hdrkey 
}

###########################################################################
# Net::SIP::HeaderPair
# container for normalized key,value and some infos to restore
# string representation
###########################################################################

package Net::SIP::HeaderPair;
use fields qw( key value orig_key line pos );

#   key:       normalized key: lower case, not compact
#   value:     value
#   orig_key:  original key: can be mixed case and compact
#   line:      index of header line within original request
#   pos:       relativ position in line (starting with 0) if multiple
#              values are given in one line

###########################################################################
# Create new HeaderPair
# Args: ($class,$key,$value,$line,$pos)
#   $key: orginal key
#   $value: value
#   $line: index of header line in orginal header
#   $pos: index within header line if multiple values are in line
# Returns: $self
###########################################################################
sub new {
	my ($class,$key,$value,$line,$pos) = @_;
	my $self = fields::new( $class );
	$self->{key} = _normalize_hdrkey( $key);
	$self->{value} = $value;
	$self->{orig_key} = $key;
	$self->{line} = $line;
	$self->{pos} = $pos;
	return $self;
}

###########################################################################
# Mark HeaderPair as removed by setting key to undef
# used from Net::SIP:Packet::scan_header
# Args: $self
###########################################################################
sub remove {
	# mark es removed
	shift->{key} = undef
}

###########################################################################
# Mark HeaderPair as modified by setting line to undef and thus deassociating
# it from the original header line
# Args: $self
###########################################################################
sub set_modified {
	# mark as modified
	my $self = shift;
	$self->{line} = $self->{pos} = undef;
}


{
	my %alias = (
		i => 'call-id',
		m => 'contact',
		e => 'content-encoding',
		l => 'content-length',
		c => 'content-type',
		f => 'from',
		s => 'subject',
		k => 'supported',
		t => 'to',
		v => 'via',
	);
	sub _normalize_hdrkey {
		my $key = lc(shift);
		return $alias{$key} || $key;
	}
}


###########################################################################
# Net::SIP::HeaderVal;
# gives string representation and hash representation 
# (split by ';' or ',') of header value
###########################################################################

package Net::SIP::HeaderVal;
use Net::SIP::Util qw(sip_hdrval2parts);
use fields qw( data parameter );

#    WWW-Authenticate: Digest method="md5",qop="auth",...
#    To: Bob Example <sip:bob@example.com>;tag=2626262;...
#
# data: the part before the first argument, e.g. "Digest" or
#    "Bob Example <sip:bob@example.com>"
# parameter: hash of parameters, e.g { method => md5, qop => auth }
#    or { tag => 2626262, ... }

###########################################################################
# create new object from string
# knows which headers have ',' as delimiter and the rest uses ';'
# Args: ($class,$pair)
#   $pair: Net::SIP::HeaderPair
# Returns: $self
###########################################################################
sub new {
	my $class = shift;
	my Net::SIP::HeaderPair $pair = shift;
	my $key = $pair->{key};
	my $v = $pair->{value};

	my $self = fields::new($class);
	($self->{data}, $self->{parameter}) = sip_hdrval2parts( $key,$v );

	return $self;
}




1;
