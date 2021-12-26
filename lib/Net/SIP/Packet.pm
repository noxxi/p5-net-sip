###########################################################################
# Net::SIP::Packet
# parsing, creating and manipulating of SIP packets
###########################################################################

use strict;
use warnings;

package Net::SIP::Packet;

use Net::SIP::Debug;
use Storable;
use Net::SIP::SDP;
use Net::SIP::Util qw(mime_parse);
use Carp 'croak';

use fields qw( code method text header lines body as_string );

# code: numeric response code in responses
# method request method in requests
# text: response text or request URI
# body: scalar with body
# as_string: string representation
# lines: array-ref or [ original_header_lines, number_of_parts ]
# header: array-ref of Net::SIP::HeaderPair




###########################################################################
# Constructor - Creates new object.
# If there are more than one argument it will forward to new_from_parts.
# If the only argument is a scalar it will forward to new_from_string.
# Otherwise it will just create the object of the given class and if
#  there is an argument treat is as a hash to fill the new object.
#
# Apart from new there are also _new_request and _new_response.
# These can be overridden so that application specific classes for
#  request and response will be used for the new object.
#
# Args: see new_from_parts(..)|new_from_string($scalar)|\%hash|none
# Returns: $self
###########################################################################
sub new {
    my $class = shift;
    return $class->new_from_parts(@_) if @_>1;
    return $class->new_from_string(@_) if @_ && !ref($_[0]);
    my $self = fields::new($class);
    %$self = %{$_[0]} if @_;
    return $self;
}

sub _new_request {
    shift;
    return Net::SIP::Request->new(@_);
}

sub _new_response {
    shift;
    return Net::SIP::Response->new(@_);
}

###########################################################################
# create new object from parts
# Args: ($class,$code_or_method,$text,$header,$body)
#   $code_or_method:   Response code or request method
#   $text:   Response text or request URI
#   $header: Header representation as array or hash
#            either [ [key1 => val2],[key2 => val2],... ] where the same
#            key can occure multiple times
#            or { key1 => val1, key2 => val2 } where val can be either
#            a scalar or an array-ref (if the same key has multiple values)
#   $body:   Body as string
# Returns: $self
# Comment:
# the actual object will be created with _new_request and _new_response and
# thus will usually be a subclass of Net::SIP::Packet
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

    my $self = $code =~m{^\d}
	? $class->_new_response({ code => $code })
	: $class->_new_request({ method => uc($code) });
    $self->{text} = defined($text) ? $text:'';

    # $self->{header} is list of Net::SIP::HeaderPair which cares about normalized
    # keys while maintaining the original key, so that one can restore header
    # the elements from @$header can be either [ key,value ] or Net::SIP::HeaderPair's
    # but have to be all from the same type
    my @hnew;
    my $normalized = 0;
    for( my $i=0;$i<@$header;$i++ ) {
	my $h = $header->[$i];
	if ( UNIVERSAL::isa($h,'Net::SIP::HeaderPair')) {
	    # already normalized
	    $normalized = 1;
	    push @hnew,$h;
	} else {
	    my ($key,$value) = @$h;
	    defined($value) || next;
	    croak( "mix between normalized and not normalized data in header" ) if $normalized;
	    push @hnew, Net::SIP::HeaderPair->new( $key,$value ) ;
	}
    }

    $self->{header} = \@hnew;
    # as_string is still undef, it will be evaluated once we call as_string()

    if ( ref($body)) {
	if ( !$self->get_header( 'content-type' )) {
	    my $sub = UNIVERSAL::can( $body, 'content_type' );
	    $self->set_header( 'content-type' => $sub->($body) ) if $sub;
	}
	$body = $body->as_string;
    }
    $self->{body} = $body;

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
    my $data = _string2parts($string);
    return $data->{method}
	? $class->_new_request($data)
	: $class->_new_response($data);
}

###########################################################################
# Find out if it is a request
# Args: $self
# Returns: true if it's a request
###########################################################################
sub is_request {
    my $self = shift;
    $self->{header} || $self->as_parts();
    return $self->{method} && 1;
}

###########################################################################
# Find out if it is a response
# Args: $self
# Returns: true if it's a response
###########################################################################
sub is_response {
    my $self = shift;
    $self->{header} || $self->as_parts();
    return ! $self->{method};
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
#      croak()s if in scalar context and I've more then one value for the key
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
	if (@v>1) {
	    # looks like we have multiple headers but expect only
	    # one. Because we've seen bad client which issue multiple
	    # content-length header we try if all in @v are the same
	    my %v = map { $_ => 1 } @v;
	    return $v[0] if keys(%v) == 1; # ok, only one
	    croak( "multiple values for $key in packet:\n".$self->as_string );
	}
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
#      croak()s if in scalar context and I've more then one value for the key
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
	croak( "multiple values for $key" ) if @v>1;
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
    if ( ref($body)) {
	if ( !$self->get_header( 'content-type' )) {
	    my $sub = UNIVERSAL::can( $body, 'content_type' );
	    $self->set_header( 'content-type' => $sub->($body) ) if $sub;
	}
	$body = $body->as_string;
    }
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
    my $key = @_>1 ? _normalize_hdrkey(shift) : undef;
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

    # return immediately if request is up to date
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
	$result[$hi] = ucfirst($header->[$hi]{key}).": ".$v;
    }

    # (re)build packet
    my $hdr_string = $self->{method}
	? "$self->{method} $self->{text} SIP/2.0\r\n"   # Request
	: "SIP/2.0 $self->{code} $self->{text}\r\n";    # Response

    $hdr_string .= join( "\r\n", grep { $_ } @result )."\r\n";

    # add content-length header if there was none
    $hdr_string .= sprintf( "Content-length: %d\r\n", length( $body ))
	if !defined($cl);

    return ( $self->{as_string} = $hdr_string."\r\n".$body );
}

###########################################################################
# packet dump in long or short form, used mainly for debuging
# Args: ($self,?$level)
#  $level: level of details: undef|0 -> one line, else -> as_string
# Returns: $dump_as_string
###########################################################################
sub dump {
    my Net::SIP::Packet $self = shift;
    my $level = shift;
    if ( !$level ) {
	if ( $self->is_request ) {
	    my ($method,$text,$header,$body) = $self->as_parts;
	    return "REQ  $method $text ".( $body ? 'with body' :'' );
	} else {
	    my ($code,$text,$header,$body) = $self->as_parts;
	    return "RESP $code '$text' ".( $body ? 'with body' :'' );
	}
    } else {
	return $self->as_string
    }
}


###########################################################################
# Return parts
# Args: ($self)
# Returns: ($code_or_method,$text,$header,$body)
#   $code_or_method:   Response code or request method
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

    # if parts are up to date return immediately
    if ( ! $self->{header} ) {
	my $data = _string2parts( $self->{as_string} );
	%$self = ( %$self,%$data );
    }
    return @{$self}{qw(method text header body)} if $self->{method};
    return @{$self}{qw(code text header body)};
}

{
    my $word_rx = qr{[\w\-\.!%\*+`'~()<>:"/?{}\[\]\x1c\x1b\x1d]+};
    my $callid_rx = qr{^$word_rx(?:\@$word_rx)?$};
    my %key2parser = (

	# FIXME: More of these should be more strict to filter out invalid values
	# for now they are only given here to distinguish them from the keys, which
	# can be given multiple times either on different lines or on the same delimited
	# by comma

	'www-authenticate' => \&_hdrkey_parse_keep,
	'authorization' => \&_hdrkey_parse_keep,
	'proxy-authenticate' => \&_hdrkey_parse_keep,
	'proxy-authorization' => \&_hdrkey_parse_keep,
	'date' => \&_hdrkey_parse_keep,
	'content-disposition' => \&_hdrkey_parse_keep,
	'content-type' => \&_hdrkey_parse_keep,
	'mime-version' => \&_hdrkey_parse_keep,
	'organization' => \&_hdrkey_parse_keep,
	'priority' => \&_hdrkey_parse_keep,
	'reply-to' => \&_hdrkey_parse_keep,
	'retry-after' => \&_hdrkey_parse_keep,
	'server' => \&_hdrkey_parse_keep,
	'to' => \&_hdrkey_parse_keep,
	'user-agent' => \&_hdrkey_parse_keep,

	'content-length' => \&_hdrkey_parse_num,
	'expires' => \&_hdrkey_parse_num,
	'max-forwards' => \&_hdrkey_parse_num,
	'min-expires' => \&_hdrkey_parse_num,

	'via' => \&_hdrkey_parse_comma_seperated,
	'contact' => \&_hdrkey_parse_comma_seperated,
	'record-route' => \&_hdrkey_parse_comma_seperated,
	'route' => \&_hdrkey_parse_comma_seperated,
	'allow' => \&_hdrkey_parse_comma_seperated,
	'supported' => \&_hdrkey_parse_comma_seperated,
	'unsupported' => \&_hdrkey_parse_comma_seperated,

	'in-reply-to' => \&_hdrkey_parse_comma_seperated,
	'accept' => \&_hdrkey_parse_comma_seperated,
	'accept-encoding' => \&_hdrkey_parse_comma_seperated,
	'accept-language' => \&_hdrkey_parse_comma_seperated,
	'proxy-require' => \&_hdrkey_parse_comma_seperated,
	'require' => \&_hdrkey_parse_comma_seperated,
	'content-encoding' => \&_hdrkey_parse_comma_seperated,
	'content-language' => \&_hdrkey_parse_comma_seperated,
	'alert-info' => \&_hdrkey_parse_comma_seperated,
	'call-info' => \&_hdrkey_parse_comma_seperated,
	'error-info' => \&_hdrkey_parse_comma_seperated,
	'error-info' => \&_hdrkey_parse_comma_seperated,
	'warning' => \&_hdrkey_parse_comma_seperated,

	'call-id' => sub {
	    $_[0] =~ $callid_rx or
		die "invalid callid, should be 'word [@ word]'\n";
	    return $_[0];
	},
	'cseq' => sub {
	    $_[0] =~ m{^\d+\s+\w+\s*$} or
		die "invalid cseq, should be 'number method'\n";
	    return $_[0];
	},
    );

    my %once = map { ($_ => 1) }
	qw(cseq content-type from to call-id content-length);
    my %key2check = (
	rsp => undef,
	req => {
	    cseq => sub {
		my ($v,$result) = @_;
		$v =~ m{^\d+\s+(\w+)\s*$} or
		    die "invalid cseq, should be 'number method'\n";
		$result->{method} eq $1 or
		    die "method in cseq does not match method of request\n";
	    },
	}
    );

    sub _hdrkey_parse_keep { return $_[0] };
    sub _hdrkey_parse_num {
	my ($v,$k) = @_;
	$v =~m{^(\d+)\s*$} || die "invalid $k, should be number\n";
	return $1;
    };

    sub _hdrkey_parse_comma_seperated {
	my ($v,$k) = @_;
	my @v = ( '' );
	my $quote = '';
	# split on komma (but not if quoted)
	while (1) {
	    if ( $quote ) {
		if ( $v =~m{\G(.*?)(\\|$quote)}gc ) {
		    if ( $2 eq "\\" ) {
			$v[-1].=$1.$2.substr( $v,pos($v),1 );
			pos($v)++;
		    } else {
			$v[-1].=$1.$2;
			$quote = '';
		    }
		} else {
		    # missing end-quote
		    die "missing '$quote' in '$v'\n";
		}
	    } elsif ( $v =~m{\G(.*?)([\\"<,])}gc ) {
		if ( $2 eq "\\" ) {
		    $v[-1].=$1.$2.substr( $v,pos($v),1 );
		    pos($v)++;
		} elsif ( $2 eq ',' ) {
		    # next item if not quoted
		    ( $v[-1].=$1 ) =~s{\s+$}{}; # strip trailing space
		    push @v,'' if !$quote;
		    $v =~m{\G\s+}gc; # skip space after ','
		} else {
		    $v[-1].=$1.$2;
		    $quote = $2 eq '<' ? '>':$2;
		}
	    } else {
		# add rest to last from @v
		$v[-1].= substr($v,pos($v)||0 );
		last;
	    }
	}
	return @v;
    }

    sub _string2parts {
	my $string = shift;
	my %result = ( as_string => $string );

	# otherwise parse request
	my ($header,$body) = split( m{\r?\n\r?\n}, $string,2 );
	my @header = split( m{\r?\n}, $header );

	my $key2check;
	if ( $header[0] =~m{^SIP/2.0\s+(\d+)\s+(\S.*?)\s*$} ) {
	    # Response, e.g. SIP/2.0 407 Authorization required
	    $result{code} = $1;
	    $result{text} = $2;
	    $key2check = $key2check{rsp};
	} elsif ( $header[0] =~m{^(\w+)\s+(\S.*?)\s+SIP/2\.0\s*$} ) {
	    # Request, e.g. INVITE <sip:bla@fasel> SIP/2.0
	    $result{method} = $1;
	    $result{text} = $2;
	    $key2check = $key2check{req};
	} else {
	    die "bad request: starts with '$header[0]'\n";
	}
	shift(@header);

	$result{body} = $body;

	my @hdr;
	my @lines;
	my @check;
	my %check_once;
	while (@header) {
	    my ($k,$v) = $header[0] =~m{^([^\s:]+)\s*:\s*(.*)}
		or die "bad header line $header[0]\n";
	    my $line = shift(@header);
	    while ( @header && $header[0] =~m{^\s+(.*)} ) {
		# continuation line
		$v .= "\n$1";
		$line .= shift(@header);
	    }
	    my $nk = _normalize_hdrkey($k);

	    my $parse = $key2parser{$nk};
	    my @v = $parse ? $parse->($v,$nk) : _hdrkey_parse_keep($v,$nk);
	    if ( @v>1 ) {
		for( my $i=0;$i<@v;$i++ ) {
		    push @hdr, Net::SIP::HeaderPair->new( $k,$v[$i],scalar(@lines),$i );
		}
	    } else {
		push @hdr, Net::SIP::HeaderPair->new( $k,$v[0],scalar(@lines) );
	    }
	    if (my $k2c = $key2check->{$nk}) {
		push @check, [ $k2c, $_ ] for @v;
	    }
	    if ($once{$nk}) {
		($check_once{$nk} //= $_) eq $_ or
		    die "conflicting definition of $nk\n"
		    for @v;
	    }
	    push @lines, [ $line, int(@v) ];
	}
	$result{header} = \@hdr;
	$result{lines}  = \@lines;
	for(@check) {
	    my ($sub,$v) = @$_;
	    $sub->($v,\%result);
	}
	return \%result;
    }
}

###########################################################################
# return SDP body
# Args: ($self,?$newsdp)
#   $newsdp: Net::SIP::SDP object if new value should be set
# Returns: $body
#   $body: Net::SIP::SDP object if body exists and content-type is
#     application/sdp (or not defined). Returns previous body if $newsdp
###########################################################################
sub sdp_body {
    my Net::SIP::Packet $self = shift;
    my $ct = $self->get_header('content-type') || '';

    my $sdpbody;
    if ($ct eq '' || lc($ct) eq 'application/sdp') {
	$sdpbody = $self->{body};
	$self->{body} = $_[0]->as_string if @_; # set new body

    } elsif ($ct =~m{^multipart/}i) {
	my $mime = mime_parse($self->{body},"Content-Type: $ct\r\n");
	my @sdp = grep { $_->{body} }
	    $mime->find_parts(sub { shift->{ct} eq 'application/sdp' });
	die "multiple SDP parts" if @sdp>1;
	$sdpbody = @sdp && $sdp[0]->{body};
	if (@_) {
	    # set new body
	    if (@sdp) {
		# replace exising SDP part
		$sdp[0]->{body} = $_[0]->as_string;
		$self->{body} = $mime->as_string(1);
	    } elsif ($mime->{parts} and
		$ct =~m{^multipart/(?:mixed|related)\s*;}i) {
		# add as another part to multipart
		push @{$mime->{parts}}, mime_parse(
		    "Content-Type: application/sdp\r\n\r\n"
		    . $_[0]->as_string
		);
		$self->{body} = $mime->as_string(1);
	    } else {
		# fully replace body
		$self->set_header('content-type' => 'application/sdp');
		$self->{body} = $_[0]->as_string;
	    }
	}

    } else {
	if (@_) {
	    # fully replace body
	    $self->set_header('content-type' => 'application/sdp');
	    $self->{body} = $_[0]->as_string;
	}
    }

    $self->{as_string} = undef if @_; # should be rebuild
    return $sdpbody ? Net::SIP::SDP->new($sdpbody) : undef;
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
# Trigger updating parts, e.g. code, method, header...
# done by setting header as undef if as_string is set, so the next time
# I'll try to access code it will be recalculated from string
# Args: $self
###########################################################################
sub _update_parts {
    my $self = shift;
    $self->{header} = undef if $self->{as_string};
}

###########################################################################
# Trigger updating string
# done by setting as_string as undef if header is set, so the next time
# I'll try to access as_string it will be recalculated from the parts
# Args: $self
###########################################################################
sub _update_string {
    my $self = shift;
    $self->{as_string} = undef if $self->{header};
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
#   $key: original key
#   $value: value
#   $line: index of header line in original header
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
