#########################################################################
# Net::SIP::Simple
# simple methods for creation of UAC,UAS
# - register    register Address
# - invite      create new call
# - listen      UAS, wait for incoming requests
# - create_registrar - create a simple registrar
# - create_stateless_proxy - create a simple stateless proxy
###########################################################################

use strict;
use warnings;

package Net::SIP::Simple;
use fields (
    'endpoint',           # Net::SIP::Endpoint
    'dispatcher',         # Net::SIP::Dispatcher
    'loop',               # Net::SIP::Dispatcher::Eventloop or similar
    'outgoing_proxy',     # optional outgoing proxy (SIP URL)
    'route',              # more routes
    'registrar',          # optional registrar (addr:port)
    'auth',               # Auth data, see Net::SIP::Endpoint
    'from',               # SIP address of caller
    'contact',            # optional local contact address
    'domain',             # default domain for SIP addresses
    'last_error',         # last error
    'options',            # hash with field,values for response to OPTIONS request
    'ua_cleanup',         # cleanup callbacks
);

use Carp qw(croak);
use Net::SIP::Dispatcher;
use Net::SIP::Dispatcher::Eventloop;
use Net::SIP::Endpoint;
use Net::SIP::Redirect;
use Net::SIP::Registrar;
use Net::SIP::StatelessProxy;
use Net::SIP::Authorize;
use Net::SIP::ReceiveChain;
use Net::SIP::Leg;
# crossref, because its derived from Net::SIP::Simple
# now load in Net::SIP
# use Net::SIP::Simple::Call;
use Net::SIP::Simple::RTP;
use Net::SIP::Util qw( :all );
use List::Util 'first';
use Net::SIP::Debug;

###########################################################################
# create UA
# Args: ($class;%args)
#   %args: misc args, all args are optional
#     legs|leg       - \@list of legs or single leg.
#                      leg can be (derived from) Net::SIP::Leg, a IO::Handle (socket),
#                      a hash reference for constructing Net::SIP::Leg or a string
#                      with a SIP address (i.e. sip:ip:port;transport=TCP)
#     tls            - common TLS settings used when creating a leg
#     outgoing_proxy - specify outgoing proxy, will create leg if necessary
#     proxy          - alias to outgoing_proxy
#     route|routes   - \@list with SIP routes in right syntax "<sip:host:port;lr>"...
#     registrar      - use registrar for registration
#     auth           - auth data: see Request->authorize for format
#     from           - myself, used for calls and registration
#     contact        - optional local contact address
#     options        - hash with fields,values for reply to OPTIONS request
#     loop           - predefined Net::SIP::Dispatcher::Eventloop, used if
#                      shared between UAs
#     dispatcher     - predefined Net::SIP::Dispatcher, used if
#                      shared between UAs
#     domain         - domain used if from/to.. do not contain domain
#     domain2proxy   - hash of { domain => proxy }
#                      used to find proxy for domain. If nothing matches here
#                      DNS need to be used. Special domain '*' catches all
#     d2p            - alias for domain2proxy
# Returns: $self
# Comment:
# FIXME
# If more than one leg is given (e.g. legs+outgoing_proxy) than you have
# to provide a function to find out, which leg is used to send out a request
###########################################################################
sub new {
    my ($class,%args) = @_;
    my $auth = delete $args{auth};
    my $registrar = delete $args{registrar};
    my $tls = delete $args{tls};

    my $ua_cleanup = [];
    my $self = fields::new( $class );

    my $options = delete $args{options} || {};
    {
	@{$options}{ map { lc } keys(%$options) } = values(%$options); # lc keys
	my %default_options = (
	    allow => 'INVITE, ACK, CANCEL, OPTIONS, BYE',
	    accept => 'application/sdp',
	    'accept-encoding' => '',
	    'accept-language' => 'en',
	    supported => '',
	);
	while ( my ($k,$v) = each %default_options ) {
	    $options->{$k} = $v if ! defined $options->{$k};
	}
    }

    my $disp = delete $args{dispatcher};
    my $loop = $disp && $disp->loop
	|| delete $args{loop}
	|| Net::SIP::Dispatcher::Eventloop->new;
    my $proxy = delete $args{outgoing_proxy} || delete $args{proxy};
    my $d2p   = delete $args{domain2proxy}   || delete $args{d2p};
    $disp ||= Net::SIP::Dispatcher->new(
	[],
	$loop,
	domain2proxy => $d2p,
    );

    my $legs = delete $args{legs} || delete $args{leg};
    $legs = [ $legs ] if $legs && ref($legs) ne 'ARRAY';
    $legs ||= [];

    my $host2ip = sub {
	my $host = shift;
	my $ip;
	$disp->dns_host2ip($host,sub { $ip = shift // \0 });
	$loop->loop(15,\$ip);
	die "failed to resolve $host".($ip ? '':' - timed out')
	    if ! defined $ip || ref($ip);
	return ($ip,ip_is_v46($ip));
    };

    foreach ($legs ? @$legs : ()) {
	if ( UNIVERSAL::isa( $_, 'Net::SIP::Leg' )) {
	    # keep
	} elsif ( UNIVERSAL::isa( $_, 'IO::Handle' )) {
	    # socket
	    $_ = Net::SIP::Leg->new(
		sock => $_,
		tls => $tls
	    )
	} elsif ( UNIVERSAL::isa( $_, 'HASH' )) {
	    # create leg from hash
	    $_ = Net::SIP::Leg->new(tls => $tls, %$_)
	} elsif (my ($proto,$host,$port,$family) = sip_uri2sockinfo($_)) {
	    (my $addr,$family) = $family ? ($host,$family) : $host2ip->($host);
	    $_ = Net::SIP::Leg->new(
		proto  => $proto,
		tls    => $tls,
		host   => $host,
		addr   => $addr,
		port   => $port,
		family => $family
	    );
	} else {
	    die "invalid leg specification: $_";
	}
    }

    for my $dst ($registrar, $proxy) {
	$dst or next;
	first { $_->can_deliver_to($dst) } @$legs and next;
	my ($proto,$host,$port,$family) = sip_uri2sockinfo($dst);
	(my $addr,$family) = $family ? ($host,$family) : $host2ip->($host);
	push @$legs, Net::SIP::Leg->new(
	    proto  => $proto,
	    tls    => $tls,
	    dst    => {
		host   => $host,
		addr   => $addr,
		port   => $port,
		family => $family,
	    }
	);
    }

    $disp->add_leg(@$legs) if @$legs;
    $disp->outgoing_proxy($proxy) if $proxy;

    push @$ua_cleanup, [
	sub {
	    my ($self,$legs) = @_;
	    $self->{dispatcher}->remove_leg(@$legs);
	},
	$self,$legs
    ] if @$legs;

    my $endpoint = Net::SIP::Endpoint->new( $disp );

    my $routes = delete $args{routes} || delete $args{route};
    my $from = delete $args{from};
    my $contact = delete $args{contact};
    my $domain = delete $args{domain};

    if ($from) {
	if (!defined($domain) && $from =~m{\bsips?:[^@]+\@([\w\-\.]+)}) {
	    $domain = $1;
	}
	if ($from !~m{\s} && $from !~m{\@}) {
	    my $sip_proto = $disp->get_legs(proto => 'tls') ? 'sips' : 'sip';
	    $from = "$from <$sip_proto:$from\@$domain>";
	}
    }

    die "unhandled arguments: ".join(", ", keys %args) if %args;

    %$self = (
	auth => $auth,
	from => $from,
	contact => $contact,
	domain => $domain,
	endpoint => $endpoint,
	registrar => $registrar,
	dispatcher => $disp,
	loop => $loop,
	route => $routes,
	options => $options,
	ua_cleanup => $ua_cleanup,
    );
    return $self;
}

###########################################################################
# cleanup object, e.g. remove legs it added to dispatcher
# Args: ($self)
# Returns: NONE
###########################################################################
sub cleanup {
    my Net::SIP::Simple $self = shift;
    while ( my $cb = shift @{ $self->{ua_cleanup} } ) {
	invoke_callback($cb,$self)
    }
    %$self = ();
}

###########################################################################
# get last error or set it
# Args: ($self;$err)
#  $err: if given will set error
# Returns: $last_error
###########################################################################
sub error {
    my Net::SIP::Simple $self = shift;
    if ( @_ ) {
	$self->{last_error} = shift;
	$DEBUG && DEBUG(100,Net::SIP::Debug::stacktrace(
	    "set error to ".$self->{last_error}) );
    }
    return $self->{last_error};
}


###########################################################################
# mainloop
# Args: (;$timeout,@stopvar)
#  $timeout: timeout, undef for no timeout. argument can be omitted
#  @stopvar: @array of Scalar-REF, loop stops if one scalar is true
# Returns: NONE
###########################################################################
sub loop {
    my Net::SIP::Simple $self = shift;
    my ($timeout,@stopvar);
    foreach (@_) {
	if ( ref($_) ) {
	    push @stopvar,$_
	} elsif ( defined($_)) {
	    $timeout = $_
	}
    }
    return $self->{loop}->loop( $timeout,@stopvar );
}

###########################################################################
# add timer
# propagates to add_timer of wNet::SIP::Dispatcher, see there for detailed
# explanation of args
# Args: ($self,$when,$cb,$repeat)
# Returns: $timer
###########################################################################
sub add_timer {
    my Net::SIP::Simple $self = shift;
    $self->{dispatcher}->add_timer( @_ );
}

###########################################################################
# control RTP behavior
# Args: ($self,$method,@arg)
#  $method: Method name for behavior, e.g. calls Net::SIP::Simple::RTP::$method
#  @arg: Arguments for method
# Returns: $cb
#  $cb: callback structure
###########################################################################
sub rtp {
    my Net::SIP::Simple $self = shift;
    my ($method,@arg) = @_;
    my $sub = UNIVERSAL::can( 'Net::SIP::Simple::RTP',$method )
	|| UNIVERSAL::can( 'Net::SIP::Simple::RTP','media_'.$method )
	|| croak( "no such method '$method' in Net::SIP::Simple::RTP" );
    return $sub->( @arg );
}


###########################################################################
# Register UA at registrar
# waits until final response is received
# Args: ($self,%args)
#  %args: Hash with keys..
#    registrar: Register there, default $self->{registrar}
#    from:      use 'from' as lokal address, default $self->{from}
#    leg:       use given Net::SIP::Leg object for registration, default first leg
#    cb_final:  user defined callback when final response is received
#    more args (expire...) will be forwarded to Net::SIP::Endpoint::register
# Returns: expires
#   if user defined callback or failed expires will be undef
#   otherwise it will be the expires value from the registrars response
###########################################################################
sub register {
    my Net::SIP::Simple $self = shift;
    my %args = @_;

    my $registrar = delete $args{registrar} || $self->{registrar}
	|| croak( "no registrar" );
    $registrar = sip_parts2uri(sip_uri2parts($registrar)); # normalize
    my $leg = delete $args{leg};
    if ( !$leg ) {
	# use first leg which can deliver to registrar
	($leg) = $self->{dispatcher}->get_legs( sub => [
	    sub {
		my ($addr,$leg) = @_;
		return $leg->can_deliver_to($addr);
	    },
	    $registrar
	]);
    }

    my $from = delete $args{from} || $self->{from}
	|| croak( "unknown from" );

    my $contact = delete $args{contact} || $self->{contact};
    if ( ! $contact) {
	$contact = $from;
	my $local = $leg->laddr(2);
	$contact.= '@'.$local unless $contact =~s{\@([^\s;,>]+)}{\@$local};
    }

    my %rarg = (
	from => $from,
	registrar => $registrar,
	contact => $contact,
	auth => delete $args{auth} || $self->{auth},
    );
    %rarg = ( %rarg, %args ) if %args;

    my $cb_final = delete $rarg{cb_final};
    my $stopvar = 0;
    $cb_final ||= \$stopvar;

    my $cb = sub {
	my ($self,$cb_final,$expires,$endpoint,$ctx,$errno,$code,$packet,$leg,$from) = @_;
	if ( $code && $code =~m{^2\d\d} ) {
	    # use expires info on contact
	    # if none given use global expires header
	    # see rfc3261 10.3.8,10.2.4
	    my $exp;
	    for my $c ( $packet->get_header( 'contact' ) ) {
		my ($addr,$p) = sip_hdrval2parts( contact => $c );
		defined( my $e = $p->{expires} ) or next;
		sip_uri_eq($addr,$contact) or next; # not me
		$exp = $e if ! defined($exp) || $e < $exp;
	    }
	    $exp = $packet->get_header( 'Expires' ) if ! defined $exp;
	    $$expires = $exp;
	    invoke_callback( $cb_final, 'OK', expires => $exp, packet => $packet );

	} elsif ( $code ) {
	    $self->error( "Failed with code $code" );
	    invoke_callback( $cb_final, 'FAIL', code => $code, packet => $packet );
	} elsif ( $errno ) {
	    $self->error( "Failed with error $errno" );
	    invoke_callback( $cb_final, 'FAIL', errno => $errno );
	} else {
	    $self->error( "Unknown failure" );
	    invoke_callback( $cb_final, 'FAIL' );
	}
    };

    my $expires;
    $self->{endpoint}->register( %rarg, callback => [ $cb,$self,$cb_final,\$expires ] );

    # if cb_final is local stopvar wait until it got set
    if ( \$stopvar == $cb_final ) {
	$self->loop( \$stopvar );
	return $stopvar eq 'OK' ? $expires: undef;
    }
}

###########################################################################
# create new call
# and waits until the INVITE is completed (e.g final response received)
# Args: ($self,$ctx;%args)
#   $ctx: \%ctx context describing the call or sip address of peer
#   %args: see Net::SIP::Simple::Call::invite
# Returns: $call
#   $call: Net::SIP::Simple::Call
###########################################################################
sub invite {
    my Net::SIP::Simple $self = shift;
    my ($ctx,%args) = @_;
    (my $to,$ctx) = ref($ctx) ? ($ctx->{to},$ctx) : ($ctx,undef);
    $to || croak( "need peer of call" );
    if ( $to !~m{\s} && $to !~m{\@} ) {;
	croak( "no domain and no fully qualified to" ) if ! $self->{domain};
	my $sip_proto = $self->{dispatcher}->get_legs(proto => 'tls')
	    ? 'sips' : 'sip';
	$to = "$to <$sip_proto:$to\@$self->{domain}>";
	$ctx->{to} = $to if $ctx;
    }
    my $call = Net::SIP::Simple::Call->new( $self,$ctx||$to );
    $call->reinvite(%args);
    return $call;
}

###########################################################################
# listen for and accept new calls
# Args: ($self,%args)
#  %args:
#    filter: optional sub or regex to filter which incoming calls gets accepted
#      if not given all calls will be accepted
#      if regex only from matching regex gets accepted
#      if sub and sub returns 1 call gets accepted, if sub returns 0 it gets rejected
#    cb_create: optional callback called on creation of newly created
#      Net::SIP::Simple::Call. If returns false the call will be closed.
#      If returns a callback (e.g some ref) it will be used instead of
#      Net::SIP::Simple::Call to handle the data
#    cb_established: callback called after receiving ACK
#    cb_cleanup: called on destroy of call object
#    auth_whatever: will require authorization, see whatever in Net::SIP::Authorize
#    for all other args see Net::SIP::Simple::Call....
# Returns: listener object, which can be used in another chain
###########################################################################
sub listen {
    my Net::SIP::Simple $self = shift;
    my %args = @_;
    my $cb_create = delete $args{cb_create};

    # handle new requests
    my $receive = sub {
	my ($self,$args,$endpoint,$ctx,$request,$leg,$from) = @_;
	my $method = $request->method;
	if ( $method eq 'OPTIONS' ) {
	    my $response = $request->create_response( '200','OK',$self->{options} );
	    $self->{endpoint}->new_response( $ctx,$response,$leg,$from );
	    $self->{endpoint}->close_context( $ctx );
	    return;
	} elsif ( $method ne 'INVITE' ) {
	    DEBUG( 10,"drop non-INVITE request: ".$request->dump );
	    $self->{endpoint}->close_context( $ctx );
	    return;
	}

	if ( my $filter = $args->{filter} ) {
	    my $rv = invoke_callback( $filter, $ctx->{from},$request );
	    if ( !$rv ) {
		DEBUG( 1, "call from '$ctx->{from}' rejected" );
		$self->{endpoint}->close_context( $ctx );
		return;
	    }
	}

	# new invite, create call
	my $call = Net::SIP::Simple::Call->new( $self,$ctx,{ %$args });
	my $cb = UNIVERSAL::can( $call,'receive' ) || die;

	# notify caller about new call
	if ($cb_create) {
	    my $cbx = invoke_callback($cb_create, $call, $request, $leg, $from);
	    if ( ! $cbx ) {
		DEBUG( 1, "call from '$ctx->{from}' rejected in cb_create" );
		$self->{endpoint}->close_context( $ctx );
		return;
	    } elsif ( ref($cbx) ) {
		$cb = $cbx
	    }
	}

	# setup callback on context and call it for this packet
	$ctx->set_callback([ $cb,$call ]);
	$cb->( $call,$endpoint,$ctx,undef,undef,$request,$leg,$from );
    };

    $self->{endpoint}->set_application( [ $receive,$self,\%args] );

    # in case listener should provide authorization put Authorizer in between
    if ( my $auth = _make_auth_from_args($self,\%args) ) {
	return $self->create_chain([$auth,$self->{endpoint}]);
    } else {
	return $self->{endpoint}
    }
}


###########################################################################
# create authorization if args say so
# Args: ($self,$args)
#   %$args:
#     auth_user2pass: see user2pass in Net::SIP::Authorize
#     auth_user2a1:   see user2a1 in Net::SIP::Authorize
#     auth_realm:     see realm in Net::SIP::Authorize
#     auth_.... :     see Net::SIP::Authorize
# Returns: authorizer if auth_* args given, removes auth_ args from hash
##########################################################################
sub _make_auth_from_args {
    my ($self,$args) = @_;

    my %auth =
	map { m{^auth_(.+)} ? ($1 => delete $args->{$_}):() }
	keys %$args;
    my $i_am_proxy = delete $auth{i_am_proxy};

    return %auth && $self->create_auth(%auth);
}

###########################################################################
# setup authorization for use in chain
# Args: ($self,%args)
#   %args:  see Net::SIP::Authorize
# Returns: authorizer object
##########################################################################
sub create_auth {
    my ($self,%args) = @_;
    return Net::SIP::Authorize->new(
	dispatcher => $self->{dispatcher},
	%args,
    );
}


###########################################################################
# setup a simple registrar
# Args: ($self,%args)
#   %args:
#     max_expires: maximum expires time accepted fro registration, default 300
#     min_expires: minimum expires time accepted, default 30
#     domains|domain: domain or \@list of domains the registrar is responsable
#       for. special domain '*' catches all
#    auth_whatever: will require authorization, see whatever in Net::SIP::Authorize
# Returns: $registrar
###########################################################################
sub create_registrar {
    my Net::SIP::Simple $self = shift;
    my %args = @_;
    my $auth = _make_auth_from_args($self,\%args);

    my $registrar = Net::SIP::Registrar->new(
	dispatcher => $self->{dispatcher},
	%args
    );
    if ( $auth ) {
	$registrar = $self->create_chain(
	    [$auth,$registrar],
	    methods => ['REGISTER']
	)
    } else {
	$self->{dispatcher}->set_receiver( $registrar );
    }
    return $registrar;
}

###########################################################################
# setup a stateless proxy
# Args: ($self,%args)
#   %args: see Net::SIP::StatelessProxy, for auth_whatever see whatever
#      in Net::SIP::Authorize
# Returns: $proxy
###########################################################################
sub create_stateless_proxy {
    my Net::SIP::Simple $self = shift;
    my %args = @_;

    $args{auth_i_am_proxy} = 1;
    my $auth = _make_auth_from_args($self,\%args);

    my $proxy = Net::SIP::StatelessProxy->new(
	dispatcher => $self->{dispatcher},
	%args
    );
    if ( $auth ) {
	$proxy = $self->create_chain([$auth,$proxy])
    } else {
	$self->{dispatcher}->set_receiver($proxy);
    }
    return $proxy;
}

###########################################################################
# setup chain of handlers, e.g. first authorize all requests, everything
# else gets handled by stateless proxy etc
# Args: ($self,$objects,%args)
# Returns: $chain
###########################################################################
sub create_chain {
    my Net::SIP::Simple $self = shift;
    my $chain = Net::SIP::ReceiveChain->new( @_ );
    $self->{dispatcher}->set_receiver( $chain );
    return $chain;
}

1;
