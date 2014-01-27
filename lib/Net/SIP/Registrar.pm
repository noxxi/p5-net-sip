###########################################################################
# package Net::SIP::Registrar
# implements a simple Registrar
# FIXME: store registry information in a more flat format, so that
#  user can give a tied hash for permanent storage. Or give an object
#  interface with a simple default implementation but a way for the
#  user to provide its own implementation
###########################################################################

use strict;
use warnings;

package Net::SIP::Registrar;
use fields qw( store max_expires min_expires dispatcher domains _last_timer );
use Net::SIP::Util ':all';
use Carp 'croak';
use Net::SIP::Debug;
use List::Util 'first';

###########################################################################
# creates new registrar
# Args: ($class,%args)
#   %args
#     max_expires: maximum time for expire, default 300
#     min_expires: manimum time for expire, default 30
#     dispatcher: Net::SIP::Dispatcher object
#     domains: domain or \@list of domains the registrar is responsable
#        for, if not given it cares about everything
#     domain: like domains if only one domain is given
# Returns: $self
###########################################################################
sub new {
    my $class = shift;
    my %args = @_;
    my $domains = delete $args{domains} || delete $args{domain};
    $domains = [ $domains ] if $domains && !ref($domains);

    my $self = fields::new($class);
    %$self = %args;
    $self->{max_expires} ||= 300;
    $self->{min_expires} ||= 30;
    $self->{dispatcher} or croak( "no dispatcher given" );
    $self->{store} = {};
    $self->{domains} = $domains;
    return $self;
}

# hack to have access to the store, to dump or restore it
sub _store {
    my $self = shift;
    $self->{store} = shift if @_;
    return $self->{store};
}

###########################################################################
# handle packet, called from Net::SIP::Dispatcher on incoming requests
# Args: ($self,$packet,$leg,$addr)
#  $packet: Net::SIP::Request
#  $leg: Net::SIP::Leg where request came in (and response gets send out)
#  $addr: ip:port where request came from and response will be send
# Returns: $code
#  $code: response code used in response (usually 200, but can be 423
#    if expires was too small). If not given no response was created
#    and packet was ignored
###########################################################################
sub receive {
    my Net::SIP::Registrar $self = shift;
    my ($packet,$leg,$addr) = @_;

    # accept only REGISTER
    $packet->is_request || return;
    if ( $packet->method ne 'REGISTER' ) {
	# if we know the target rewrite the destination URI
	my $addr = (sip_uri2parts($packet->uri))[3];
	DEBUG( 1,"method ".$packet->method." addr=<$addr>" );
	my @found = $self->query( $addr );
	@found or do {
	    DEBUG( 1, "$addr not locally registered" );
	    return;
	};
	DEBUG( 1,"rewrite URI $addr in ".$packet->method." to $found[0]" );
	$packet->set_uri( $found[0] );
	return; # propagate to next in chain
    }

    my $to = $packet->get_header( 'to' ) or do {
	DEBUG( 1,"no to in register request. DROP" );
	return;
    };

    # what address will be registered
    ($to) = sip_hdrval2parts( to => $to );
    if ( my ($domain,$user,$proto) = sip_uri2parts( $to ) ) {
	# normalize if possible
	$to = "$proto:$user\@$domain";
    }

    # check if domain is allowed
    if ( my $rd = $self->{domains} ) {
	my ($domain) = $to =~m{\@([\w\-\.]+)};
	if ( ! first { $domain =~m{\.?\Q$_\E$}i || $_ eq '*' } @$rd ) {
	    DEBUG( 1, "$domain matches none of my own domains. DROP" );
	    return;
	}
    }

    my $disp = $self->{dispatcher};
    my $loop = $disp->{eventloop};
    my $now = int($loop->looptime);
    my $glob_expire = $packet->get_header( 'expires' );

    # to which contacs it will be registered
    my @contact = $packet->get_header( 'contact' );

    my %curr;
    foreach my $c (@contact) {
	# update contact info
	my ($c_addr,$param) = sip_hdrval2parts( contact => $c );
	$c_addr = $1 if $c_addr =~m{<(\w+:\S+)>}; # do we really need this?
	my $expire = $param->{expires};
	$expire = $glob_expire if ! defined $expire;
	$expire = $self->{max_expires}
	    if ! defined $expire || $expire > $self->{max_expires};
	if ( $expire ) {
	    if ( $expire < $self->{min_expires} ) {
		# expire to small
		my $response = $packet->create_response(
		    '423','Interval too brief',
		);
		$disp->deliver( $response, leg => $leg, dst_addr => $addr );
		return 423;
	    }
	    $expire += $now if $expire;
	}
	$curr{$c_addr} = $expire;
    }

    $self->{store}{ $to } = \%curr;

    # expire now!
    $self->expire();
    DEBUG_DUMP( 100,$self->{store} );

    # send back a list of current contacts
    my $response = $packet->create_response( '200','OK' );
    while ( my ($where,$expire) = each %curr ) {
	$expire -= $now;
	$response->add_header( contact => "<$where>;expires=$expire" );
    }

    # send back where it came from
    $disp->deliver( $response, leg => $leg, dst_addr => $addr );
    return 200;
}

###########################################################################
# return information for SIP address
# Args: ($self,$addr)
# Returns: @sip_contacts
###########################################################################
sub query {
    my Net::SIP::Registrar $self = shift;
    my $addr = shift;
    DEBUG( 50,"lookup of $addr" );
    my $contacts = $self->{store}{$addr} || return;
    return grep { m{^sips?:} } keys %$contacts;
}

###########################################################################
# remove all expired entries from store
# Args: $self
# Returns: none
###########################################################################
sub expire {
    my Net::SIP::Registrar $self = shift;

    my $disp = $self->{dispatcher};
    my $loop = $disp->{eventloop};
    my $now = $loop->looptime;

    my $store = $self->{store};
    my (@drop_addr,$next_exp);
    while ( my ($addr,$contact) = each %$store ) {
	my @drop_where;
	while ( my ($where,$expire) = each %$contact ) {
	    if ( $expire<$now ) {
		push @drop_where, $where;
	    } else {
		$next_exp = $expire if ! $next_exp || $expire < $next_exp;
	    }
	}
	if ( @drop_where ) {
	    delete @{$contact}{ @drop_where };
	    push @drop_addr,$addr if !%$contact;
	}
    }
    delete @{$store}{ @drop_addr } if @drop_addr;

    # add timer for next expire
    if ( $next_exp ) {
	my $last_timer = \$self->{_last_timer};
	if ( ! $$last_timer || $next_exp < $last_timer || $$last_timer <= $now ) {
	    $disp->add_timer( $next_exp, [ \&expire, $self ] );
	    $$last_timer = $next_exp;
	}
    }
}

1;
