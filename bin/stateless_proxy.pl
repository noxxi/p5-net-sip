###########################################################################
# Stateless proxy
# listens on multiple legs and forwards SIP packets between the legs
# TODO: do NAT
###########################################################################

use strict;
use warnings;
use IO::Socket::INET;
use Getopt::Long qw(:config posix_default bundling);
use List::Util 'first';

use Net::SIP;
use Net::SIP::Util ':all';
use Net::SIP::Debug;
use Net::SIP::NATHelper::Local;
use Storable;

$SIG{TERM} = $SIG{INT} = sub { exit(0) };

sub usage {
    print STDERR "ERROR: @_\n" if @_;
    print STDERR <<EOS;
usage: $0 [ basic_options ] (
    --leg ip[:port]
    [ --registrar ]
    [ --domain domain ]*
    [ --proxy host[:port]
)+

Listens on given local addresses and forwards SIP packets between
the created legs. For each leg it can specify a number of domains,
which are used on this side of the leg, if none are specified everything
is accepted. If option --registrar is given it will work as a registrar
for the specified domains on this leg.

Basic options:
  -d|--debug [level]           Enable debugging
  -h|--help                    Help (this info)
  --rdump file                 dump/restore register information into/from this file
  --nathelper                  use local NATHelper
Leg specific options:
  -L|--leg  ip[:port]          specify leg
  -D|--domain domain           specify domain on legs side
  -P|--proxy host[:port]       send all packets on leg via host as proxy
  -r|--registrar               work as registrar on this leg
  -X|--prefix DD=tgt-domain    rewrite target number DDXXXX\@domain to XXXX\@tgt-domain

Example:

  Listen on 192.168.0.2:5060 and accept requests from example.com and work
  as registrar for example.com. Route calls for example.com on this leg, all
  other calls are forwarded through leg 192.168.178.3:5060.
  Calls for recipients 0XXX\@example.com gets rewritten to
  XXX\@sip-gateway.example.com and routed accordingly via 192.168.178.3:5060.
  On 192.168.178.3:5060 requests from everywhere, but only for example.com
  are accepted.

  $0 -d 50 \
  --leg 192.168.0.2:5060 --domain example.com -r -X 0=sip-gateway.example.com \
  --leg 192.168.178.3:5060 --proxy 192.168.178.3

EOS
    exit( @_ ? 1:0 );
}

###################################################
# Get options
###################################################

my (%legs,$debug);
my (@domains,%prefix,$be_registrar,$proxy,$leg,$rdump,$nathelper);
my $check_leg = sub {
    my (undef,$val) = @_;
    if ( $leg ) {
	$legs{$leg} = {
	    domains => @domains ? [ @domains ] : undef,
	    prefix => %prefix ? { %prefix }: undef,
	    registrar => $be_registrar,
	    proxy => $proxy,
	};
	(@domains,%prefix,$be_registrar,$proxy) = ();
    }
    $leg = $val;
};
GetOptions(
    'd|debug:i'   => \$debug,
    'h|help'      => sub { usage() },
    'rdump=s'     => \$rdump,
    'nathelper'   => \$nathelper,
    'L|leg=s'     => $check_leg,
    'r|registrar' => \$be_registrar,
    'D|domain=s'  => \@domains,
    'P|proxy=s'   => \$proxy,
    'X|prefix=s'  => sub {
	my ($prefix,$domain) = $_[1] =~m{^(\d+)=(\w[\w\-\.]+)$}
	    or usage( "bad prefix $_[1]" );
	$prefix{$prefix} = $domain;
    },
) || usage( "bad option" );

$check_leg->(); #final call
Net::SIP::Debug->level( $debug || 1 ) if defined $debug;
%legs or usage( 'no addr to listen' );

###################################################
# create Legs
###################################################

my (%domain2leg,%leg2proxy,%leg2rewrite);
while ( my ($addr,$opt) = each %legs ) {
    my $leg = $opt->{leg} = Net::SIP::Leg->new( addr => $addr );
    foreach my $dom (@{ $opt->{domains} }) {
	$domain2leg{$dom}   = $leg;
	$leg2proxy{$leg} = $opt->{proxy} if $opt->{proxy};
    }
    if ( my $p = $opt->{prefix} ) {
	my %p = %{ $opt->{prefix} };
	# longest prefix first
	my @pf = sort { length($b) <=> length($a) } keys %p;
	$leg2rewrite{$leg} = sub {
	    my ($user,$dom) = @_;
	    $user or return;
	    DEBUG( 50,"try to rewrite $user\@$dom, pf=@pf" );
	    for my $pf (@pf) {
		if ( $user =~m{^\Q$pf\E(.+)} ) {
		    return ($1,$p{$pf});
		}
	    }
	    return;
	};
    }
}

###################################################
# create Dispatcher
###################################################

my $loop = Net::SIP::Dispatcher::Eventloop->new;
my $disp = Net::SIP::Dispatcher->new(
    [ map { $_->{leg} } values(%legs) ],
    $loop,
);

$nathelper = $nathelper && Net::SIP::NATHelper::Local->new($loop);

###################################################
# create Registrars on the legs and wraps them
# together into on object
###################################################

my %savereg;
END {
    $rdump or return;
    Storable::store( \%savereg,$rdump );
}

my %registrar;
if ( my $regdata = $rdump && -f $rdump &&  Storable::retrieve($rdump)) {
    %savereg = %$regdata
}
foreach my $opt ( values %legs ) {
    $opt->{registrar} or do {
	DEBUG( 50,"no registrar on leg $opt->{leg} ".$opt->{leg}->dump );
	next;
    };
    my $reg = $registrar{ $opt->{leg} } = Net::SIP::Registrar->new(
	dispatcher => $disp,
	domains    => $opt->{domains},
	#min_expires => 1,
	#max_expires => 15,
    );
    DEBUG( 50,"create registrar on leg $opt->{leg} ".$opt->{leg}->dump." for domains @{$opt->{domains}}" );
    my $key = $opt->{leg}->dump;
    $reg->_store( $savereg{$key} ||= {} );
}

my $registrar = %registrar
    ? myRegistrar->new( %registrar )
    : undef;

###################################################
# create StatelessProxy
###################################################

my $stateless_proxy = myProxy->new(
    dispatcher    => $disp,
    domain2leg    => \%domain2leg,
    leg2rewrite   => \%leg2rewrite,
    leg2registrar => \%registrar,
    leg2proxy     => \%leg2proxy,
    nathelper     => $nathelper,
);

if ( $registrar ) {
    # create chain, where first the registrar gets the packet
    # and the proxy will handle it only, if the registrar
    # does not handle it
    my $chain = Net::SIP::ReceiveChain->new(
	[ $registrar, $stateless_proxy ]
    );
    DEBUG( 50,"set receiver to $chain" );
    $disp->set_receiver( $chain );
} else {
    DEBUG( 50,"set receiver to $stateless_proxy" );
    $disp->set_receiver( $stateless_proxy );
}

###################################################
# run..
###################################################
$loop->loop;


###################################################
###################################################
#
# myRegistrar contains multiple registrars
# the receive method checks based on the incoming
# leg, if one of the registrars is responsable
# it will not be queried, this will be done on
# the single registrars
#
###################################################
###################################################

package myRegistrar;
use Net::SIP::Debug;

sub new {
    my ($class,%hash) = @_;
    # Net::SIP::Registrar objects indexed by string
    # representation of leg
    return bless \%hash,$class
}

sub receive {
    my myRegistrar $self = shift;
    my ($packet,$leg,$addr) = @_;
    return unless $packet->is_request and $packet->method eq 'REGISTER';
    DEBUG( 50,"Registrar got ".$packet->dump );
    # return undef if not registrar for leg, otherwise
    # let it handle by the registrar object
    my $reg = $self->{$leg} || return;
    return $reg->receive( @_ );
}

###################################################
###################################################
#
# myProxy
# special handling for domain2leg and registrars
# on the leg and for rewriting leg2rewrite and
# setting dst with leg2proxy
#
###################################################
###################################################

package myProxy;
use base 'Net::SIP::StatelessProxy';
use Net::SIP::Debug;
use Net::SIP::Util ':all';
use fields qw( domain2leg leg2registrar leg2rewrite leg2proxy );

sub new {
    my ($class,%args) = @_;
    my $d2l     = delete $args{domain2leg};
    my $reg     = delete $args{leg2registrar};
    my $rewrite = delete $args{leg2rewrite};
    my $l2p     = delete $args{leg2proxy};
    my $self = $class->SUPER::new( %args,
	rewrite_contact => \&_rewrite_contact,
    );
    $self->{domain2leg}    = $d2l;
    $self->{leg2registrar} = $reg;
    $self->{leg2rewrite}   = $rewrite;
    $self->{leg2proxy}     = $l2p;
    return $self;
}

# QUICK and DIRTY caching of contact rewrites
{
    my ($cache,$cache_old,$trotate,$random);
    sub _rewrite_contact {
	my ($contact) = @_;
	my $now = time();
	if ( ! $trotate || $now - $trotate > 600 ) {
	    $cache_old = $cache;
	    $trotate = $now;
	}
	my $hit = $cache->{$contact};
	if ( ! $hit && ( $hit = $cache_old->{$contact})) {
	    # refresh cache
	    $cache->{$contact} = $hit
	}
	$hit and do {
	    DEBUG( 50,"rewrote $contact -> $hit" );
	    return $hit
	};
	$contact !~m{\@} and do {
	    # no hit for rewrite back found
	    DEBUG( 50,"no rewrite back for $contact found" );
	    return;
	};


	# create new rewrite
	$random ||= rand( 2**32 );
	for( my $try = 0;$try < 1000; $try++ ) {
	    my $rw = sprintf "%x.%x",rand(2**32),$random;
	    next if $cache->{$rw} || $cache_old->{$rw};
	    $cache->{$rw} = $contact;
	    $cache->{$contact} = $rw;
	    DEBUG( 50,"rewrite $contact -> $rw (NEW)" );
	    return $rw;
	}
	DEBUG( 50,"rewrite failed, cache too full..." );
	return;
    }
}

# FIXME: move to Net::SIP::Util
# reverse to sip_uri2parts
sub sip_parts2uri {
    my ($domain,$user,$sip_proto,$param) = @_;
    my $uri = "$sip_proto:$user\@$domain";
    return sip_parts2hdrval( 'to',$uri,$param )
}


sub __forward_request_getleg {
    my myProxy $self = shift;
    my $entry = shift;
    my $packet = $entry->{packet};

    # rewrite packet
    if ( my $lrw = $self->{leg2rewrite} ) {
	if ( my $rw = $lrw->{$entry->{incoming_leg}} ) {
	    DEBUG( 50,"rewrite URI in request\n".$packet->dump );

	    # rewrite URI
	    # FIXME: this works only for RFC3261 conform requests!
	    my $uri = $packet->uri;
	    my ($domain,$user,$sip_proto,undef,$param) = sip_uri2parts($uri);
	    if ( ($user,$domain) = $rw->($user,$domain) ) {
		my $new_uri = sip_parts2uri( $domain,$user,$sip_proto,$param);
		DEBUG( 50,"rewrite URI $uri to $new_uri" );
		$packet->set_uri($new_uri);
	    }
	} else {
	    DEBUG( 50,"no rewriting" );
	}
    }

    if ( my @r = $packet->get_header( 'route' )) {
	# default routing
	DEBUG( 50,"have route header, no special handling" );
	$entry->{has_route} = 1;
	return $self->SUPER::__forward_request_getleg( $entry )
    }

    my ($domain,$user,$sip_proto,undef,$param) = sip_uri2parts($packet->uri);

    my $d2l = $self->{domain2leg};
    my $disp = $self->{dispatcher};
    my @legs; # list of possible outgoing legs

    if ( $d2l && %$d2l ) {
	##### special routing based on domain2leg
	DEBUG( 50,"special routing based on domain2leg, domain=$domain" );
	my $dom = $domain;
	my $leg = $d2l->{$dom}; # exact match
	while ( ! $leg) {
	    $dom =~s{^[^\.]+\.}{} or last;
	    $leg = $d2l->{ "*.$dom" };
	}
	$leg ||= $d2l->{ $dom = '*'}; # catch-all
	if ( ! $leg ) {
	    DEBUG( 50,"no leg found for domain $domain" );
	    # limit to legs for which I have no domain2leg mapping
	    my %legs = map { $_ => $_ } @{ $disp->{legs} };
	    delete @legs{ values %$d2l };
	    @legs = values %legs;
	} else {
	    DEBUG( 50,"found leg=".$leg->dump." for domain $domain" );
	    @legs = $leg
	}
	if ( ! @legs ) {
	    # no available legs -> DROP
	    DEBUG( 2,"no leg for domain $domain and no legs w/o domain -> DROP ".$packet->dump );
	    return;
	}
    }

    if ( my $l2r = $self->{leg2registrar} ) {
	#### try if the registrar has the address on some leg
	#### if, then set the outgoing leg and rewrite the packet to
	#### reflect the new URI
	my @reg = @legs ? @{$l2r}{@legs} : values %$l2r;
	for my $leg ( @legs ? @legs : values %$l2r ) {
	    my $reg = $l2r->{$leg} or next;
	    DEBUG( 10,"query registrar for $sip_proto:$user\@$domain" );
	    my @addr = $reg->query( "$sip_proto:$user\@$domain" ) or next;
	    $packet->set_uri( $addr[0] );
	    @legs = grep { $_ eq $leg } @{ $disp->{legs}};
	    last;
	}
    }

    @{ $entry->{outgoing_leg}} = @legs;
    return $self->SUPER::__forward_request_getleg( $entry );
}

sub __forward_request_getdaddr {
    my myProxy $self = shift;
    my $entry = shift;
    my $legs = $entry->{outgoing_leg};

    # if leg was given by route try to check for Registrar there
    if ( @$legs && $entry->{has_route} && ( my $reg = $self->{leg2registrar}{$legs->[0]} )) {
	#### try if the registrar has the address on the leg
	#### if, then set the outgoing leg and rewrite the packet to
	#### reflect the new URI
	my $packet = $entry->{packet};
	my ($domain,$user,$sip_proto) = sip_uri2parts($packet->uri);
	DEBUG( 10,"query registrar for $sip_proto:$user\@$domain" );
	if ( my @addr = $reg->query( "$sip_proto:$user\@$domain" )) {
	    $packet->set_uri( $addr[0] );
	}
    }

    # find out proxy on leg
    if (@$legs == 1 && ( my $addr = $self->{leg2proxy}{$legs->[0]} )) {
	$addr .= ':5060' if $addr !~m{:\d+$};
	DEBUG( 50,"set addr to $addr from legs proxy address" );
	@{ $entry->{dst_addr}} = $addr;
    }
    return $self->SUPER::__forward_request_getdaddr( $entry );
}
