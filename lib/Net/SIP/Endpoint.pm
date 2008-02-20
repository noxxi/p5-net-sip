
############################################################################
# package Net::SIP::Endpoint
# implements the behavior of an endpoint (SIP phone).
# packet managment (lower layer) is done by Net::SIP::Dispatcher while
# call managment is done with Net::SIP::Endpoint::Context
############################################################################

use strict;
use warnings;
package Net::SIP::Endpoint;
use fields (
	'dispatcher',   # lower layer, delivers and receives packets through the legs
	'application',  # upper layer, e.g user interface..
	'ctx'           # hash of ( callid => Net::SIP::Endpoint::Context )
);

use Net::SIP::Debug;
use Net::SIP::Endpoint::Context;
use Net::SIP::Util qw(invoke_callback);
use Scalar::Util 'weaken';

############################################################################
# create a new endpoint
# Args: ($class,$dispatcher)
#  $dispatcher: lower layer which handles the delivery and receiving of packets
# Returns: $self
############################################################################
sub new {
	my ($class,$dispatcher) = @_;
	my $self = fields::new($class);

	$self->{dispatcher} = $dispatcher;
	$self->{ctx} = {}; # \%hash with ( callid => $ctx )

	# announce myself as upper layer for incoming packets to
	# the dispatcher
	my $cb = [ \&receive,$self ];
	weaken( $cb->[1] );
	$dispatcher->set_receiver( $cb );

	return $self;
}

############################################################################
# set upper layer (application)
# Args: ($self,$app)
#  $app: upper layer which needs to have method receive( $request )
#    to handle new request, which this layer cannot handle alone
#    (e.g INVITE to a new dialog)
#    or this can be \&sub, [ \&sub,@arg ]...
# Returns: NONE
############################################################################
sub set_application {
	my Net::SIP::Endpoint $self = shift;
	my $app = shift;
	my $cb;
	if ( my $sub = UNIVERSAL::can( $app,'receive' )) {
		$cb = [ $sub,$app ];
	} else {
		$cb = $app; # alreday callback
	}
	$self->{application} = $cb;
}

############################################################################
# create a new call or re-invite on a existing call
# wrapper around new_request()
# Args: ($self,$ctx;$callback,$body,%args)
#   $ctx: Context|\%args, see new_request()
#   $callback: optional Callback, see new_request()
#   $body: optional Body
#   %args: additional args for Net::SIP::Request::new
# Returns: $ctx
#   $ctx: see new_request()
############################################################################
sub invite {
	my Net::SIP::Endpoint $self = shift;
	my ($ctx,$callback,$body,%args) = @_;
	return $self->new_request( 'INVITE',$ctx,$callback,$body,%args );
}

############################################################################
# registers UAC
# Args: ($self,%args)
#  %args: at minimum there must be
#    from:    the sip-address to register
#    contact: to which local address should it registered
#    registrar: where it should be registered
#  there can be:
#    expires: Expires header, defaults to 900 if not given
#    callback: callback which will be called on response
#  all other args will be used in creation of request
# Returns: NONE
############################################################################
sub register {
	my Net::SIP::Endpoint $self = shift;
	my %args = @_;

	my ($me,$registrar,$contact) =
		delete @args{qw( from registrar contact )};

	my $expires = delete $args{expires};
	$expires = 900 if !defined($expires);

	my %ctx = (
		to      => $me,
		from    => $me,
		contact => $contact,
		auth    => delete $args{auth},
	);
	return $self->new_request(
		'REGISTER',
		\%ctx,
		delete($args{callback}),
		undef,
		uri => "sip:$registrar",
		expires => $expires,
		%args,
	);
}


############################################################################
# starts new request, e.g creates request packet and delivers it
# Args: ($self,$method,$ctx;$callback,$body,%args)
#   $method: method name, e.g. 'INVITE','REGISTER',..
#     can also be a full Net::SIP::Request already (used for retries after
#     302,305 responses)
#   $ctx: already espablished context (Net::SIP::Endpoint::Context)
#     or \%hash to create a new one (see Net::SIP::Endpoint::Context->new)
#   $callback: [ \&sub,@arg ] which will be called if the layer receives
#     responses important to the upper layer (e.g 180 Ringing, 200 Ok,
#     401/407 Authorization required...)
#     if callback is ommitted the callback from the context is used,
#     if callback is set it will be the new callback for the context
#   $body: optional Body, either scalar or smth with method as_string
#     (like Net::SIP::SDP)
#   %args: additional args for Net::SIP::Request::new
# Returns: $ctx
#    $ctx: context, eg the original one or newly created
# Comment: if it cannot create a new context (because of missing args)
#   or something else fatal happens it will die()
############################################################################
sub new_request {
	my Net::SIP::Endpoint $self = shift;
	my ($method,$ctx,$callback,$body,%args) = @_;

	die "cannot redefine call-id" if delete $args{ 'call-id' };
	my ($leg,$dst_addr) = delete @args{qw(leg dst_addr)};

	if ( ! UNIVERSAL::isa( $ctx,'Net::SIP::Endpoint::Context' )) {
		$ctx = Net::SIP::Endpoint::Context->new($ctx);
		$self->{ctx}{ $ctx->callid } = $ctx; # make sure we manage the context
		DEBUG( 10,"create new request for $method within new call ".$ctx->callid );
	} else {
		DEBUG( 10,"create new request for $method within existing call ".$ctx->callid );
	}

	$ctx->set_callback( $callback ) if $callback;

	my $request = $ctx->new_request( $method,$body,%args );
	DEBUG( 50,"request=".$request->as_string );

	my $tid = $request->tid;
	$self->{dispatcher}->deliver( $request,
		id => $tid,
		callback => [ \&_request_delivery_callback, $self,$ctx ],
		leg => $leg,
		dst_addr => $dst_addr,
	);

	return $ctx;
}

############################################################################
# internal callback used for delivery
# will be called from dispatcher if the request was definitly successfully
# delivered (tcp only) or an error occurred
# Args: ($self,$ctx,$error,$delivery_packet)
#   $ctx: Net::SIP::Endpoint::Context
#   $error: errno if error occured
#   $delivery_packet: Net::SIP::Dispatcher::Packet which encapsulates
#     the original request and information about leg, dst_addr...
#     and has method use_next_dstaddr to try the next dstaddr if for the
#     current no (more) retries are possible
# Returns: NONE
############################################################################
sub _request_delivery_callback {
	my Net::SIP::Endpoint $self = shift;
	my ($ctx,$error,$delivery_packet) = @_;

	my $tid = $delivery_packet->tid;

	# either successfully send over reliable transport
	# or permanently failed, e.g no (more) retries possible
	$ctx->request_delivery_done( $self,$tid,$error )
}

############################################################################
# remove context from Endpoint and cancel all outstanding deliveries
# Args: ($self,$id)
#  $id: either id for ctx or context object or SIP packet
# Returns: $ctx
#  $ctx: removed context object
############################################################################
sub close_context {
	my Net::SIP::Endpoint $self = shift;
	my $id = shift;
	$id = $id->callid if ref($id);
	DEBUG( 10,"close context call-id $id " );
	my $ctx = delete $self->{ctx}{$id} || do {
		DEBUG( 50,"no context for call-id $id found" );
		return;
	};
	# cancel all outstanding deliveries
	$self->{dispatcher}->cancel_delivery( callid => $id );
	return $ctx;
}


############################################################################
# receive packet from dispatcher and forwards it to receive_response
# or receive_request depending on type of packet
# Args: ($self,$packet,$leg,$from)
#   $packet: Net::SIP::Packet
#   $leg: Net::SIP::Leg through which the packets was received
#   $from: ip:port where it got packet from
# Returns: NONE
############################################################################
sub receive {
	my Net::SIP::Endpoint $self = shift || return;
	my ($packet,$leg,$from) = @_;
	return $packet->is_response
		? $self->receive_response( $packet,$leg,$from )
		: $self->receive_request( $packet,$leg,$from )
		;
}

############################################################################
# Handle incoming response packet
# Args: ($self,$response,$leg,$from)
#  $response: incoming Net::SIP::Response packet
#  $leg: where response came in
#  $from: ip:port where it got response from
# Returns: NONE
############################################################################
sub receive_response {
	my Net::SIP::Endpoint $self = shift;
	my ($response,$leg,$from) = @_;

	# find context for response or drop
	my $callid = $response->get_header( 'call-id' );
	my $ctx = $self->{ctx}{$callid} || do {
		DEBUG( 50,"cannot find context for packet with callid=$callid. DROP");
		return;
	};

	DEBUG( 10,"received reply for tid=".$response->tid );
	$self->{dispatcher}->cancel_delivery( $response->tid );
	$ctx->handle_response( $response,$leg,$from,$self );
}

############################################################################
# Handle incoming request packet
# Args: ($self,$request,$leg,$from)
#  $request: incoming Net::SIP::Request packet
#  $leg: where response came in
#  $from: ip:port where it got response from
# Returns: NONE
############################################################################
sub receive_request {
	my Net::SIP::Endpoint $self = shift;
	my ($request,$leg,$from) = @_;

	# this might be a request for an existing context or for a new context
	my $callid = $request->get_header( 'call-id' );
	my $ctx = $self->{ctx}{$callid};

	my $method = $request->method;
	if ( ! $ctx ) {
		if ( $method eq 'BYE' || $method eq 'ACK' || $method eq 'CANCEL' ) {
			# no context for this call, reply with 481 call does not exist
			# (RFC3261 15.1.2)
			$self->new_response(
				undef,
				$request->create_response( 481,'call does not exist' ),
				$leg,  # send back thru same leg
				$from, # and back to the sender
			);
			return;
		}

		# create a new context;
		$ctx = Net::SIP::Endpoint::Context->new(
			incoming => 1,
			from => scalar( $request->get_header( 'from' )),
			to   => scalar( $request->get_header( 'to' )),
			contact => scalar( $request->get_header( 'contact' )),
			callid => scalar( $request->get_header( 'call-id' )),
			via  => [ $request->get_header( 'via' ) ],
		);

		$ctx->set_callback( sub {
			my ($self,$ctx,undef,undef,$request,$leg,$from) = @_;
			invoke_callback( $self->{application}, $self,$ctx,$request,$leg,$from );
		});
	}

	# if I got an ACK cancel delivery of Response to INVITE
	if ( $method eq 'ACK' ) {
		$self->{dispatcher}->cancel_delivery( $request->tid );
	}

	$ctx->handle_request( $request,$leg,$from,$self );
}

############################################################################
# deliver a response packet
# Args: ($self,$ctx,$response,$leg,$addr)
#   $ctx     : Net::SIP::Endpoint::Context which generated response
#   $response: Net::SIP::Respone packet
#   $leg     : leg to send out response, eg where the request came in
#   $addr    : where to send respone (ip:port), eg where the request came from
# Returns: NONE
############################################################################
sub new_response {
	my Net::SIP::Endpoint $self = shift;
	my ($ctx,$response,$leg,$addr) = @_;

	$self->{ctx}{ $ctx->callid } = $ctx if $ctx; # keep context
	$self->{dispatcher}->deliver( $response,
		leg      => $leg,
		dst_addr => $addr,
	);
}


1;
