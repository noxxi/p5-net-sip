
############################################################################
# Net::SIP::Endpoint::Context
# the calling context for a call managed by the endpoint
############################################################################

use strict;
use warnings;

package Net::SIP::Endpoint::Context;

use fields (

	# ===== can be set with new()
	'method',  # initiated by which method
	'from',    # from where
	'to',      # to where
	'auth',    # [ user,pass ] or { realm1 => [ user1,pass1 ], realm2 => [ user2,pass2 ],... }
			   # or callback(realm,user)->pass
			   # if given, handle_response might automatically try to authorize requests
	'contact', # optional local contact
	'remote_contact', # remote contact from response
	'callid',  # call-id value
	'cseq',    # number in cseq header
	'route',   # for 'route' header, comes usually from 'record-route' info in response
	'via',     # for 'via' header in created responses, comes from incoming request
	'incoming', # flag if call is incoming, e.g. 'to' is myself
	'local_tag', # local tag which gets assigned to either from or to depending on incoming

	# ===== Internals
	# \@array of hashrefs for infos about pending transactions
	'_transactions',
	# arrayref specifying a user defined callback for request success or failure
	'_callback',
	# cseq counter for incoming requests
	'_cseq_incoming',
	# last request in current incoming transaction
	'_last_transreq',

);


use Digest::MD5 'md5_hex';
use Net::SIP::Request;
use Net::SIP::Response;
use Net::SIP::Debug;
use Errno qw( EINVAL EPERM EFAULT );
use Hash::Util 'lock_keys';
use List::Util 'first';
use Net::SIP::Util ':all';

############################################################################
# Creates new context
# Args: ($class,@args)
#   @args: either single \%args (hash-ref) or %args (hash) with at least
#     values for from and to
#     callid,cseq will be generated if not given
#     routes will default to undef and usually set from record-route header
#     in response packets
# Returns: $self
############################################################################
sub new {
	my $class = shift;
	my %args = @_ == 1 ? %{ shift(@_) } : @_;
	my $self = fields::new( $class );
	%$self = %args;
	$self->{callid} ||= md5_hex( time(), rand(2**32) );
	$self->{cseq} ||= 0;
	$self->{_transactions} = [];
	$self->{_cseq_incoming} = 0;

	# create tag on my side (to|from)
	my $side = $self->{incoming} ? 'to':'from';
	my ($data,$param) = sip_hdrval2parts( $side => $self->{$side} );
	if ( my $tag = $param->{tag} ) {
		# FIXME: what to do if local_tag was already set to different value?
		$self->{local_tag} = $tag;
	} else {
		$self->{$side}.=";tag=".(
			$self->{local_tag} = md5_hex( time(), rand(2**32), $self->{$side} )
		);
	}

	DEBUG( 100,"CREATE context $self callid=$self->{callid}" );
	return $self
}

# destroying of fields in perl5.8 cleanup can cause strange errors, where
# it complains, that it cannot coerce array into hash. So use this function
# on your own risks and rename it to DETSTROY if you want to have debugging
# info
sub _DESTROY {
	DEBUG( 100,"DESTROY context $_[0] callid=$_[0]->{callid}" );
}

############################################################################
# returns callid for context
# Args: $self
# Returns: $id
############################################################################
sub callid {
	my Net::SIP::Endpoint::Context $self = shift;
	return $self->{callid};
}

############################################################################
# get peer
# Args: $self
# Returns: $peer
#  $peer: for incoming calls this is 'from', for outgoing 'to'
############################################################################
sub peer {
	my Net::SIP::Endpoint::Context $self = shift;
	my $peer = $self->{incoming} ? $self->{from} : $self->{to};
	my ($data) = sip_hdrval2parts( from => $peer ); # strip parameters like tag etc
	return $data;
}

############################################################################
# return list of outstanding requests matching filter, if no filter is given
# returns all requests
# Args: ($self,%filter)
#  %filter
#     method => name: filter for requests with given method
#     request => packet: filter for packet, e.g. finds if packet is outstanding
# Returns: @requests
#   returns all matching requests (Net::SIP::Request objects), newest
#   requests first
############################################################################
sub find_outstanding_requests {
	my Net::SIP::Endpoint::Context $self = shift;
	my %filter = @_;
	my @trans = @{$self->{_transactions}} or return;
	if ( my $pkt = $filter{request} ) {
		@trans = grep { $pkt == $_->{request} } @trans or return;
	}
	if ( my $method = $filter{method} ) {
		@trans = grep { $method eq $_->{request}->method } @trans or return;
	}
	return map { $_->{request} } @trans;
}

############################################################################
# creates a new SIP request packet within this context
# Args: ($self,$method;$body,%args)
#   $method: method for request, eg 'INVITE','BYE'...
#      or already a Net::SIP::Request object
#   $body: (optional) body for SIP packet
#   %args: (optional) additional args given to Net::SIP::Request->new
# Returns: $request
#   $request: Net::SIP::Request object
############################################################################
sub new_request {
	my Net::SIP::Endpoint::Context $self = shift;
	my ($method,$body,%args) = @_;

	my $request;
	if ( ref($method)) {
		# already a request object
		$request = $method;
		$method = $request->method;

	} else {

		# increase cseq unless its explicitly specified
		# the latter case is useful for ACK and CANCEL
		# which need the same sequence number as the INVITE
		# they belong to
		my $cseq = delete $args{cseq} || ++$self->{cseq};

		$method = uc($method);
		my $uri = delete $args{uri};
		my ($to,$from) = $self->{incoming} ? ($self->{from},$self->{to})
			: ($self->{to},$self->{from});
		if ( !$uri ) {
			($uri) = sip_hdrval2parts( to => $self->{remote_contact}||$to);
			# XXX handle quotes right, e.g "<bla>" <sip:bla@fasel.com>
			$uri = $1 if $uri =~m{<(\S+)>$};
		}

		# contact is mandatory for INVITE
		# will be added within Leg

		$request = Net::SIP::Request->new(
			$method,     # Method
			$uri,        # URI
			{
				from => $from,
				to => $to,
				$self->{contact} ? ( contact => $self->{contact} ):(),
				cseq => "$cseq $method",
				'call-id' => $self->{callid},
				'max-forwards' => 70,
				%args,
			},
			$body
		);
	}

	# overwrite any route header in request if we already learned a route
	$request->set_header( route => $self->{route} ) if $self->{route};

	# create new transaction
	my %trans = (
		tid      => $request->tid,
		request  => $request,
		callback => $self->{_callback},
	);
	lock_keys(%trans);
	unshift @{ $self->{_transactions} }, \%trans; # put as first

	return $request;
}

############################################################################
# set callback for context
# Args: ($self,$cb)
#  $cb: [ \&sub,@arg ]
# Returns: NONE
############################################################################
sub set_callback {
	my Net::SIP::Endpoint::Context $self = shift;
	$self->{_callback} = shift;
}

############################################################################
# notify context that current delivery is permanently done (e.g successful
# or failed). On failure call current callback to notify upper layer about
# permanent failure of request
# This is used for errors from the transport layer, errors from the SIP
# layer (e.g response with 400 Bad request) are handled by handle_response()
# Args: ($self,$tid;$error)
#  $tid: Transaction ID
#  $error: errno if error occured
# Returns: NONE
############################################################################
sub request_delivery_done {
	my Net::SIP::Endpoint::Context $self = shift;
	my ($endpoint,$tid,$error) = @_;
	return if ! $error; # notify of success once I get response

	my $trans = $self->{_transactions};
	my @ntrans;
	foreach my $tr (@$trans) {
		if ( $tr->{tid} eq $tid ) {
			$self->{_transactions} = \@ntrans;
			if ( my $cb = $tr->{callback} ) {
				# permanently failed
				invoke_callback( $cb, $self,$endpoint,$error );
			}
		} else {
			push @ntrans,$tr
		}
	}
}

############################################################################
# handle response packet for this context
# cseq of response must match the cseq of the current delivery!
# if there is no current delivery or the cseq does not match the response
# gets dropped
# Args: ($self,$response,$leg,$from,$endpoint)
#    $response: incoming Net::SIP::Response packet
#    $leg: Net::SIP::Leg through which the response came in
#    $from: ip:port where response came in
#    $endpoint: endpoint responsable for this context, used for redeliveries...
# Returns: NONE
############################################################################
sub handle_response {
	my Net::SIP::Endpoint::Context $self = shift;
	my ($response,$leg,$from,$endpoint) = @_;

	# find and remove transaction because I got response for it
	# if response does not terminates transaction one need to add
	# it again
	my $tid = $response->tid;
	my $method = $response->method;
	my $trans = $self->{_transactions};
	my (@ntrans,$tr);
	foreach my $t (@$trans) {
		if ( !$tr and $t->{tid} eq $tid and $method eq $t->{request}->method) {
			$tr = $t;
		} else {
			push @ntrans,$t
		}
	}
	$tr || do {
		# no delivery pending
		DEBUG( 10,"got response for unkown transaction. DROP" );
		return;
	};
	$self->{_transactions} = \@ntrans;

	DEBUG( 10,"got response for transaction ".$tr->{request}->dump );

	# match response to client transaction, RFC3261 17.1.3
	# check if the response came in through the same leg, where the
	# request was send, e.g that the branch tag is the same
	$leg->check_via( $response ) || do {
		DEBUG( 10,"response came in through the wrong leg" );
		return;
	};

	my $cb = $tr->{callback};
	my @arg = ($endpoint,$self);
	my $code = $response->code;

	# Don't care about the response for a CANCEL  or a BYE
	# because this connection close is issued by this side
	# and no matter what the peer wants the call be will closed
	# But invoke callback to notify upper layer
	if ( $method eq 'CANCEL' or $method eq 'BYE' ) {
		if ( $code >=100 and $code<=199 ) {
			push @ntrans,$tr
		} else {
			invoke_callback($cb,@arg,0,$code,$response,$leg,$from);
			# close context only for BYE,
			# for CANCEL we will close the context on receiving the
			# response and sending the ACK
			$endpoint->close_context( $self ) if $method eq 'BYE';
		}
		return;
	} elsif ( $self->{method} ne 'INVITE' and 
		($code>=200 and $code<300 or $code>=400 and $code != 401 and $code!= 407)) {
		# final response in non-dialog (only INVITE can create dialog)
		$endpoint->close_context($self);
	}

	# for 300-699 an ACK must be created (RFC3261, 17.1.1.2)
	# notification of upper layer will be done down in the method
	# XXXXXXXXXXXXXX do we need to wait that the ACK was accepted
	# XXXXXXXXXXXXXX before sending new request??
	# XXXXXXXXXXXXXX (e.g for 401,407,302..)
	if ( $method eq 'INVITE' && $code>=300 ) {
		# must create ACK
		DEBUG( 50,"code=$code, must generate ACK" );
		my $ack = $tr->{request}->create_ack( $response );
		$endpoint->new_request( $ack,$self,undef,undef,leg => $leg, dst_addr => $from );
	}


	if ( $code =~m{^1\d\d} ) {
		# transaction is not done
		push @ntrans,$tr if $code >=100 and $code<=199;

		# forward preliminary responses to INVITE to app
		# ignore all other preliminary responses
		if ( $method eq 'INVITE' ) {
			invoke_callback($cb,@arg,0,$code,$response,$leg,$from);
		}

	} elsif ( $code =~m{^2\d\d} ) {
		# 2xx OK

		if ( $method eq 'INVITE' ) {
			# is response to INVITE, create ACK
			# and propagate to upper layer
			my $req = $tr->{request};

			# extract route information on INVIE, but not on re-INVITE
			# we assume, that it is a re-INVITE, if we have a remote_contact
			# already
			if ( ! $self->{remote_contact}
				and my @route = $response->get_header( 'record-route' )) {
				$self->{route} = [ reverse @route ];
			}

			# 12.1.2 - set URI for dialog to contact given in response which
			# establishes the dialog
			if ( my $contact = $response->get_header( 'contact' )) {
				$contact = $1 if $contact =~m{<(\w+:[^>\s]+)>};
				$self->{remote_contact} = $contact;
				$req->set_uri( $contact );

			}

			# use to-tag from this request to update 'to'
			# FIXME: this should probably be better done by the upper layer
			# which decides, which call to accept (in case of call-forking with
			# multiple 2xx responses)
			$self->{to} = $response->get_header( 'to' ) if ! $self->{incoming};

			# create ACK
			# if 2xx response changed contact use it as the new URI
			my $ack = $req->create_ack( $response );
			invoke_callback($cb,@arg,0,$code,$response,$leg,$from,$ack);
			$endpoint->new_request( $ack,$self,undef,undef,leg => $leg, dst_addr => $from );


		} else {
			# response to ACK, REGISTER...
			# simply propagate to upper layer, only INVITE needs
			# special handling
			invoke_callback($cb,@arg,0,$code,$response,$leg,$from);
		}

	} elsif ( $code == 401 || $code == 407 ) {
		# Authorization required
		my $r = $tr->{request};
		my $auth = $self->{auth};
		if ( $auth && $r->authorize( $response, $auth )) {
			# found something to authorize
			# redo request
			# update local cseq from cseq in request
			($self->{cseq}) = $r->cseq =~m{(\d+)};
			$endpoint->new_request( $r,$self );
		} else {
			# need user feedback
			invoke_callback($cb,@arg,EPERM,$code,$response,$leg,$from);
		}

	} elsif ( $code == 300 || $code == 301 ) {
		# need user feedback in these cases
		# 21.3.1 300 multiple choices
		# 21.3.2 301 moved permanently
		invoke_callback($cb,@arg,EFAULT,$code,$response,$leg,$from);

	} elsif ( $code == 302 ) {
		# 21.3.3 302 moved temporarily
		# redo request and insert request again
		my $contact = $self->{to} = $response->get_header( 'contact' );
		$contact = $1 if $contact =~m{<(\w+:[^>\s]+)>};
		$self->{remote_contact} = $contact;
		( my $r = $tr->{request} )->set_uri( $contact );
		$r->set_cseq( ++$self->{cseq} );
		$endpoint->new_request( $r,$self );

	} elsif ( $code == 305 ) {
		# 21.3.4 305 use proxy
		# set proxy as the first route and insert request again
		my $route = $self->{route} ||= [];
		unshift @$route,$response->get_header( 'contact' );
		( my $r = $tr->{request} )->set_header( route => $route );
		$r->set_cseq( ++$self->{cseq} );
		$endpoint->new_request( $r,$self );

	} else {
		# some kind of unrecoverable error
		invoke_callback($cb,@arg,EINVAL,$code,$response,$leg,$from);
	}
}

############################################################################
# handle incoming request
# Args: ($self,$request,$leg,$endpoint)
#   $request: incoming Net::SIP::Request packet
#   $leg: Net::SIP::Leg through which the request came in
#   $from: ip:port where request came in
#   $endpoint: endpoint responsable for this context, used for responses...
# Returns: NONE
# Comment: only new requests will be delivered to this method, because the dispatcher
#   cares about retransmits, eg requests for which I issued already a response
#   within the last 64*T1
############################################################################
sub handle_request {
	my Net::SIP::Endpoint::Context $self = shift;
	my ($request,$leg,$from,$endpoint) = @_;

	my $cseq = $request->cseq;
	my ($cseq_num) = $cseq=~m{^(\d+)};

	DEBUG( 100,"method=%s cseq=%s/%s inc=%d", $request->method, $cseq_num,$cseq, $self->{_cseq_incoming} );
	if ( $cseq_num < $self->{_cseq_incoming} ) {
		# must be an retransmit of an really old request, drop
		DEBUG( 10,"retransmit of really old request? Dropping" );
		return;
	}

	# check with last request in transaction
	my $ctx_is_new;
	if ( my $trans = $self->{_last_transreq} ) {
		my $last_cseq = $trans->cseq;
		if ( $last_cseq eq $cseq ) {
			DEBUG( 10,"retransmit of last request. DROP" );
			return;
		}
	} else {
		$ctx_is_new = 1;
	}
	$self->{_last_transreq} = $request;

	my $method = $request->method;

	if ( $method eq 'ACK' || $method eq 'CANCEL' ) {
		# must be have same cseq_num as last request, otherwise drop
		if ( $cseq_num != $self->{_cseq_incoming} ) {
			DEBUG( 10,"received $method for unreceived INVITE: $cseq_num|$self->{_cseq_incoming}" );
			return;
		}
	} else {
		# cannot have the same cseq_num as last request
		if ( $cseq_num == $self->{_cseq_incoming} ) {
			DEBUG( 10,"reused cseq for $method. DROP" );
			return;
		}
	}
	$self->{_cseq_incoming} = $cseq_num;

	my $cb = $self->{_callback} || do {
		DEBUG( 50,"no callback at context!" );
		return;
	};
	my @arg = ($endpoint,$self);

	# extract route information for future requests to the UAC (re-invites)
	# only for INVITE (rfc3261,12.1.1)
	if ( $ctx_is_new and $method eq 'INVITE' and 
		my @route = $request->get_header( 'record-route' )) {
		$self->{route} = \@route;
	}

	{
		# check if to has already a (my) tag, if not add it to request,
		# so that it gets added to responses
		my $to = $request->get_header( 'to' );
		my ($data,$param) = sip_hdrval2parts( to => $to );
		if ( ! $param->{tag} ) {
			DEBUG( 50,"added my tag to to header in request" );
			$param->{tag} = $self->{local_tag};
			$to = sip_parts2hdrval( 'to',$data,$param );
			$request->set_header( to => $to );
		}
	}

	if ( $method eq 'BYE' || $method eq 'CANCEL' ) {
		# if the peer wants to hangup we must confirm
		my $response = $request->create_response( '200','Closing' );
		$endpoint->new_response( $self,$response,$leg,$from );

		# invoke callback before closing context, so that we have more
		# information about the current call
		invoke_callback($cb,@arg,0,0,$request,$leg,$from);

		if ( $method eq 'CANCEL' ) {
			# must create 487 Request canceled
			my $response = $request->create_response( '487','Request canceled' );
			$response->set_header(
				cseq => $response->cseq =~m{(\d+)} && "$1 INVITE" );
			DEBUG(10,"send response: ".$response->dump(1));
			$endpoint->new_response($self,$response,$leg,$from);
		}

		$endpoint->close_context($self);
		return;
	}

	# If new INVITE, send 100 Trying
	if ( $method eq 'INVITE' ) {
		my $response = $request->create_response( '100','Trying' );
		$endpoint->new_response( $self,$response,$leg,$from );
	}


	# propagate to upper layer, which needs
	# - for INVITE send 180 Ringing periodically and after some time a final response
	# - for ACK to establish the call
	# - BYE|CANCEL is already handled above
	# - for everything else to handle the Option fully, eg issue final response..

	invoke_callback($cb,@arg,0,0,$request,$leg,$from);
}

1;
