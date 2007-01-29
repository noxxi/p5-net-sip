use strict;
use warnings;

############################################################################
#
# IDFROM = data from SIP FROM header + Tag + interface, where request came in
# IDTO   = data from SIP TO header + Tag + interface where response came in
#
# ALLOCATE( call-id,cseq,peer,interface,media_data)
#  allocate new media data for call call-id, session cseq, side peer
#  peer is IDFROM for INVITE and ACK requests and IDTO for 2xx responses
#  media_data is a \@list from Net::SIP::SDP::get_media and interface
#  is the IP where the new ports should be allocated
#  If it cannot allocate new data it should drop the request, so that
#  it gets retransmitted
#  All inactive sessions with the call-id but lower cseq should be deleted
#  immediatly, if there are session with same call-id but higher cseq
#  the request should be ignored and the the SIP request should not be
#  forwarded
#  If there are already data allocated for call-id,cseq,IDX it is assumed
#  that the SIP packet was a retransmit and the already allocated data
#  will be returned
#
# ACTIVATE( call-id,cseq,IDFROM,IDTO)
#  create session based on the sockets groups for IDFROM and IDTO within
#  the same call-id,cseq. Gets called on ACK requests.
#  Session might exist already if the ACK was a retransmit.
#  If there are other sessions with same call-id and lower cseq they
#  should be CLOSEed.
#
# CLOSE( call-id,cseq,IDFROM,IDTO)
#  close session. If data where transferred through session forwarding
#  should be stopped immediatly and the ports be freed after some time
#  (10 seconds). If no data where transferred ports should be freed
#  immediatly
#  for CANCEL requests cseq is given so that only the specific request
#  will be canceled, for BYE cseq is not given, because all sessions for
#  IDFROM->IDTO and IDTO->IDFROM should be closed
#
# Handling of timeouts:
#  * if no data got transferred through an activated session it should
#    be deleted after 3 minutes
#  * if session got not activated after 3 minutes it should be deleted
#
# ---------------- Net::SIP::NATHelper ---------------------------------------
#  |       |       |       |     ...
#                        call-id
#                          |
#       ---------- Net::SIP::NATHelper::Call's -------------------------
#       |       |       |       |      ...
#                     cseq
#                       |
#       ---------------------------------------------
#        |     |
#        |   socket_groups
#        |     |
#        |     |- idx: Net::SIP::NATHelper::SocketGroup
#        |     |- idx: Net::SIP::NATHelper::SocketGroup
#        |     |- idx: Net::SIP::NATHelper::SocketGroup
#        |     |- idx: Net::SIP::NATHelper::SocketGroup
#        |     |...
#        |
#      sessions
#        |
#        |- idfrom+idto:Net::SIP::NATHelper::Session containing 2xNet::SIP::NATHelper::SocketGroup
#        |- idfrom+idto:Net::SIP::NATHelper::Session containing 2xNet::SIP::NATHelper::SocketGroup
#        |...
#
############################################################################


package Net::SIP::NATHelper;
use Net::SIP::Util ':all';
use Net::SIP::Debug;
use List::Util 'first';

############################################################################
# create new Net::SIP::NATHelper
# Args: ($class);
# Returns: $self
############################################################################
sub new {
	my ($class) = @_;
	# Hash of Net::SIP::NATHelper::Call indexed by call-id
	return bless {}, $class;
}


############################################################################
# allocate new sockets for RTP
# Args: ($self,$callid,$cseq,$idx,$interface,\@media)
# Returns: \@new_media
# Comment: if it fails () will be returned. In this cases the SIP packet
#  will not be forwarded (dropped) thus causing a retransmit which will
#  then cause another call to allocate_sockets and maybe this time we
#  have enough resources
############################################################################
sub allocate_sockets {
	my Net::SIP::NATHelper $self = shift;
	my ($callid,$cseq,$idx,$interface,$media) = @_;

	my $call = $self->{$callid}
		||= Net::SIP::NATHelper::Call->new( $callid );
	return $call->allocate_sockets( $cseq,$idx,$interface,$media);
}

############################################################################
# activate session
# Args: ($self,$callid,$cseq,$idfrom,$idto)
# Returns: TRUE if successful, else FALSE
# Comment: if it returns FALSE because it fails the SIP packet will not
#   be forwarded. This is the case on retransmits of really old SIP
#   packets where the session was already closed
############################################################################
sub activate_session {
	my Net::SIP::NATHelper $self = shift;
	my ($callid,$cseq,$idfrom,$idto) = @_;

	my $call = $self->{$callid};
	unless ( $call ) {
		DEBUG( 10,"tried to activate non-existing call $callid" );
		return;
	}
	return $call->activate_session( $cseq,$idfrom,$idto );
}

############################################################################
# close session(s)
# Args: ($self,$callid,$cseq,$idfrom,$idto)
#   $cseq: optional sequence number, only for CANCEL requests
# Returns: TRUE if successful, else FALSE
# Comment: this SIP packet should be forwarded, even if the call
#  is not known here, because it did not receive the response from
#  the peer yet
############################################################################
sub close_session {
	my Net::SIP::NATHelper $self = shift;
	my ($callid,$cseq,$idfrom,$idto) = @_;

	my $call = $self->{$callid};
	unless ( $call ) {
		DEBUG( 10,"tried to close non-existing call $callid" );
		return;
	}
	return $call->close_session( $cseq,$idfrom,$idto );
}


############################################################################
# cleanup, e.g. delete expired sessions and unused socket groups
# Args: ($self)
# Returns: TRUE if changes occured
############################################################################
sub expire {
	my Net::SIP::NATHelper $self = shift;

	my $sock_expire = time() - 3*60;
	my $rv = 0;
	foreach my $callid ( keys %$self ) {
		my $call = $self->{$callid};
		$call->expire( $sock_expire ) && $rv++;
		if ( $call->is_empty ) {
			DEBUG( 50,"remove call $callid" );
			delete $self->{$callid};
		}
	}
	return $rv;
}

############################################################################
# collect the callbacks for all sessions in all calls
# Args: $self
# Returns: @callbacks, see Net::SIP::NATHelper::Session::callbacks
############################################################################
sub callbacks {
	my Net::SIP::NATHelper $self = shift;
	return map { $_->callbacks } values %$self;
}

############################################################################
# Dump debug information into string
# Args: $self
# Returns: $string
############################################################################
sub dump {
	my Net::SIP::NATHelper $self = shift;
	my $result = "";
	foreach ( sort keys %$self ) {
		$result.= $self->{$_}->dump;
	}
	return $result;
}

############################################################################
# return number of reserved calls
# Args: $self
# Returns: $n
############################################################################
sub number_of_calls {
	my Net::SIP::NATHelper $self = shift;
	return scalar( keys %$self )
}

############################################################################
############################################################################
#
# Net::SIP::NATHelper::SocketGroup
# manages groups of sockets created from an SDP body
# manages the local (NAT) sockets and the original targets from the SDP
#
############################################################################
############################################################################

package Net::SIP::NATHelper::SocketGroup;
use fields qw( id lastmod socks targets media );
use Net::SIP::Util 'create_rtp_sockets';
use Net::SIP::Debug;
use Socket;

############################################################################
# create new socket group based on the original media and a local address
# Args: ($class,$id,$new_addr,$media)
# Returns: $self|()
# Comment: () will be returned if allocation of sockets fails
############################################################################
sub new {
	my ($class,$id,$new_addr,$media) = @_;

	my (@rtp_sockets,@targets,@new_media);
	foreach my $m (@$media) {
		my ($addr,$port,$range) = @{$m}{qw/addr port range/};

		# allocate new sockets
		my ($new_port,@socks) = create_rtp_sockets( $new_addr,$range );
		unless (@socks) {
			DEBUG( 1,"allocation of RTP sockets failed: $!" );
			return;
		}
		push @rtp_sockets,@socks;
		push @new_media, [ $new_addr,$new_port,int(@socks) ];

		DEBUG( 100,"m_old=$addr $port/$range new_port=$new_port" );

		# and save targets, e.g. where data received on these new socks
		# gets forwarded to.
		my $addr_bin = inet_aton($addr);
		for( my $i=0;$i<@socks;$i++ ) {
			my $dst = sockaddr_in( $port+$i,$addr_bin );
			push @targets,$dst;
		}
	}

	unless (@rtp_sockets) {
		DEBUG( 100,"no sockets to allocate for socketgroup" );
		return;
	}

	my $self = fields::new($class);
	%$self = (
		id => $id,
		socks => \@rtp_sockets,
		targets => \@targets,
		media => \@new_media,
		lastmod => time(),
	);
	return $self;
}

############################################################################
# returns time, when data where transferred through socket the last time
# Args: $self
# Returns: $lastmod
############################################################################
sub lastmod {
	my Net::SIP::NATHelper::SocketGroup $self = shift;
	return $self->{lastmod};
}

############################################################################
# updates timestamp of last modification, used in expiring
# Args: ($self)
# Returns: NONE
############################################################################
sub didit {
	my Net::SIP::NATHelper::SocketGroup $self = shift;
	$self->{lastmod} = time();
}

############################################################################
# returns \@list of media [ip,port,range] in group
# Args: $self
# Returns: \@media
############################################################################
sub get_media {
	my Net::SIP::NATHelper::SocketGroup $self = shift;
	return $self->{media};
}

############################################################################
# returns \@list of sockets in group
# Args: $self
# Returns: \@sockets
############################################################################
sub get_socks {
	my Net::SIP::NATHelper::SocketGroup $self = shift;
	return $self->{socks};
}

############################################################################
# returns \@list of the original targets in group
# Args: $self
# Returns: \@targets
############################################################################
sub get_targets {
	my Net::SIP::NATHelper::SocketGroup $self = shift;
	return $self->{targets};
}

############################################################################
# Dump debug information into string
# Args: $self
# Returns: $string
############################################################################
sub dump {
	my Net::SIP::NATHelper::SocketGroup $self = shift;
	my $result = $self->{id}." >> ".join( ' ',
		map { "$_->[0]:$_->[1]/$_->[2]" }
		@{$self->{media}} ).
		"\n";
	return $result;
}

############################################################################
############################################################################
#
# Net::SIP::NATHelper::Session
# each session consists of two Net::SIP::NATHelper::SocketGroup's and the data
# are transferred between these groups
#
############################################################################
############################################################################

package Net::SIP::NATHelper::Session;
use fields qw( sfrom sto );
use Net::SIP::Debug;
use List::Util 'max';

############################################################################
# create new Session between two SocketGroup's
# Args: ($class,$socketgroup_from,$socketgroup_to)
# Returns: $self
############################################################################
sub new {
	my ($class,$sfrom,$sto) = @_;
	my $self = fields::new( $class );

	# sanity check that both use the same number of sockets
	if ( @{ $sfrom->get_socks } != @{ $sto->get_socks } ) {
		DEBUG( 1,"different number of sockets in request and response" );
		return;
	}

	%$self = (
		sfrom => $sfrom,
		sto => $sto,
	);
	return $self;
}

############################################################################
# return time of last modification, e.g. maximum of lastmod of both
# socketgroups
# Args: $self
# Returns: $lastmod
############################################################################
sub lastmod {
	my Net::SIP::NATHelper::Session $self = shift;
	return max( $self->{sfrom}->lastmod, $self->{sto}->lastmod );
}

############################################################################
# return all [ socket, callback ] pairs for the session
# Args: $self
# Returns: @callbacks
############################################################################
sub callbacks {
	my Net::SIP::NATHelper::Session $self = shift;

	# data received on sockets in $sfrom will be forwarded to the original
	# target from $sfrom using the matching socket from $sto and the other
	# way around.
	# This means we do symetric RTP in all cases

	my $sfrom        = $self->{sfrom};
	my $sockets_from = $sfrom->get_socks;
	my $targets_from = $sfrom->get_targets;

	my $sto          = $self->{sto};
	my $sockets_to   = $sto->get_socks;
	my $targets_to   = $sto->get_targets;

	my @cb;
	for( my $i=0;$i<@$sockets_from;$i++ ) {
		push @cb, [ $sockets_from->[$i], [
			\&_forward_data,
			$sockets_from->[$i],   # read data from socket FROM(nat)
			$sockets_to->[$i],     # forward data using socket TO(nat)
			$targets_from->[$i],   # to FROM(original)
			$sfrom,                # call $sfrom->didit

		]];
		push @cb, [ $sockets_to->[$i], [
			\&_forward_data,
			$sockets_to->[$i],     # read data from socket TO(nat)
			$sockets_from->[$i],   # forward data using socket FROM(nat)
			$targets_to->[$i],     # to TO(original)
			$sto,                  # call $sto->didit
		]];
	}
	return @cb;
}

############################################################################
# internal function used for forwarding data in callbacks()
############################################################################
sub _forward_data {
	my ($read_socket,$write_socket,$dstaddr,$group) = @_;
	recv( $read_socket, my $buf,2**16,0 ) || do {
		DEBUG( 10,"recv data failed: $!" );
		return;
	};
	$group->didit;
	send( $write_socket, $buf,0,$dstaddr ) || do {
		DEBUG( 10,"send data failed: $!" );
		return;
	};
	my $name = sub {
		my $bin = shift;
		use Socket;
		my ($port,$addr) = unpack_sockaddr_in( $bin );
		return inet_ntoa($addr).':'.$port;
	};
	DEBUG( 50,"transferred %d bytes on %s via %s to %s",
		length($buf), $name->( getsockname($read_socket )),
		$name->(getsockname( $write_socket )),$name->($dstaddr));
}


############################################################################
# Dump debug information into string
# Args: $self
# Returns: $string
############################################################################
sub dump {
	my Net::SIP::NATHelper::Session $self = shift;
	return ( $self->{sfrom} && $self->{sfrom}{id} || 'NO.SFROM' ).",".
		( $self->{sto} && $self->{sto}{id} || 'NO.STO' )."\n";
}

############################################################################
############################################################################
#
# Net::SIP::NATHelper::Call
# manages Call, e.g. for each active cseq for the same call-id
# it manages the Net::SIP::NATHelper::SocketGroup's and Net::SIP::NATHelper::Session's
#
############################################################################
############################################################################

package Net::SIP::NATHelper::Call;
use fields qw( callid by_cseq );
use Hash::Util 'lock_keys';
use Net::SIP::Debug;

sub new {
	my ($class,$callid) = @_;
	my $self = fields::new($class);
	%$self = (
		callid => $callid,
		by_cseq => {},
	);
	return $self;
}

############################################################################
# allocate sockets for rewriting SDP body
# Args: ($self,$cseq,$idx,$interface,$media)
# Returns: $new_media
############################################################################
sub allocate_sockets {
	my Net::SIP::NATHelper::Call $self = shift;
	my ($cseq,$idx,$interface,$media) = @_;

	# find existing data for $cseq
	my $data = $self->{by_cseq}{$cseq};

	if ( ! $data ) {
		# if it is not known check if cseq is too small (retransmit of old packet)
		foreach ( keys %{$self->{by_cseq}} ) {
			if ( $_ > $cseq ) {
				DEBUG( 10,"retransmit? cseq $cseq is smaller than $_ in call $self->{callid}" );
				return;
			}
		}

		# need new record
		$data = $self->{by_cseq}{$cseq} = {
			socket_groups => {},    # indexed by idx=idfrom|idto
			sessions => {},         # indexed by idfrom+idto
		};
		lock_keys( %$data );
	}

	# if SocketGroup already exists return it's media
	# otherwise try to create a new one
	# if this fails return (), otherwise return media

	my $sgroups = $data->{socket_groups};
	my $group = $sgroups->{$idx}
		||= Net::SIP::NATHelper::SocketGroup->new( $idx,$interface,$media )
		|| return;
	return $group->get_media;
}

############################################################################
# activate session
# Args: ($self,$cseq,$idfrom,$idto)
# Returns: $success
#   $success: TRUE if activated, FALSE if something went wrong
############################################################################
sub activate_session {
	my Net::SIP::NATHelper::Call $self = shift;
	my ($cseq,$idfrom,$idto) = @_;

	my $data = $self->{by_cseq}{$cseq};
	unless ( $data ) {
		DEBUG( 10,"tried to activate non-existing cseq $cseq in call $self->{callid}" );
		return;
	}

	my $sessions = $data->{sessions};
	if ( $sessions->{"$idfrom\0$idto"} ) {
		# exists already, maybe retransmit of ACK
		return 1;
	}

	my $sgroups  = $data->{socket_groups};
	my $gfrom    = $sgroups->{$idfrom};
	my $gto      = $sgroups->{$idto};
	if ( !$gfrom || !$gto ) {
		DEBUG( 50,"session $self->{callid},$cseq $idfrom -> $idto not complete " );
		return;
	}

	$sessions->{"$idfrom\0$idto"} = Net::SIP::NATHelper::Session->new( $gfrom,$gto );
	DEBUG( 10,"new session $self->{callid},$cseq $idfrom -> $idto" );
	return 1;
}

############################################################################
# close session
# Args: ($self,$cseq,$idfrom,$idto)
#   $cseq: optional sequence number, only for CANCEL requests
# Returns: $success
#   $success: TRUE if closed, FALSE if there is no matching session
############################################################################
sub close_session {
	my Net::SIP::NATHelper::Call $self = shift;
	my ($cseq,$idfrom,$idto) = @_;

	my $by_cseq = $self->{by_cseq};
	#DEBUG( 100,$self->dump );
	if ( $cseq ) {
		# close initiated by CANCEL
		my $sess = delete $by_cseq->{$cseq}{session}{"$idfrom\0$idto"};
		unless ( $sess ) {
			DEBUG( 10,"tried to CANCEL non existing session in $self->{callid}|$cseq" );
			return;
		}
		DEBUG( 10,"close session $self->{callid}|$cseq $idto,$idfrom success" );
	} else {
		# close from BYE (which has different cseq then the INVITE)
		# need to go through all cseq to find session
		my @sessions;
		foreach my $cseq ( keys %$by_cseq ) {
			# BYE can be initiated by UAC or UAS
			my $sess;
			my $s = $by_cseq->{$cseq}{sessions};
			push @sessions,$sess if $sess = delete $s->{"$idfrom\0$idto"};
			push @sessions,$sess if $sess = delete $s->{"$idto\0$idfrom"};
		}
		unless (@sessions) {
			DEBUG( 10,"tried to BYE non existing session in $self->{callid}" );
			return;
		}
		DEBUG( 10,"close session $self->{callid} $idto,$idfrom success" );
	}

	return 1;
}

############################################################################
# expire call, e.g. inactive sessions, unused socketgroups...
# Args: ($self,$expire)
#  $expire: last activity must be greater than $expire to not expire
# Returns: TRUE if changes
############################################################################
sub expire {
	my Net::SIP::NATHelper::Call $self = shift;
	my $expire = shift;

	my $by_cseq = $self->{by_cseq};
	my $modified = 0;
	while ( my ($cseq,$data) = each %$by_cseq ) {

		# drop inactive sessions
		my $sessions = $data->{sessions};
		foreach ( keys %$sessions ) {
			my $lastmod = $sessions->{$_}->lastmod;
			if ( $lastmod < $expire ) {
				DEBUG( 10,"expired session $_ because lastmod($lastmod) < expire($expire)" );
				delete $sessions->{$_};
				$modified++;
			}
		}

		# delete socketgroups, which are not used in sessions and which
		# are expired
		# use string representation as key for comparison
		my %used;
		foreach ( values %$sessions ) {
			$used{ $_->{sfrom} }++;
			$used{ $_->{sto} }++;
		}

		my $groups = $data->{socket_groups};
		foreach my $id ( keys %$groups ) {
			my $v = $groups->{$id};
			next if $used{ $v }; # used in not expired session
			my $lastmod = $v->lastmod;
			if ( $lastmod < $expire ) {
				DEBUG( 10,"expired socketgroup $id because lastmod($lastmod) < expire($expire)" );
				delete $groups->{$id};
				$modified++;
			}
		}
	}
	return $modified;
}

############################################################################
# check if empty, e.g. no more socket groups on the call
# Args: $self
# Returns: TRUE if empty
############################################################################
sub is_empty {
	my Net::SIP::NATHelper::Call $self = shift;
	my $by_cseq = $self->{by_cseq};
	foreach my $cseq ( keys %$by_cseq ) {
		my $data = $by_cseq->{$cseq};
		if ( !%$data || !%{ $data->{socket_groups} } ) {
			delete $by_cseq->{$cseq};
		}
	}
	return %$by_cseq ? 0:1;
}

############################################################################
# collect the callbacks for all sessions within the call
# Args: $self
# Returns: @callbacks, see Net::SIP::NATHelper::Session::callbacks
############################################################################
sub callbacks {
	my Net::SIP::NATHelper::Call $self = shift;
	my @cb;
	my $by_cseq = $self->{by_cseq};
	foreach my $data ( values %$by_cseq ) {
		push @cb, map { $_->callbacks } values %{ $data->{sessions} };
	}
	return @cb;

}
############################################################################
# Dump debug information into string
# Args: $self
# Returns: $string
############################################################################
sub dump {
	my Net::SIP::NATHelper::Call $self = shift;
	my $result = "-- DUMP of call $self->{callid} --\n";
	my $by_cseq = $self->{by_cseq};
	foreach ( sort { $a <=> $b } keys %$by_cseq ) {
		$result.= "-- Socket groups in cseq $_ --\n";
		my $sgroups = $by_cseq->{$_}{socket_groups};
		foreach ( sort keys %$sgroups ) {
			$result.= $sgroups->{$_}->dump;
		}
		$result.= "-- Sessions in cseq $_ --\n";
		my $sessions = $by_cseq->{$_}{sessions};
		foreach ( sort keys %$sessions ) {
			$result.= $sessions->{$_}->dump;
		}
	}
	return $result;
}


1;
