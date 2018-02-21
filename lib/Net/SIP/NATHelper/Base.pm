use strict;
use warnings;

############################################################################
#
#    NATHelper::Base
#    Helper class for NAT of RTP connections
#    - allocate sockets for rewriting SDP bodies
#    - transfer data between sockets within sessions
#    - close sessions
#    - expire sockets and sessions on inactivity
#
############################################################################

#
# ---------------- Base ------------------------------------------------
#  |       |       |       |     ...
#                        call-id
#                          |
#       ---------- Call's -----------------------------------
#       |       |       |           |   ...
#                     idfrom
#                       |
#       ---------------------------------------------
#       |       |       |           |   ...
#                      cseq
#                       |
#       -----------------
#        |     |        |
#        |     |  socket_group_from: SocketGroup
#        |     |
#        |   socket_groups_to
#        |     |
#        |     |- idto: SocketGroup
#        |     |- idto: SocketGroup
#        |     |- idto: SocketGroup
#        |     |- idto: SocketGroup
#        |     |...
#        |
#      sessions
#        |
#        |- idto: Session containing 2 x SocketGroup
#        |- idto: Session containing 2 x SocketGroup
#        |...
#


package Net::SIP::NATHelper::Base;
use fields qw( calls max_sockets max_sockets_in_group socket_count group_count  );

use Net::SIP::Util ':all';
use Net::SIP::Debug;
use List::Util qw( first sum );
use Time::HiRes 'gettimeofday';
use Errno 'EMFILE';
use Socket;

############################################################################
# create new Net::SIP::NATHelper::Base
# Args: ($class,%args);
# Returns: $self
############################################################################
sub new {
    my ($class,%args) = @_;
    # Hash of Net::SIP::NATHelper::Call indexed by call-id
    my $self = fields::new($class);
    %$self = (
	calls => {},
	socket_count => 0,
	group_count => 0,
	max_sockets => delete $args{max_sockets},
	max_sockets_in_group => delete $args{max_sockets_in_group},
    );
    return $self;
}

############################################################################
# create a new call - might be redefined in derived classes to use
# other call classes
# Args: ($self,$callid)
#   $callid: call-id
# Returns: $call object
############################################################################
sub create_call {
    Net::SIP::NATHelper::Call->new($_[1])
}

############################################################################
# allocate new sockets for RTP
#
# Args: ($self,$callid,$cseq,$idfrom,$idto,$side,$addr,\@media)
#   $callid: call-id
#   $cseq:   sequence number for cseq
#   $idfrom: ID for from-side
#   $idto:   ID for to-side
#   $side:   0 if SDP is from request, else 1
#   $addr:   IP where to create the new sockets
#   \@media: media like returned from Net::SIP::SDP::get_media
#
# Returns: $media
#   $media: \@list of [ip,base_port] of with the size of \@media
#
# Comment: if it fails () will be returned. In this cases the SIP packet
#  should not be forwarded (dropped) thus causing a retransmit (for UDP)
#  which will then cause another call to allocate_sockets and maybe this
#  time we have enough resources
############################################################################
sub allocate_sockets {
    my Net::SIP::NATHelper::Base $self = shift;
    my $callid = shift;

    my $call = $self->{calls}{$callid}
	||= $self->create_call($callid);
    return $call->allocate_sockets( $self,@_ );
}


############################################################################
# activate session
# Args: ($self,$callid,$cseq,$idfrom,$idto;$param)
#   $callid: call-id
#   $cseq:   sequence number for cseq
#   $idfrom: ID for from-side
#   $idto:   ID for to-side
#   $param:  user defined param which gets returned from info_as_hash
# Returns: ($info,$duplicate)
#   $info:  hash from sessions info_as_hash
#   $duplicate: TRUE if session was already created
# Comment: if it returns FALSE because it fails the SIP packet will not
#   be forwarded. This is the case on retransmits of really old SIP
#   packets where the session was already closed
############################################################################
sub activate_session {
    my Net::SIP::NATHelper::Base $self = shift;
    my $callid = shift;

    my $call = $self->{calls}{$callid};
    unless ( $call ) {
	DEBUG( 10,"tried to activate non-existing call $callid" );
	return;
    }
    return $call->activate_session( @_ );
}

############################################################################
# close session(s)
# Args: ($self,$callid,$cseq,$idfrom,$idto)
#   $callid: call-id
#   $cseq:   optional sequence number, only for CANCEL requests
#   $idfrom: ID for from-side
#   $idto:   ID for to-side
# Returns: @session_info
#   @session_info: list of hashes from session info_as_hash
# Comment: this SIP packet should be forwarded, even if the call
#  is not known here, because it did not receive the response from
#  the peer yet (e.g. was retransmit)
############################################################################
sub close_session {
    my Net::SIP::NATHelper::Base $self = shift;
    my $callid = shift;

    my $call = $self->{calls}{$callid};
    unless ( $call ) {
	DEBUG( 10,"tried to close non-existing call $callid" );
	return;
    }
    return $call->close_session( @_ );
}


############################################################################
# cleanup, e.g. delete expired sessions and unused socket groups
# Args: ($self,%args)
#  %args: hash with the following data
#    time:   current time, will get from gettimeofday() if not given
#    unused: seconds for timeout of sockets, which were never used in session
#       defaults to 3 minutes
#    active: seconds for timeout of sockets used in sessions, defaults to
#       30 seconds
# Returns: @expired
#   @expired: list of infos about expired sessions using sessions info_as_hash
############################################################################
sub expire {
    my Net::SIP::NATHelper::Base $self = shift;
    my %args = @_;

    $args{time}   ||= gettimeofday();
    $args{unused} ||= 3*60; # unused sockets after 3 minutes
    $args{active} ||= 30;   # active sessions after 30 seconds
    DEBUG( 100,"expire now=$args{time} unused=$args{unused} active=$args{active}" );
    my @expired;
    my $calls = $self->{calls};
    foreach my $callid ( keys %$calls ) {
	my $call = $calls->{$callid};
	push @expired, $call->expire( %args );
	if ( $call->is_empty ) {
	    DEBUG( 50,"remove call $callid" );
	    delete $calls->{$callid};
	}
    }
    return @expired;
}

############################################################################
# collect the callbacks for all sessions in all calls
# Args: $self
# Returns: @callbacks, see *::Session::callbacks
############################################################################
sub callbacks {
    my Net::SIP::NATHelper::Base $self = shift;
    return map { $_->callbacks } values %{ $self->{calls} };
}

############################################################################
# run over all sessions and execute callback
# Args: $self;$callback
#   $callback: callback, defaults to simply return the session
# Returns: @rv
#   @rv: array with the return values of all callbacks together
############################################################################
sub sessions {
    my Net::SIP::NATHelper::Base $self = shift;
    my $callback = shift;
    $callback ||= sub { return shift }; # default callback returns session
    return map { $_->sessions( $callback ) } values %{ $self->{calls} };
}

############################################################################
# Dump debug information into string
# Args: $self
# Returns: $string
############################################################################
sub dump {
    my Net::SIP::NATHelper::Base $self = shift;
    my $result = "";
    foreach ( values %{ $self->{calls} } ) {
	$result.= $_->dump;
    }
    return $result;
}

############################################################################
# return number of reserved calls
# Args: $self
# Returns: $n
############################################################################
sub number_of_calls {
    my Net::SIP::NATHelper::Base $self = shift;
    return scalar( keys %{ $self->{calls} })
}

############################################################################
# get RTP sockets
# can be redefined to allow enforcing of resource limits, caching of
# sockets...
# right now creates fresh RTP sockets unless max_sockets is reached,
# in which case it returns () with $! set to EMFILE
# Args: ($self,$new_addr,$media)
#    $new_addr: IP for new sockets
#    $media: old media like given from Net::SIP::SDP::get_media
# Returns: \@new_media
#    @new_media: list of [ addr,base_port,\@socks,\@targets]
#      where addr and base_port are the address and base port for the new
#      media, @socks the list of sockets and @targets the matching targets
#      based on the original media
############################################################################
sub get_rtp_sockets {
    my Net::SIP::NATHelper::Base $self = shift;
    my ($new_addr,$media) = @_;
    my @new_media;

    my $need_sockets = sum( map { $_->{range} } @$media );
    if ( my $max = $self->{max_sockets_in_group} ) {
	if ( $need_sockets > $max ) {
	    DEBUG( 1,"allocation of RTP sockets denied because max_sockets_in_group limit reached" );
	    $! = EMFILE;
	    return;
	}
    }

    if ( my $max = $self->{max_sockets} ) {
	if ( $self->{socket_count} + $need_sockets > $max ) {
	    DEBUG( 1,"allocation of RTP sockets denied because max_sockets limit reached" );
	    $! = EMFILE;
	    return;
	}
    }

    foreach my $m (@$media) {
	my ($addr,$port,$range) = @{$m}{qw/addr port range/};
	# allocate new sockets
	my ($new_port,@socks) = create_rtp_sockets( $new_addr,$range );
	unless (@socks) {
	    DEBUG( 1,"allocation of RTP sockets failed: $!" );
	    return;
	}

	if (!$port or $addr eq '0.0.0.0' or $addr eq '::') {
	    # RFC 3264 6.1 - stream marked as inactive
	    DEBUG(50,"inactive stream" );
	    push @new_media, [ $new_addr,0,\@socks,
		# no target for socket on other side
		[ map { undef } (0..$#socks) ]
	    ];
	} else {
	    DEBUG( 100,"m_old=$addr $port/$range new_port=$new_port" );
	    push @new_media, [ $new_addr,$new_port,\@socks,
		# target for sock on other side is original address
		[ map { ip_parts2sockaddr($addr,$port+$_) } (0..$#socks) ]
	    ]
	}
    }

    $self->{socket_count} += $need_sockets;
    $self->{group_count} ++;

    return \@new_media;
}

############################################################################
# free created RTP sockets
# Args: $self,$media
#   $media: see return code from get_rtp_sockets
# Returns: NONE
############################################################################
sub unget_rtp_sockets {
    my Net::SIP::NATHelper::Base $self = shift;
    my $media = shift;
    $self->{group_count} --;
    $self->{socket_count} -= sum( map { int(@{ $_->[2] }) } @$media );
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
use fields qw( callid from );
use Hash::Util 'lock_keys';
use List::Util 'max';
use Net::SIP::Debug;
use Net::SIP::Util 'invoke_callback';

sub new {
    my ($class,$callid) = @_;
    my $self = fields::new($class);
    %$self = (
	callid => $callid,
	from => {},
    );
    return $self;
}

############################################################################
# allocate sockets for rewriting SDP body
# Args: ($nathelper,$self,$cseq,$idfrom,$idto,$side,$addr,$media)
# Returns: $media
############################################################################
sub allocate_sockets {
    my Net::SIP::NATHelper::Call $self = shift;
    my ($nathelper,$cseq,$idfrom,$idto,$side,$addr,$media) = @_;

    # find existing data for $idfrom,$cseq
    my $cseq_data = $self->{from}{$idfrom};
    my $data = $cseq_data && $cseq_data->{$cseq};

    if ( ! $data ) {
	# if it is not known check if cseq is too small (retransmit of old packet)
	if ( $cseq_data ) {
	    foreach ( keys %$cseq_data ) {
		if ( $_ > $cseq ) {
		    DEBUG( 10,"retransmit? cseq $cseq is smaller than $_ in call $self->{callid}" );
		    return;
		}
	    }
	}

	# need new record
	$cseq_data ||= $self->{from}{$idfrom} = {};
	$data = $cseq_data->{$cseq} = {
	    socket_group_from => undef,
	    socket_groups_to  => {},    # indexed by idto
	    sessions          => {},    # indexed by idto
	};
	lock_keys( %$data );
    }

    # if SocketGroup already exists return it's media
    # otherwise try to create a new one
    # if this fails return (), otherwise return media

    my $sgroup;
    if ( $side == 0 ) { # FROM
	$sgroup = $data->{socket_group_from} ||= do {
	    DEBUG( 10,"new socketgroup with idfrom $idfrom" );
	    Net::SIP::NATHelper::SocketGroup->new( $nathelper,$idfrom,$addr,$media )
		|| return;
	};
    } else {
	$sgroup = $data->{socket_groups_to}{$idto} ||= do {
	    DEBUG( 10,"new socketgroup with idto $idto" );
	    Net::SIP::NATHelper::SocketGroup->new( $nathelper,$idto,$addr,$media )
		|| return;
	};
    }

    return $sgroup->get_media;
}

############################################################################
# activate session
# Args: ($self,$cseq,$idfrom,$idto;$param)
# Returns: ($info,$duplicate)
############################################################################
sub activate_session {
    my Net::SIP::NATHelper::Call $self = shift;
    my ($cseq,$idfrom,$idto,$param) = @_;

    my $by_cseq = $self->{from}{$idfrom};
    my $data = $by_cseq && $by_cseq->{$cseq};
    unless ( $data ) {
	DEBUG( 10,"tried to activate non-existing session $idfrom|$cseq in call $self->{callid}" );
	return;
    }

    my $sessions = $data->{sessions};
    if ( my $sess = $sessions->{$idto} ) {
	# exists already, maybe retransmit of ACK
	return ( $sess->info_as_hash( $self->{callid},$cseq ), 1 );
    }

    my $gfrom = $data->{socket_group_from};
    my $gto   = $data->{socket_groups_to}{$idto};
    if ( !$gfrom || !$gto ) {
	DEBUG( 50,"session $self->{callid},$cseq $idfrom -> $idto not complete " );
	return;
    }

    my $sess = $sessions->{$idto} = $self->create_session( $gfrom,$gto,$param );
    DEBUG( 10,"new session {$sess->{id}} $self->{callid},$cseq $idfrom -> $idto" );

    return ( $sess->info_as_hash( $self->{callid},$cseq ), 0 );
}

############################################################################
# create Session object
# Args: ($self,$gfrom,$gto,$param)
#   $gfrom: socket group on from-side
#   $gto:   socket group on to-side
#   $param: optional session parameter (see Base::activate_session)
# Reuturns: $session object
############################################################################
sub create_session {
    shift;
    return Net::SIP::NATHelper::Session->new(@_)
}

############################################################################
# close session
# Args: ($self,$cseq,$idfrom,$idto)
#   $cseq: optional sequence number, only for CANCEL requests
# Returns: @session_info
#   @session_info: list of infos of all closed sessions, info is hash with
#     callid,cseq,idfrom,idto,from,to,bytes_from,bytes_to
############################################################################
sub close_session {
    my Net::SIP::NATHelper::Call $self = shift;
    my ($cseq,$idfrom,$idto) = @_;

    #DEBUG( 100,$self->dump );

    my @info;
    if ( $cseq ) {
	# close initiated by CANCEL
	my $data = $self->{from}{$idfrom};
	$data = $data && $data->{$cseq};
	my $sess = $data && delete( $data->{sessions}{$idto} ) or do {
	    DEBUG( 10,"tried to CANCEL non existing session in $self->{callid}|$cseq" );
	    return;
	};
	push @info, $sess->info_as_hash( $self->{callid},$cseq );
	DEBUG( 10,"close session {$sess->{id}} $self->{callid}|$cseq $idto,$idfrom success" );

    } else {
	# close from BYE (which has different cseq then the INVITE)
	# need to close all sessions between idfrom and idto, because BYE could
	# originate by UAC or UAS
	foreach my $pair ( [ $idfrom,$idto ],[ $idto,$idfrom ] ) {
	    my ($from,$to) = @$pair;
	    my $by_cseq = $self->{from}{$from} || next;

	    foreach my $cseq ( keys %$by_cseq ) {
		my $sess = delete $by_cseq->{$cseq}{sessions}{$to} || next;
		push @info, $sess->info_as_hash( $self->{callid},$cseq );
		DEBUG( 10,"close session {$sess->{id}} $self->{callid}|$cseq $idto,$idfrom " );
	    }
	}
	unless (@info) {
	    DEBUG( 10,"tried to BYE non existing session in $self->{callid}" );
	    return;
	}
	DEBUG( 10,"close sessions $self->{callid} $idto,$idfrom success" );
    }
    return @info;
}

############################################################################
# expire call, e.g. inactive sessions, unused socketgroups...
# Args: ($self,%args)
#   %args: see *::Base::expire
# Returns: @expired
#   @expired: list of infos about expired sessions containing, see
#      close_session
############################################################################
sub expire {
    my Net::SIP::NATHelper::Call $self = shift;
    my %args = @_;

    my $expire_unused = $args{time} - $args{unused};
    my $expire_active = $args{time} - $args{active};

    my @expired;
    my %active_pairs; # mapping [idfrom,idto]|[idto,idfrom] -> session.created
    my $need_next_pass;
    my $by_from = $self->{from};

    for my $pass (1,2) {
	while ( my ($idfrom,$by_cseq) = each %$by_from ) {

	    # start with highest cseq so that we hopefully need 2 passes
	    # for expire session which got replaced by new ones
	    my @cseq = sort { $b <=> $a } keys %$by_cseq;
	    foreach my $cseq ( @cseq ) {
		my $data = $by_cseq->{$cseq};

		# drop inactive sessions
		my $sessions = $data->{sessions};
		foreach my $idto ( keys %$sessions ) {
		    my $sess = $sessions->{$idto};
		    my $lastmod = max($sess->lastmod,$sess->{created});
		    if ( $lastmod < $expire_active ) {
			DEBUG( 10,"expired session {$sess->{id}} $cseq|$idfrom|$idto because lastmod($lastmod) < active($expire_active)" );
			my $sess = delete $sessions->{$idto};
			push @expired, $sess->info_as_hash( $self->{callid}, $cseq, reason => 'expired' );

		    } elsif ( my $created = max(
			$active_pairs{ "$idfrom\0$idto" } || 0,
			$active_pairs{ "$idto\0$idfrom" } || 0
			) ) {
			if ( $created > $sess->{created} ) {
			    DEBUG( 10,"removed session {$sess->{id}} $cseq|$idfrom|$idto because there is newer session" );
			    my $sess = delete $sessions->{$idto};
			    push @expired, $sess->info_as_hash( $self->{callid}, $cseq, reason => 'replaced' );
			} elsif ( $created < $sess->{created} ) {
			    # probably a session in the other direction has started
			    DEBUG( 100,"there is another session with created=$created which should be removed in next pass" );
			    $active_pairs{ "$idfrom\0$idto" } = $sess->{created};
			    $need_next_pass = 1
			}
		    } else {
			# keep session
			DEBUG( 100,"session {$sess->{id}} $idfrom -> $idto created=$sess->{created} stays active in pass#$pass" );
			$active_pairs{ "$idfrom\0$idto" } = $sess->{created};
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

		my $groups = $data->{socket_groups_to};
		my %expired_sg;
		my @v = values(%$groups);
		push @v,$data->{socket_group_from} if $data->{socket_group_from};
		foreach my $v ( @v ) {
		    next if $used{ $v }; # used in not expired session
		    my $lastmod = $v->{lastmod};
		    if ( ! $lastmod ) {
			# was never used
			if ( $v->{created} < $expire_unused ) {
			    DEBUG( 10,"expired socketgroup $v->{id} because created($v->{created}) < unused($expire_unused)" );
			    $expired_sg{$v} = 1;
			}
		    } elsif ( $lastmod < $expire_active ) {
			DEBUG( 10,"expired socketgroup $v->{id} because lastmod($lastmod) < active($expire_active)" );
			$expired_sg{$v} = 1;
		    }
		}

		$data->{socket_group_from} = undef if %expired_sg
		    and delete( $expired_sg{ $data->{socket_group_from} } );
		if ( %expired_sg ) {
		    foreach my $id (keys(%$groups)) {
			delete $groups->{$id} if delete $expired_sg{$groups->{$id}};
			%expired_sg || last;
		    }
		}
	    }
	}

	# only run again if needed
	$need_next_pass || last;
	$need_next_pass = 0;
	DEBUG( 100,'need another pass' );
    }
    return @expired;
}

############################################################################
# check if empty, e.g. no more socket groups on the call
# Args: $self
# Returns: TRUE if empty
############################################################################
sub is_empty {
    my Net::SIP::NATHelper::Call $self = shift;
    my $by_from = $self->{from};
    foreach my $idfrom ( keys %$by_from ) {
	my $by_cseq = $by_from->{$idfrom};
	foreach my $cseq ( keys %$by_cseq ) {
	    my $data = $by_cseq->{$cseq};
	    if ( ! %{ $data->{socket_groups_to}} && ! $data->{socket_group_from} ) {
		DEBUG( 100,"deleted unused cseq $cseq in $self->{callid}|$idfrom" );
		delete $by_cseq->{$cseq};
	    }
	}
	if ( ! %$by_cseq ) {
	    DEBUG( 100,"deleted unused idfrom $idfrom in $self->{callid}" );
	    delete $by_from->{$idfrom};
	}
    }
    return %$by_from ? 0:1;
}

############################################################################
# collect the callbacks for all sessions within the call
# Args: $self
# Returns: @callbacks, see Net::SIP::NATHelper::Session::callbacks
############################################################################
sub callbacks {
    my Net::SIP::NATHelper::Call $self = shift;
    my @cb;
    my $by_from = $self->{from};
    foreach my $by_cseq ( values %$by_from ) {
	foreach my $data ( values %$by_cseq ) {
	    push @cb, map { $_->callbacks } values %{ $data->{sessions} };
	}
    }
    return @cb;
}

############################################################################
# run over all session and execte callback
# Args: $self,$callback
# Returns: @rv
#  @rv: results of all callback invocations together
############################################################################
sub sessions {
    my Net::SIP::NATHelper::Call $self = shift;
    my $callback = shift;
    my $by_from = $self->{from};
    my @rv;
    foreach my $by_cseq ( values %$by_from ) {
	foreach my $data ( values %$by_cseq ) {
	    push @rv, map { invoke_callback($callback,$_) }
		values %{ $data->{sessions} };
	}
    }
    return @rv;
}

############################################################################
# Dump debug information into string
# Args: $self
# Returns: $string
############################################################################
sub dump {
    my Net::SIP::NATHelper::Call $self = shift;
    my $result = "-- DUMP of call $self->{callid} --\n";
    my $by_from = $self->{from};
    foreach my $idfrom ( sort keys %$by_from ) {
	my $by_cseq = $by_from->{$idfrom};
	foreach ( sort { $a <=> $b } keys %$by_cseq ) {
	    $result.= "-- Socket groups in $idfrom|$_ --\n";
	    my $sgroups = $by_cseq->{$_}{socket_groups_to};
	    my $sf = $by_cseq->{$_}{socket_group_from};
	    $result .= $sf->dump if $sf;
	    foreach ( sort keys %$sgroups ) {
		$result.= $sgroups->{$_}->dump;
	    }
	    $result.= "-- Sessions in $idfrom|$_ --\n";
	    my $sessions = $by_cseq->{$_}{sessions};
	    foreach ( sort keys %$sessions ) {
		$result.= $sessions->{$_}->dump;
	    }
	}
    }
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
use fields qw( sfrom sto created bytes_from bytes_to callbacks id param );
use Net::SIP::Debug;
use List::Util 'max';
use Net::SIP::Util ':all';
use Time::HiRes 'gettimeofday';

# increased for each new session
my $session_id = 0;

############################################################################
# create new Session between two SocketGroup's
# Args: ($class,$socketgroup_from,$socketgroup_to;$param)
# Returns: $self
############################################################################
sub new {
    my ($class,$sfrom,$sto,$param) = @_;
    my $self = fields::new( $class );

    # sanity check that both use the same number of sockets
    if ( @{ $sfrom->get_socks } != @{ $sto->get_socks } ) {
	DEBUG( 1,"different number of sockets in request and response" );
	return;
    }

    %$self = (
	sfrom => $sfrom,
	sto => $sto,
	created => scalar( gettimeofday() ),
	bytes_from => 0,
	bytes_to => 0,
	callbacks => undef,
	param => $param,
	id => ++$session_id,
    );
    return $self;
}

############################################################################
# returns session info as hash
# Args: ($self,$callid,$cseq,%more)
#   %more: hash with more key,values to put into info
# Returns: %session_info
#   %session_info: hash with callid,cseq,idfrom,idto,from,to,
#      bytes_from,bytes_to,sessionid and %more
############################################################################
sub info_as_hash {
    my Net::SIP::NATHelper::Session $self = shift;
    my ($callid,$cseq,%more) = @_;

    my $from = join( ",", map {
	"$_->{addr}:$_->{port}/$_->{range}"
    } @{ $self->{sfrom}{orig_media} } );

    my $to = join( ",", map {
	"$_->{addr}:$_->{port}/$_->{range}"
    } @{ $self->{sto}{orig_media} } );

    return {
	callid => $callid,
	cseq   => $cseq,
	idfrom => $self->{sfrom}{id},
	idto   => $self->{sto}{id},
	from   => $from,
	to     => $to,
	bytes_from => $self->{bytes_from},
	bytes_to => $self->{bytes_to},
	created => $self->{created},
	sessionid => $self->{id},
	param => $self->{param},
	%more,
    }
}

############################################################################
# return time of last modification, e.g. maximum of lastmod of both
# socketgroups
# Args: $self
# Returns: $lastmod
############################################################################
sub lastmod {
    my Net::SIP::NATHelper::Session $self = shift;
    return max( $self->{sfrom}{lastmod}, $self->{sto}{lastmod} );
}

############################################################################
# return all [ socket, callback,cbid ] tuples for the session
# cbid is uniq for each callback and can be used to detect, which callbacks
# changed compared to the last call
# Args: $self
# Returns: @callbacks
############################################################################

my $callback_id = 0; # uniq id for each callback
sub callbacks {
    my Net::SIP::NATHelper::Session $self = shift;

    my $callbacks = $self->{callbacks};
    return @$callbacks if $callbacks; # already computed

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

    my $fwd_data = $self->can('forward_data');

    my @cb;
    for( my $i=0;$i<@$sockets_from;$i++ ) {
	# If we detect, that the peer does symmetric RTP we connect the
	# socket and set the addr to undef to make sure that we use send
	# and not sendto when forwarding the data
	my $recvaddr = $targets_to->[$i];
	my $dstaddr = $targets_from->[$i];

	push @cb, [
	    $sockets_from->[$i],
	    [
		$fwd_data,
		$sockets_from->[$i],   # read data from socket FROM(nat)
		$sockets_to->[$i],     # forward them using socket TO(nat)
		\$recvaddr,\$dstaddr,  # will be set to undef once connected
		$sfrom,                # call $sfrom->didit
		\$self->{bytes_to},    # to count bytes coming from 'to'
		$self->{id},           # for debug messages
	    ],
	    ++$callback_id
	];

	push @cb, [
	    $sockets_to->[$i],
	    [
		$fwd_data,
		$sockets_to->[$i],     # read data from socket TO(nat)
		$sockets_from->[$i],   # forward data using socket FROM(nat)
		\$dstaddr,\$recvaddr,  # will be set to undef once connected
		$sto,                  # call $sto->didit
		\$self->{bytes_from},  # to count bytes coming from 'from'
		$self->{id},           # for debug messages
	    ],
	    ++$callback_id
	];
    }
    $self->{callbacks} = \@cb; # cache
    return @cb;
}

############################################################################
# function used for forwarding data in callbacks()
############################################################################
sub forward_data {
    my ($read_socket,$write_socket,$rfrom,$rto,$group,$bytes,$id) = @_;
    my $peer = recv( $read_socket, my $buf,2**16,0 ) || do {
	DEBUG( 10,"recv data failed: $!" );
	return;
    };

    my $name = sub { ip_sockaddr2string(shift) };

    if ( ! $$bytes ) {
	if ( $peer eq $$rfrom ) {
	    DEBUG( 10,"peer ".$name->($peer).
		" uses symmetric RTP, connecting sockets");
	    $$rfrom = undef if connect($read_socket,$peer);
	} else {
	    # set rfrom to peer for later checks
	    $$rfrom = $peer;
	}
    } elsif ( $$rfrom && $peer ne $$rfrom ) {
	# the previous packet was from another peer, ignore this data
	DEBUG( 10,"{$id} ignoring unexpected data from %s on %s, expecting data from %s instead",
	    $name->($peer), $name->(getsockname($read_socket)),$name->($$rfrom));
    }

    my $l = length($buf);
    $$bytes += $l;
    $group->didit($l);

    if ( $$rto ) {
	send( $write_socket, $buf,0, $$rto ) || do {
	    DEBUG( 10,"send data failed: $!" );
	    return;
	};
	DEBUG( 50,"{$id} transferred %d bytes on %s via %s to %s",
	    length($buf), $name->( getsockname($read_socket )),
	    $name->(getsockname( $write_socket )),$name->($$rto));
    } else {
	# using connected socket
	send( $write_socket, $buf,0 ) || do {
	    DEBUG( 10,"send data failed: $!" );
	    return;
	};
	DEBUG( 50,"{$id} transferred %d bytes on %s via %s to %s",
	    length($buf), $name->( getsockname($read_socket )),
	    $name->(getsockname( $write_socket )),
	    $name->(getpeername( $write_socket )));
    }
}


############################################################################
# Dump debug information into string
# Args: $self
# Returns: $string
############################################################################
sub dump {
    my Net::SIP::NATHelper::Session $self = shift;
    return "{$self->{id}}".
	( $self->{sfrom} && $self->{sfrom}{id} || 'NO.SFROM' ).",".
	( $self->{sto} && $self->{sto}{id} || 'NO.STO' )."\n";
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
use fields qw( id created lastmod new_media orig_media nathelper );
use Net::SIP::Debug;
use Time::HiRes 'gettimeofday';
use Socket;

############################################################################
# create new socket group based on the original media and a local address
# Args: ($class,$nathelper,$id,$new_addr,$media)
# Returns: $self|()
# Comment: () will be returned if allocation of sockets fails
############################################################################
sub new {
    my ($class,$nathelper,$id,$new_addr,$media) = @_;
    my $new_media = $nathelper->get_rtp_sockets( $new_addr,$media )
	or return;

    my $self = fields::new($class);
    %$self = (
	nathelper => $nathelper,
	id => $id,
	orig_media => [ @$media ],
	new_media => $new_media,
	lastmod => 0,
	created => scalar( gettimeofday() ),
    );
    return $self;
}

############################################################################
# give allocated sockets back to NATHelper
############################################################################
sub DESTROY {
    my Net::SIP::NATHelper::SocketGroup $self = shift;
    ($self->{nathelper} || return )->unget_rtp_sockets( $self->{new_media} )
}


############################################################################
# updates timestamp of last modification, used in expiring
# Args: ($self)
# Returns: NONE
############################################################################
sub didit {
    my Net::SIP::NATHelper::SocketGroup $self = shift;
    $self->{lastmod} = gettimeofday();
}

############################################################################
# returns \@list of media [ip,port,range] in group
# Args: $self
# Returns: \@media
############################################################################
sub get_media {
    my Net::SIP::NATHelper::SocketGroup $self = shift;
    my @media = map { [
	$_->[0],           # addr
	$_->[1],           # base port
	int(@{$_->[2]})    # range, e.g number of sockets
    ]} @{ $self->{new_media} };
    return \@media;
}

############################################################################
# returns \@list of sockets in group
# Args: $self
# Returns: \@sockets
############################################################################
sub get_socks {
    my Net::SIP::NATHelper::SocketGroup $self = shift;
    return [ map { @{$_->[2]} } @{$self->{new_media}} ];
}

############################################################################
# returns \@list of the original targets in group
# Args: $self
# Returns: \@targets
############################################################################
sub get_targets {
    my Net::SIP::NATHelper::SocketGroup $self = shift;
    return [ map { @{$_->[3]} } @{$self->{new_media}} ];
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
	@{$self->get_media} ).
	"\n";
    return $result;
}

1;
