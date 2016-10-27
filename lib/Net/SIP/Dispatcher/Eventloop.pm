
###########################################################################
# package Net::SIP::Dispatcher::Eventloop
# simple event loop for Net::SIP
###########################################################################

use strict;
use warnings;

package Net::SIP::Dispatcher::Eventloop;
use fields qw( fd timer now );
use Time::HiRes qw(gettimeofday);
use Socket;
use List::Util qw(first);
use Net::SIP::Util 'invoke_callback';
use Net::SIP::Debug;
use Errno 'EINTR';

###########################################################################
# creates new event loop
# Args: $class
# Returns: $self
###########################################################################
sub new {
    my $class = shift;
    my $self = fields::new($class);
    %$self = (
	fd => [],
	timer => [],
	now => scalar(gettimeofday()),
    );
    return $self;
}

###########################################################################
# adds callback for the event, that FD is readable
# Args: ($self,$fd,$callback,?$name)
#  $fd: file descriptor
#  $callback: callback to be called, when fd is readable, will be called
#    with fd as argument
#  $name: optional name for callback, used for debugging
# Returns: NONE
###########################################################################
sub addFD {
    my Net::SIP::Dispatcher::Eventloop $self = shift;
    my ($fd,$callback,$name) = @_;
    defined( my $fn = fileno($fd)) || return;
    #DEBUG( 100, "$self added fn=$fn sock=".ip_sockaddr2string(getsockname($fd)));
    $self->{fd}[$fn] = [ $fd,$callback,$name ];
}

###########################################################################
# removes callback for readable for FD
# Args: ($self,$fd)
#  $fd: file descriptor
# Returns: NONE
###########################################################################
sub delFD {
    my Net::SIP::Dispatcher::Eventloop $self = shift;
    my ($fd) = @_;
    defined( my $fn = fileno($fd)) || return;
    #DEBUG( 100, "$self delete fn=$fn sock=".ip_sockaddr2string(getsockname($fd)));
    delete $self->{fd}[$fn];
}

###########################################################################
# add timer
# Args: ($self,$when,$callback;$repeat,$name)
#  $when: absolute time_t or relative (smaller than a year), can be
#    subsecond resolution
#  $callback: callback to be called, gets timer object as argument
#  $repeat: interval for repeated callbacks, optional
#  $name: optional name for debugging
# Returns: $timer object
###########################################################################
sub add_timer {
    my Net::SIP::Dispatcher::Eventloop $self = shift;
    my ($when,$callback,$repeat,$name ) = @_;
    $when += $self->{now} if $when < 3600*24*365;

    my $timer = Net::SIP::Dispatcher::Eventloop::TimerEvent->new(
	$when, $repeat, $callback,$name );
    push @{ $self->{timer}}, $timer;
    return $timer;
}

###########################################################################
# return time of currentloop, e.g. when select(2) returned
# Args: ()
# Returns: time
###########################################################################
sub looptime {
    my Net::SIP::Dispatcher::Eventloop $self = shift;
    return $self->{now}
}


###########################################################################
# simple mainloop
# Args: ($self;$timeout,@stop)
#  $timeout: if 0 just poll once, if undef never return, otherwise return
#    after $timeout seconds
#  @stop: \@array of Scalar-REF, if one gets true the eventloop will be stopped
# Returns: NONE
###########################################################################
sub loop {
    my Net::SIP::Dispatcher::Eventloop $self = shift;
    my ($timeout,@stop) = @_;

    # looptime for this run
    my $looptime = $self->{now} = gettimeofday();

    # if timeout defined and != 0 set $end to now+timeout
    # otherwise set end to undef|0 depending on timeout
    my $end = $timeout ? $looptime + $timeout : $timeout;
    my $to = $timeout;

    while ( !$to || $to>0 ) {

	DEBUG( 100, "timeout = ".( defined($to) ? $to: '<undef>' ));
	# handle timers
	my $timer = $self->{timer};

	my $do_timer = 1;
	while ( @$timer && $do_timer ) {
	    $do_timer = 0;
	    @$timer = sort { $a->{expire} <=> $b->{expire} } @$timer;

	    # delete canceled timers
	    shift(@$timer) while ( @$timer && !$timer->[0]{expire} );

	    # run expired timers
	    while ( @$timer && $timer->[0]{expire} <= $looptime ) {
		my $t = shift(@$timer);
		DEBUG( 50, "trigger timer(%s) %s repeat=%s",
		    $t->name,$t->{expire} || '<undef>', $t->{repeat} || '<undef>' );
		invoke_callback( $t->{callback},$t );
		if ( $t->{expire} && $t->{repeat} ) {
		    $t->{expire} += $t->{repeat};
		    DEBUG( 100, "timer(%s) gets repeated at %d",$t->name,$t->{expire} );
		    push @$timer,$t;
		    $do_timer = 1; # rerun loop
		}
	    }
	}

	# adjust timeout for select based on when next timer expires
	if ( @$timer ) {
	    my $next_timer = $timer->[0]{expire} - $looptime;
	    $to = $next_timer if !defined($to) || $to>$next_timer;
	}
	DEBUG( 100, "timeout = ".( defined($to) ? $to: '<undef>' ));

	if ( grep { ${$_} } @stop ) {
	    DEBUG( 50, "stopvar triggered" );
	    return;
	}

	# wait for selected fds
	my $fds = $self->{fd};
	my $rin;
	if ( my @to_read = grep { $_ } @$fds ) {

	    # Select which fds are readable or timeout
	    my $rin = '';
	    map { vec( $rin,fileno($_->[0]),1 ) = 1 } @to_read;
	    DEBUG( 100, "handles=".join( " ",map { fileno($_->[0]) } @to_read ));
	    select( my $rout = $rin,undef,undef,$to ) < 0 and do {
		next if $! == EINTR;
		die $!
	    };
	    # returned from select
	    $looptime = $self->{now} = gettimeofday();
	    DEBUG( 100, "can_read=".join( " ",map { $_ } grep { $fds->[$_] && vec($rout,$_,1) } (0..$#$fds)));
	    for( my $fn=0;$fn<@$fds;$fn++ ) {
		vec($rout,$fn,1) or next;
		my $fd_data = $fds->[$fn] or next;
		DEBUG( 50,"call cb on fn=$fn ".( $fd_data->[2] || '') );
		invoke_callback( $fd_data->[1],$fd_data->[0] );
	    }
	} else {
	    DEBUG( 50, "no handles, sleeping for %s", defined($to) ? $to : '<endless>' );
	    select(undef,undef,undef,$to )
	}

	if ( defined($timeout)) {
	    last if !$timeout;
	    $to = $end - $looptime;
	} else {
	    $to = undef
	}
    }
}


##########################################################################
# Timer object which gets returned from add_timer and has method for
# canceling the timer (by setting expire to 0)
##########################################################################
package Net::SIP::Dispatcher::Eventloop::TimerEvent;
use fields qw( expire repeat callback name );

##########################################################################
# create new timer object, see add_timer for description of Args
# Args: ($class,$expire,$repeat,$callback)
# Returns: $self
##########################################################################
sub new {
    my ($class,$expire,$repeat,$callback,$name) = @_;
    my $self = fields::new( $class );
    unless ( $name ) {
	# check with caller until I find a function which is not
	# named 'add_timer'
	for( my $i=1;1;$i++ ) {
	    my (undef,undef,undef,$sub) = caller($i) or last;
	    next if $sub =~m{::add_timer$};
	    my $line = (caller($i-1))[2];
	    $name = "${sub}[$line]";
	    last;
	}
    }
    %$self = (
	expire => $expire,
	repeat => $repeat,
	callback => $callback,
	name => $name
    );
    return $self;
}

##########################################################################
# cancel timer by setting expire to 0, it will be deleted next time
# the timer queue is scanned in loop
# Args: $self
# Returns: NONE
##########################################################################
sub cancel {
    my Net::SIP::Dispatcher::Eventloop::TimerEvent $self = shift;
    $self->{expire} = 0;
    $self->{callback} = undef;
}

##########################################################################
# returns name for debugging
# Args: $self
# Returns: $name
##########################################################################
sub name {
    my Net::SIP::Dispatcher::Eventloop::TimerEvent $self = shift;
    return $self->{name} || 'NONAME'
}

1;
