
###########################################################################
# package Net::SIP::Dispatcher::Eventloop
# simple event loop for Net::SIP
###########################################################################

use strict;
use warnings;

package Net::SIP::Dispatcher::Eventloop;
use fields qw( fd vec just_dropped timer now );
use Time::HiRes qw(gettimeofday);
use Socket;
use List::Util qw(first);
use Net::SIP::Util ':all';
use Net::SIP::Debug;
use Carp 'confess';
use Errno 'EINTR';


# constants for read/write events
use Exporter 'import';
our @EXPORT = qw(EV_READ EV_WRITE);
use constant EV_READ  => 0;
use constant EV_WRITE => 1;

###########################################################################
# creates new event loop
# Args: $class
# Returns: $self
###########################################################################
sub new {
    my $class = shift;
    my $self = fields::new($class);
    %$self = (
	fd           => [],         # {fd}[fn][rw] -> [fd,callback,name]
	vec          => [ '','' ],  # read|write vec(..) for select
	just_dropped => undef,      # dropped fn inside current select
	timer        => [],         # list of TimerEvent objects
	now => scalar(gettimeofday()),  # time after select
    );
    return $self;
}

###########################################################################
# adds callback for the event, that FD is readable
# Args: ($self,$fd,$rw,$callback,?$name)
#  $fd: file descriptor
#  $rw: if the callback is for read(0) or write(1)
#  $callback: callback to be called, when fd is readable, will be called
#    with fd as argument
#  $name: optional name for callback, used for debugging
# Returns: NONE
###########################################################################
sub addFD {
    my Net::SIP::Dispatcher::Eventloop $self = shift;
    my ($fd,$rw,$callback,$name) = @_;
    ref($callback) or confess("wrong usage");
    defined( my $fn = fileno($fd)) || return;
    $DEBUG && DEBUG(99, "$self added fn=$fn rw($rw) sock="
	. eval { ip_sockaddr2string(getsockname($fd)) });
    $self->{fd}[$fn][$rw] = [ $fd,$callback,$name || '' ];
    vec($self->{vec}[$rw],$fn,1) = 1;
    $DEBUG && DEBUG(100, "maxfd=%d",0+@{$self->{fd}});
}

###########################################################################
# removes callback for readable for FD
# Args: ($self,$fd,?$rw)
#  $fd: file descriptor
#  $rw: if disable for read(0) or write(1). Disables both if not given
# Returns: NONE
###########################################################################
sub delFD {
    my Net::SIP::Dispatcher::Eventloop $self = shift;
    my $fd = shift;
    defined( my $fn = $fd && fileno($fd)) || return;
    if (!@_) {
	$DEBUG && DEBUG(99, "$self delete fn=$fn sock="
	    . eval { ip_sockaddr2string(getsockname($fd)) });
	delete $self->{fd}[$fn];
	vec($self->{vec}[0],$fn,1) = 0;
	vec($self->{vec}[1],$fn,1) = 0;
	# mark both read and write as dropped so we don't process events for the
	# fd inside the same loop
	$self->{just_dropped}[$fn] = [1,1] if $self->{just_dropped};

    } else {
	for my $rw (@_) {
	    $DEBUG && DEBUG(99, "$self disable rw($rw) fn=$fn sock="
		. eval { ip_sockaddr2string(getsockname($fd)) });
	    delete $self->{fd}[$fn][$rw];
	    vec($self->{vec}[$rw],$fn,1) = 0;
	    # mark $rw handler as dropped so we don't process events for the fd
	    # inside the same loop
	    $self->{just_dropped}[$fn][$rw] = 1 if $self->{just_dropped};
	}
    }
    $DEBUG && DEBUG(100, "maxfd=%d",0+@{$self->{fd}});
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
	my @vec = @{$self->{vec}};
	$DEBUG && DEBUG(100,"BEFORE read=%s write=%s",
	    unpack("b*",$vec[0]), unpack("b*",$vec[1]));
	my $nfound = select($vec[0],$vec[1], undef, $to);
	$DEBUG && DEBUG(100,"AFTER  read=%s write=%s nfound=%d",
	    unpack("b*",$vec[0]), unpack("b*",$vec[1]), $nfound);
	if ($nfound<0) {
	    next if $! == EINTR;
	    die $!
	};

	$looptime = $self->{now} = gettimeofday();
	$self->{just_dropped} = [];

	for(my $i=0; $nfound>0 && $i<@$fds; $i++) {
	    next if !$fds->[$i];
	    for my $rw (0,1) {
		vec($vec[$rw],$i,1) or next;
		$nfound--;
		next if $self->{just_dropped}[$i][$rw];
		$DEBUG && DEBUG(50,"call cb on fn=$i rw=$rw ".$fds->[$i][$rw][2]);
		invoke_callback(@{ $fds->[$i][$rw] }[1,0]);
	    }
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
