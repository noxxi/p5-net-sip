
=head1 NAME

Net::SIP::Dropper::ByIPPort - drops SIP messages based on senders IP and port

=head1 SYNOPSIS

    use Net::SIP::Dropper::ByIPPort;
    my $drop_by_ipport = Net::SIP::Dropper::ByIPPort->new(
	database => '/path/to/database.drop',
	methods => [ 'REGISTER', '...', '' ],
	attempts => 10,
	interval => 60,
    );

    my $dropper = Net::SIP::Dropper->new( cb => $drop_by_ipport );
    my $chain = Net::SIP::ReceiveChain->new([ $dropper, ... ]);

=head1 DESCRIPTION

With C<Net::SIP::Dropper::ByIPPort> one can drop packets, if too much packets
are received from the same IP and port within a specific interval. This is to
stop bad behaving clients.

=cut


use strict;
use warnings;

package Net::SIP::Dropper::ByIPPort;
use Net::SIP::Debug;
use Net::SIP::Util 'invoke_callback';
use fields qw(interval attempts methods dbcb data);

=head1 CONSTRUCTOR

=over 4

=item new ( ARGS )

ARGS is a hash with the following keys:

=over 8

=item database

Optional file name of database or callback for storing/retrieving the data.

If it is a callback it will be called with C<< $callback->(\%data) >> to
retrieve the data (C<%data> will be updated) and C<< $callback->(\%data,true) >>
to save the data. No return value will be expected from the callback.

%data contains the number of attempts from a specific IP, port at a specific
time in the following format:
C<< $data{ip}{port}{time} = count >>

=item attempts

After how many attempts within the specific interval the packet will be dropped.
Argument is required.

=item interval

The interval for attempts.  Argument is required.

=item methods

Optional argument to restrict dropping to specific methods.

Is array reference of method names, if one of the names is empty also responses
will be considered. If not given all packets will be checked.

=back

=back

=cut

sub new {
    my ($class,%args) = @_;
    my $interval = delete $args{interval} or croak('interval should be defined');
    my $attempts = delete $args{attempts} or croak('attempts should be defined');
    my $methods  = delete $args{methods}; # optional

    my %ips_ports;
    my $dbcb;
    if ( my $db = delete $args{database} ) {
	if ( ! ref $db ) {
	    # file name
	    require Storable;
	    if ( ! -e $db ) {
		# initialize DB
		Storable::store(\%ips_ports, $db) or
		    croak("cannot create $db: $!");
	    }
	    $dbcb = [
		sub {
		    my ($file,$data,$save) = @_;
		    if ( $save ) {
			Storable::store($data,$file);
		    } else {
			%$data = %{ Storable::retrieve($file) }
		    }
		},
		$db
	    ];
	} else {
	    $dbcb = $db
	}

	# load contents of database
	invoke_callback($dbcb,\%ips_ports);

	DEBUG_DUMP(100, \%ips_ports);
    }


    # initialize object
    my Net::SIP::Dropper::ByIPPort $self = fields::new($class);
    $self->{data} = \%ips_ports;
    $self->{interval} = $interval;
    $self->{attempts} = $attempts;
    $self->{methods}  = $methods;
    $self->{dbcb} = $dbcb;

    return $self
}

=head1 METHODS

=over 4

=item run ( PACKET, LEG, FROM )

This method is called as a callback from the L<Net::SIP::Dropper> object.
It returns true if the packet should be dropped, e.g. if there are too much
packets from the same ip,port within the given interval.

=cut

sub run {
    my Net::SIP::Dropper::ByIPPort $self = shift;
    my ($packet,$leg,$from) = @_;

    # expire current contents
    $self->expire;

    # check if the packet type/method fits
    if (my $m = $self->{methods}) {
	if ($packet->is_response) {
	    return if ! grep { !$_ } @$m
	} else {
	    my $met = $packet->method;
	    return if ! grep { $_ eq $met } @$m
	}
    };

    # enter ip,port into db
    my ($ip,$port) = ($from->{addr},$from->{port});
    $self->{data}{$ip}{$port}{ time() }++;
    $self->savedb();

    # count attempts in interval
    # because everything outside of interval is expired we can
    # just look at all entries for ip,port
    my $count = 0;
    for (values %{$self->{data}{$ip}{$port}} ) {
	$count += $_;
    }
    # by using port = 0 one can block the whole IP
    for (values %{$self->{data}{$ip}{0} || {}} ) {
	$count += $_;
    }

    # drop if too much attempts
    if ( $count >= $self->{attempts} ) {
	DEBUG(1,"message dropped because $ip:$port was in database with $count attempts");
	return 1;
    }
    return;
}

=item expire

This method is called from within C<run> but can also be called by hand.
It will expire all entries which are outside of the interval.

=cut

sub expire {
    my Net::SIP::Dropper::ByIPPort $self = shift;
    my $interval = $self->{interval};
    my $data = $self->{data};

    my $maxtime = time() - $interval;
    my $changed;
    for my $ip ( keys %$data ) {
	my $ipp = $data->{$ip};
	for my $port (keys %$ipp) {
	    my $ippt = $ipp->{$port};
	    for my $time (keys %$ippt) {
		if ($time<=$maxtime) {
		    delete $ippt->{$time};
		    $changed = 1;
		}
	    }
	    delete $ipp->{$port} if ! %$ippt;
	}
	delete $data->{$ip} if ! %$ipp;
    }
    $self->savedb if $changed;
}

=item savedb

This method is called from C<expire> and C<run> for saving to the database after
changes, but can be called by hand to, useful if you made manual changes using
the C<data> method.

=cut

sub savedb {
    my Net::SIP::Dropper::ByIPPort $self = shift;
    my $dbcb = $self->{dbcb} or return;
    invoke_callback($dbcb,$self->{data},'save')
}

=item data

This method gives access to the internal hash which stores the attempts.
An attempt from a specific IP and port and a specific time (as int, like time()
gives) will be added to
 C<< $self->data->{ip}{port}{time} >>.

By manually manipulating the hash one can restrict a specific IP,port forever
(just set time to a large value and add a high number of attempts) or even
restrict access for the whole IP (all ports) until time by using a port number
of 0.

After changes to the data it is advised to call C<savedb>.

=cut

sub data {
    my Net::SIP::Dropper::ByIPPort $self = shift;
    return $self->{data}
}

=pod

=back

=cut

1;
