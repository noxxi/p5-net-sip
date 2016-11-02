package Net::SIP::Debug;
use strict;
use warnings;
use Carp;
use Data::Dumper;
use Time::HiRes 'gettimeofday';
use Scalar::Util 'looks_like_number';
use base 'Exporter';
our @EXPORT = qw( DEBUG DEBUG_DUMP LEAK_TRACK $DEBUG );
our @EXPORT_OK = qw( debug stacktrace );


our $DEBUG = 0; # exported fast check: if false no kind of debugging is done
our $level = 0; # needed global for source filter

my %level4package;           # package specific level
my $debug_prefix = 'DEBUG:'; # default prefix
my $debug_sub;               # alternative sub to STDERR output


##############################################################
# set level, scope etc from use. Usually used at the
# start, e.g. perl -MNet::SIP::Debug=level program
# Args: @args
#  @args: something for sub level, rest to Exporter
# Returns: NONE
##############################################################
sub import {
    my $class = shift;
    my (@export,@level);
    for (@_) {
	if ( ref eq 'CODE' ) {
	    # set debug sub
	    $debug_sub = $_;
	} elsif ( m{[=\*]} || m{^\d} || m{::}  ) {
	    push @level,$_
	} else {
	    push @export,$_
	}
    }
    $class->level(@level) if @level;
    $class->export_to_level(1,@export) if @export;
    $class->export_to_level(1) if ! @export && ! @level;
}

##############################################################
# set/get debug level
# Args: ($class,@spec)
#  @spec: number|package|package=number for setting
#   global|package specific debug level. If package
#   is postfixed with '*' the level will be used for
#   subpackages too.
# Returns: NONE|level
#   level: if not @spec level for the current package
#      (first outside Net::SIP::Debug in caller stack) will
#      be returned
##############################################################
sub level {
    shift; # class
    if ( @_ ) {
	my @level = @_ >1 ? split( m{[^\w:=\*]+}, $_[0] ): @_;
	foreach (@level) {
	    if ( m{^\d+$} ) {
		$level = $_;
	    } elsif ( m{^([\w:]+)(\*)?(?:=(\d+))?$} ) {
		# package || package=level
		my $l = defined($3) ? $3: $level || 1;
		my $name = $1;
		my $below = $2;
		my @names = ( $name );
		push @names, "Net::".$name if $name =m{^SIP\b};
		push @names, "Net::SIP::".$name if $name !~m{^Net::SIP\b};
		foreach (@names) {
		    $level4package{$_} = $l;
		    $level4package{$_.'::'} = $l if $below;
		}
	    }
	}
	$DEBUG = grep { $_>0 } ($level, values(%level4package));

    } else {
	# check
	$DEBUG or return 0;
	if ( %level4package ) {
	    # check if there is a specific level for this package
	    my $pkg;
	    for( my $i=1;1;$i++ ) {
		# find first frame outside of this package
		($pkg) = caller($i);
		last if !$pkg or $pkg ne __PACKAGE__;
	    }
	    return $level if !$pkg;

	    # find exakt match
	    my $l = $level4package{$pkg};
	    return $l if defined($l);

	    # find match for upper packages, e.g. if there is an entry for
	    # 'Net::SIP::' it matches everything below Net::SIP
	    while ( $pkg =~s{::\w+(::)?$}{::} ) {
		return $l if defined( $l = $level4package{$pkg} );
	    }
	}
    }
    return $level
}

################################################################
# set prefix
# default prefix is 'DEBUG:' but in forking apps it might
# be useful to change it to "DEBUG($$):" or similar
# Args: $class,$prefix
# Returns: NONE
################################################################
sub set_prefix {
    (undef,$debug_prefix) = @_
}

################################################################
# write debug output if debugging enabled for caller
# Args: ?$level, ( $message | $fmt,@arg )
#  $level: if first arg is number it's interpreted as debug level
#   $message: single message
#   $fmt: format for sprintf
#   @arg: arguments for sprintf after format
# Returns: NONE
################################################################
sub DEBUG { goto &debug }
sub debug {
    $DEBUG or return;
    my $level = __PACKAGE__->level || return;
    my $prefix = $debug_prefix;
    if (@_>1 and looks_like_number($_[0])) {
	my $when = shift;
	return if $when>$level;
	$prefix .= "<$when>";
    }
    my ($msg,@arg) = @_;
    return if !defined($msg);
    if ( 1 || $msg !~ m{^\w+:} ) {
	# Message hat keinen eigenen "Prefix:", also mit Funktion[Zeile] prefixen
	my ($sub) = (caller(1))[3];
	my $line  = (caller(0))[2];
	$sub =~s{^main::}{} if $sub;
	$sub ||= 'Main';
	$msg = "$sub\[$line]: ".$msg;
    }

    if ( @arg ) {
	# $msg als format-string für sprintf ansehen
	no warnings 'uninitialized';
	$msg = sprintf($msg,@arg);
    }

    # if $debug_sub use this
    return $debug_sub->($msg) if $debug_sub;

    # alle Zeilen mit DEBUG: prefixen
    $prefix = sprintf "%.4f %s",scalar(gettimeofday()),$prefix;
    $msg = $prefix." ".$msg;
    $msg =~s{\n}{\n$prefix\t}g;
    return $msg if defined wantarray; # don't print
    $msg =~s{[^[:space:][:print:]]}{_}g;
    print STDERR $msg,"\n";
}

################################################################
# Dumps structure if debugging enabled
# Args: ?$level,@data
#  $level: if first arg is number it's interpreted as debug level
#  @data: what to be dumped, if @data>1 will dump \@data, else $data[0]
# Returns: NONE
################################################################
sub DEBUG_DUMP {
    $DEBUG or return;
    my $level = __PACKAGE__->level || return;
    my $when;
    if (@_>1 and looks_like_number($_[0])) {
	$when = shift;
	return if $when>$level;
    }
    @_ = Dumper( @_>1 ? \@_:$_[0] );
    unshift @_,$when if defined $when;
    goto &debug;
}

################################################################
# return stacktrace
# Args: $message | $fmt,@arg
# Returns: $stacktrace
#   $stacktrace: stracktrace including debug info from args
################################################################
sub stacktrace {
    return Carp::longmess( debug(@_) );
}


################################################################
# helps to track leaks, e.g. where refcounts will never go to
# zero because of circular references...
# will build proxy object around reference and will inform when
# LEAK_TRACK is called or when object gets destroyed. If Devel::Peek
# is available it will Devel::Peek::Dump the object on each
# LEAK_TRACK (better would be to just show the refcount of the
# reference inside the object, but Devel::Peek dumps to STDERR
# and I didn't found any other package to provide the necessary
# functionality)
# Args: $ref
# Returns: $ref
#  $ref: reblessed original reference if not reblessed yet
################################################################
sub LEAK_TRACK {
    my $class = ref($_[0]);
    my $leak_pkg = '__LEAK_TRACK__';

    my ($file,$line) = (caller(0))[1,2];
    my $count = Devel::Peek::SvREFCNT($_[0]);

    if ( $class =~m{^$leak_pkg} ) {
	# only print info
	warn "$_[0] +++ refcount($count) tracking from $file:$line\n";
	Devel::Peek::Dump($_[0],1);
	return $_[0];
    }

    unless ( $class eq 'HASH' || $class eq 'ARRAY' || $class eq 'SCALAR' ) {
	# need to create wrapper package ?
	$leak_pkg .= '::'.$class;
	if ( ! UNIVERSAL::can( $leak_pkg, 'DESTROY' )) {
	    eval <<EOL;
package $leak_pkg;
our \@ISA = qw( $class );
sub DESTROY {
    warn "\$_[0] --- destroy\n";
    \$_[0]->SUPER::DESTROY;
}
EOL
	    die $@ if $@;
	}
    }

    bless $_[0], $leak_pkg;
    warn "$_[0] +++ refcount($count) starting tracking called from $file:$line\n";
    Devel::Peek::Dump($_[0],1);
    return $_[0];
}

{
    package __LEAK_TRACK__;
    sub DESTROY {
	my ($file,$line) = (caller(0))[1,2];
	warn "$_[0] --- destroy in $file:$line\n";
    }
}

eval 'require Devel::Peek';
if ( $@ ) {
    # cannot be loaded
    *{ 'Devel::Peek::Dump' } = sub {};
    *{ 'Devel::Peek::SvREFCNT' } = sub { 'unknown' };
}


=for experimental_use_only

# works, but startup of programs using this is noticably slower, therefore
# not enabled by default

use Filter::Simple;
FILTER_ONLY( code => sub {

    # replace DEBUG(...) with
    # - if Debug::level around it (faster, because expressions inside debug
    #   get only evaluated if debugging is active)
    # - no warnings for expressions, because in often debug messages
    #   are quick and dirty
    # FIXME: do it for DEBUG_DUMP too
    # cannot use Text::Balanced etc because placeholder might contain ')' which
    # should not be matched

    my $code = '';
    {
	local $_ = $_; # copy
	while (1) {
	    $code .=
		s{\ADEBUG\s*\(}{}s ? '' :
		s{\A(.*?[^\w:])DEBUG\s*\(}{}s ? $1 :
		last;
	    my $level = 1;
	    my $inside = '';
	    while ( s{\A((?:$Filter::Simple::placeholder|.)*?)([()])}{}s ) {
		$inside .= $1;
		$level += ( $2 eq '(' ) ? +1:-1;
		last if !$level;
		$inside .= $2;
	    }
	    $level && die "unbalanced brackets in DEBUG(..)";
	    $code .= "if (\$Debug::level) { no warnings; Debug::debug($inside) }";
	}
	$code .= $_; # rest
    }
    $_ = $code;
});

=cut

1;
