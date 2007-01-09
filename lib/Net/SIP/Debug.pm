package Net::SIP::Debug;
use strict;
use warnings;
use Carp;
use Data::Dumper;
use Time::HiRes 'gettimeofday';
use base 'Exporter';
our @EXPORT = qw( DEBUG DEBUG_DUMP LEAK_TRACK );
our @EXPORT_OK = qw( debug stacktrace );


our $level; # needed global for source filter
my %level4package;


##############################################################
# set level, scope etc from use. Usually used at the
# start, e.g. perl -MNet::SIP::Debug=level program
##############################################################
sub import {
	my $class = shift;
	my (@export,@level);
	foreach (@_) {
		if ( m{[=\*]} || m{^\d} || m{::}  ) {
			push @level,$_
		} else {
			push @export,$_
		}
	}
	if (@level) {
		$class->level(@level)
	} elsif (@export) {
		$class->export_to_level(1,@export)
	} elsif (!@_) {
		# export defaults only
		$class->export_to_level(1)
	}
}

##############################################################
# setzt/liefert debuglevel: Debug->level
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
				$name = "Net::".$name if $name =m{^SIP\b};
				$name = "Net::SIP::".$name if $name !~m{^Net::SIP\b};
				$level4package{$name} = $l;
				$level4package{$name.'::'} = $l if $below;

			} 
		}

	} else {
		# check
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
# debug Ausgabe
# debug( message ) oder debug( format, @args )
################################################################
sub DEBUG { goto &debug }
sub debug {
	return unless Debug->level;
	my ($msg,@arg) = @_;
	return if !defined($msg);
	if ( 1 || $msg !~ m{^\w+:} ) {
		# Message hat keinen eigenen "Prefix:", also mit Funktion[Zeile] prefixen
		my ($pkg,$func,$sub) = (caller(1))[0,1,3];
		my $line             = (caller(0))[2];
		$sub =~s{^main::}{} if $sub;
		$sub ||= 'Main';
		$msg = "$sub\[$line]: ".$msg;
	}

	if ( @arg ) {
		# $msg als format-string für sprintf ansehen
		no warnings 'uninitialized';
		$msg = sprintf($msg,@arg);
	}

	# alle Zeilen mit DEBUG: prefixen
	my $prefix = sprintf "%.4f DEBUG($$):", scalar(gettimeofday());
	$msg = $prefix." ".$msg;
	$msg =~s{\n}{\n$prefix\t}g;
	return $msg if defined wantarray; # don't print
	print STDERR $msg,"\n";
}

################################################################
# Dumps structure
################################################################
sub DEBUG_DUMP {
	return unless Debug->level;
	@_ = Dumper( @_>1 ? \@_:$_[0] );
	goto &debug;
}

################################################################
# Stacktrace zurückgegeben
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
