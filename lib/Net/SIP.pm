use strict;
use warnings;

package Net::SIP;
our $VERSION = '0.16';

# this includes everything else
use Net::SIP::Simple ();
use Net::SIP::Simple::Call ();

use base 'Exporter';
our (@EXPORT_OK, %EXPORT_TAGS);
BEGIN {
	foreach ( qw(
		Net::SIP::Request
		Net::SIP::Response
		Net::SIP::Packet
		Net::SIP::SDP
		Net::SIP::Simple
		Net::SIP::Dispatcher
		Net::SIP::Dispatcher::Eventloop
		Net::SIP::Registrar
		Net::SIP::StatelessProxy
		Net::SIP::Endpoint
		)) {
		my $pkg = $_; # copy from alias
		my ($sub) = $pkg =~m{::(\w+)$};
		{
			no strict 'refs';
			*{ $sub } = sub () { $pkg };
		};
		push @EXPORT_OK,$sub;
		push @{ $EXPORT_TAGS{alias} },$sub;
	}
}


sub import {
	my $class = shift;
	my @tags = @_;
	while ( my $tag = shift(@tags)) {
		if ( $tag eq ':all' ) {
			push @tags,':alias',':util';
		} elsif ( $tag eq ':util' ) {
			Net::SIP::Util->export_to_level(2,$class,':all')
		} elsif ( $tag eq ':alias' ) {
			$class->export_to_level(1,$class,$tag);
		} elsif ( $tag =~m{^debug=(.*)}i ) {
			Net::SIP::Debug->level($1);
		} elsif ( UNIVERSAL::can( 'new',"Net::SIP::$tag" )) {
			# must be alias
			$class->export_to_level(1,$class,$tag);
		} else {
			# default try to import from Net::SIP::Util
			Net::SIP::Util->export_to_level(2,$class,$tag)
		}
	}
}


1;
