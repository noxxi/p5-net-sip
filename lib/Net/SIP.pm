use strict;
use warnings;

require 5.008;

package Net::SIP;
our $VERSION = '0.57';

# this includes nearly everything else
use Net::SIP::Simple ();
use Net::SIP::Simple::Call ();
use List::Util 'first';

# do not include these, because they are only
# used when we do NAT
# use Net::SIP::NATHelper::Base;
# use Net::SIP::NATHelper::Local;
# use Net::SIP::NATHelper::Client;
# use Net::SIP::NATHelper::Server;

use base 'Exporter';
our (@EXPORT_OK, %EXPORT_TAGS);
BEGIN {
	foreach ( qw(
		Net::SIP::Request
		Net::SIP::Response
		Net::SIP::Packet
		Net::SIP::SDP
		Net::SIP::Simple
		Net::SIP::Simple::RTP
		Net::SIP::Dispatcher
		Net::SIP::Dispatcher::Eventloop
		Net::SIP::Redirect
		Net::SIP::Registrar
		Net::SIP::StatelessProxy
		Net::SIP::ReceiveChain
		Net::SIP::Authorize
		Net::SIP::Endpoint
		Net::SIP::NATHelper::Client
		Net::SIP::NATHelper::Server
		Net::SIP::NATHelper::Local
		Net::SIP::Debug
		Net::SIP::Leg
		)) {

		my $pkg = $_; # copy from alias
		my $sub;
		if ( $pkg =~m{^Net::SIP::(.*)} ) {
			( $sub = $1 ) =~s{::}{_}g;
		} elsif ( $pkg =~m{::(\w+)$} ) {
			$sub = $1;
		}
		if ( $sub ) {
			no strict 'refs';
			*{ $sub } = sub () { $pkg };
			push @EXPORT_OK,$sub;
			push @{ $EXPORT_TAGS{alias} },$sub;
		};
	}
}


sub import {
	my $class = shift;
	my @tags = @_;
	while ( my $tag = shift(@tags)) {
		if ( $tag eq ':all' ) {
			push @tags,':alias',':util',':debug';
		} elsif ( $tag eq ':util' ) {
			Net::SIP::Util->export_to_level(1,$class,':all')
		} elsif ( $tag eq ':debug' ) {
			Net::SIP::Debug->export_to_level(1,$class,':DEFAULT')
		} elsif ( $tag eq ':alias' ) {
			$class->export_to_level(1,$class,$tag);
		} elsif ( $tag =~m{^debug=(.*)}i ) {
			Net::SIP::Debug->level($1);
		} elsif ( first { $_ eq $tag } @EXPORT_OK ) {
			# from the predefined list
			$class->export_to_level(1,$class,$tag);
		} else {
			# default try to import from Net::SIP::Util
			Net::SIP::Util->export_to_level(1,$class,$tag)
		}
	}
}


1;
