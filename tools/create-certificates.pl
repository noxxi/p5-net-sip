use strict;
use warnings;
use IO::Socket::SSL::Utils;

my $path = $ARGV[0] || 't/certs';
-d $path or die "wrong path $path - should be directory";

my $now = time();
my $then = $now + 10*365*86400;

my @ca = CERT_create(
    subject => { CN => 'root CA' },
    key => KEY_create_rsa(4096),
    not_before => $now,
    not_after => $then,
    CA => 1,
);
PEM_cert2file($ca[0],"$path/ca.pem");

for (qw(caller.sip.test listen.sip.test proxy.sip.test)) {
    my ($cert,$key) = CERT_create(
	subject => { CN => $_ },
	key => KEY_create_rsa(4096),
	not_before => $now,
	not_after => $then,
	issuer => \@ca,
    );
    open(my $fh,'>',"$path/$_.pem") or die $!;
    print $fh PEM_cert2string($cert).PEM_key2string($key);
}

