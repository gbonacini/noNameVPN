#!/usr/bin/perl

#########################################################
# Chat keys generator.
# (c) 2013-2023 GBonacini
# All Rights Reserved.
my $VERSION="0.3.2";
#########################################################

use strict;
use warnings;
use Getopt::Std;

my $seguenceId=10;
my $secureDir="$ENV{'PWD'}/.keys";
my $sequenceFile="$secureDir/sequence.srl";
my $configFile="$secureDir/openssl.cnf";
my %options;
my @keyFiles=qw/ca.pem privkey.pem server.key server.pem server.req/;
my $opensslCnf="[ req ]\ndefault_bits = 4096\ndefault_keyfile = privkey.pem\ndistinguished_name = req_distinguished_name\nprompt = no\n[ req_distinguished_name ]\nC = IT\nST = Sometplace\nL = Somewhere\nO = Dynamiclib\nOU = Dynamiclib\nCN = Common\nemailAddress = thistest\@thistest.com\n";

my $ERR_MSG=" [-h]\n";
getopts("h",\%options);
die ("$0 ${ERR_MSG}version=$VERSION\n") if(defined $options{h});

mkdir("$secureDir") unless -d $secureDir;

if(-f "$sequenceFile"){
	open(SEQUENCE, "+< $sequenceFile") or die "Can not open sequence file.\n";
	$seguenceId=<SEQUENCE>;
	chomp($seguenceId);
	$seguenceId++;
	$seguenceId=10 if($seguenceId>=99);
	seek(SEQUENCE, 0, 0);
}else{
	open(SEQUENCE, "> $sequenceFile") or die "Can not open sequence file.\n";
}
print SEQUENCE "$seguenceId\n";
close(SEQUENCE);

unless(-f $configFile){
	open(CNF_FILE, "> $configFile") or die "Can not open config file.\n";
	print CNF_FILE "$opensslCnf";
	close(CNF_FILE);
}

if(-d "$secureDir"){
	chdir("$secureDir") or die "Can change directory to $secureDir: $!";
	unlink(@keyFiles);
}else{
	mkdir("$secureDir",0700) or die "Can not create $secureDir: $!";
	chdir("$secureDir") or die "Can change directory to $secureDir: $!";
}

print STDERR "--- CA creation:\n";
system("openssl req -config $configFile -out ca.pem -new -x509") == 0
        or die "CA creation error: $?";

print STDERR "--- Private key creation:\n";
system("openssl genrsa -out server.key 4096") == 0
        or die "Private key creation error: $?";

print STDERR "--- Certificate request creation:\n";
system("openssl req -config $configFile -key server.key -new -out server.req") == 0
        or die "Certificate request creation error: $?";

print STDERR "--- Public key creation:\n";
system("openssl x509 -req -in server.req -CA ca.pem -CAkey privkey.pem -CAserial sequence.srl -out server.pem") == 0
        or die "Public key creation error: $?";

print STDERR "--- End\n";
exit 0;
