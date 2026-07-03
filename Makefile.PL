use strictures 2;

use ExtUtils::MakeMaker;

our $VERSION = '0.001';

my $space = chr 32;

WriteMakefile(
  NAME               => 'Overnet::Program::IRC::Server',
  DISTNAME           => 'Overnet-IRC-Server',
  AUTHOR             => 'Nicholas B. Hubbard <nicholashubbard@posteo.net>',
  ABSTRACT           => 'The Overnet IRC server program, implemented in Perl',
  VERSION_FROM       => 'lib/Overnet/Program/IRC/Server.pm',
  LICENSE            => 'gpl_3',
  MIN_PERL_VERSION   => '5.040',
  CONFIGURE_REQUIRES => {
    'ExtUtils::MakeMaker' => 0,
    'strictures'          => 2,
  },
  PREREQ_PM => {
    'IO::Socket::SSL' => 0,
    'JSON'            => 0,
    'Moo'             => 0,
    'Net::Nostr'      => 0,
    'Overnet'         => 0.001,
    'Overnet::Relay'  => 0.001,
    'strictures'      => 2,
  },
  EXE_FILES => [
    'bin/overnet-irc-auth.pl',            'bin/overnet-irc-authority-relay-service.pl',
    'bin/overnet-irc-authority-relay.pl', 'bin/overnet-irc-chat-client.pl',
    'bin/overnet-irc-local-server.pl',    'bin/overnet-irc-server.pl',
    'bin/overnet-irc-service.pl',         'bin/overnet-irc-proxy.pl',
  ],
  test => {
    TESTS => join(
      $space,
      qw(
        t/00-load.t
        t/bin-syntax.t
        t/irc-auth-cli.t
        t/irc-auth-helper.t
        t/irc-proxy-cli.t
        t/irc-proxy-runner.t
        t/irc-proxy-smoke.t
        t/irc-proxy.t
        t/makemaker-metadata.t
        t/manifest-skip-policy.t
        t/readme-auth.t
        t/write-failures.t
      )
    ),
  },
  META_MERGE => {
    resources => {
      repository => 'https://github.com/overnet-project/irc-server',
      bugtracker => 'https://github.com/overnet-project/irc-server/issues',
    },
  },
);
