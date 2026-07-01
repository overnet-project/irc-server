package t::irc_auth_daemon_e2e::FakeListener;

use strictures 2;
use Moo;

has queue => (
  is      => 'ro',
  reader  => '_queue',
  default => sub { [] },
);

no Moo;

sub accept {
  my ($self) = @_;
  return shift @{$self->{queue}};
}

sub close {
  return 1;
}

1;
