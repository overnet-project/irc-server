package t::irc_auth_daemon_e2e::FakeListener;

use strictures 2;

sub new {
  my ($class, %args) = @_;
  return bless {queue => $args{queue} || [],}, $class;
}

sub accept {
  my ($self) = @_;
  return shift @{$self->{queue}};
}

sub close {
  return 1;
}

1;
