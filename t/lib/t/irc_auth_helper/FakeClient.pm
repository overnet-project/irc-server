package t::irc_auth_helper::FakeClient;

use strictures 2;
use Moo;

has response => (
  is     => 'ro',
  reader => '_response',
);
has responses => (
  is     => 'ro',
  reader => '_responses',
);
has calls => (
  is      => 'ro',
  reader  => '_calls',
  default => sub { [] },
);

no Moo;

sub sessions_authorize {
  my ($self, %params) = @_;
  push @{$self->{calls}},
    {
    method => 'sessions.authorize',
    params => \%params,
    };
  if (ref($self->{responses}) eq 'ARRAY' && @{$self->{responses}}) {
    return shift @{$self->{responses}};
  }
  return $self->{response};
}

sub calls {
  my ($self) = @_;
  return $self->{calls};
}

1;
