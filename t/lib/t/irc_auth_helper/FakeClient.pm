package t::irc_auth_helper::FakeClient;

use strictures 2;

sub new {
  my ($class, %args) = @_;
  return bless {
    response  => $args{response},
    responses => $args{responses},
    calls     => [],
  }, $class;
}

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
