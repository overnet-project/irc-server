package TestIRCServer;

use strictures 2;
use Moo;

extends 'Overnet::Program::IRC::Server';

has sent_lines => (
  is      => 'ro',
  default => sub { [] },
);
has requests => (
  is      => 'ro',
  default => sub { [] },
);
has request_handler => (
  is      => 'rw',
  default => sub {
    sub { return }
  },
);

no Moo;

my %DEFAULT_RESPONSES = (
  'nostr.open_subscription'          => sub { return {} },
  'nostr.read_subscription_snapshot' => sub { return {events => [],} },
  'nostr.query_events'               => sub { return {events => [],} },
  'nostr.publish_event'              => sub { return {accepted => 1,} },
  'events.read'                      => sub { return {entries => [],} },
  'events.append'                    => sub { return {} },
  'subscriptions.open'               => sub { return {} },
  'subscriptions.close'              => sub { return {} },
);

sub _send_client_line {
  my ($self, $client_id, $line) = @_;
  push @{$self->{sent_lines}}, [$client_id, $line];
  return 1;
}

sub _request {
  my ($self, %args) = @_;
  push @{$self->{requests}}, {%args};

  my $handled = $self->{request_handler}->(%args);
  return $handled if defined $handled;

  my $default = $DEFAULT_RESPONSES{$args{method} || q{}};
  return $default ? $default->() : {};
}

sub configure {
  my ($self, %overrides) = @_;
  $self->{config} = {
    adapter_id     => 'irc.test',
    network        => 'overnet',
    listen_host    => '127.0.0.1',
    listen_port    => 6667,
    server_name    => 'irc.example.test',
    adapter_config => {
      authority_profile => 'nip29',
      group_host        => 'groups.example.test',
      network           => 'overnet',
    },
    authority_relay => {
      url              => 'ws://127.0.0.1:7448',
      poll_interval_ms => 250,
      query_timeout_ms => 1_000,
    },
    %overrides,
  };
  $self->{instance_id} = 'test-instance';
  return $self;
}

sub add_client {
  my ($self, $client_id, %fields) = @_;
  my $client = {
    id           => $client_id,
    registered   => 0,
    capabilities => {},
    peerhost     => '203.0.113.7',
    peerport     => 50_000 + $client_id,
    %fields,
  };
  $self->{clients}{$client_id} = $client;
  return $client;
}

sub lines_for {
  my ($self, $client_id) = @_;
  return [map { $_->[1] } grep { $_->[0] == $client_id } @{$self->{sent_lines}}];
}

sub clear_sent_lines {
  my ($self) = @_;
  @{$self->{sent_lines}} = ();
  return 1;
}

1;
