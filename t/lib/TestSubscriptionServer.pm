package TestSubscriptionServer;

use strictures 2;

use parent 'Overnet::Program::IRC::Server';

sub _render_subscription_item {
  my ($self, %args) = @_;
  return {
    client_ids => $self->{render_client_ids} || [1],
    line       => ':seven3 PRIVMSG #overnet :Hello',
  };
}

sub _send_client_line {
  my ($self, $client_id, $line) = @_;
  push @{$self->{sent_lines}}, [$client_id, $line];
  return 1;
}

1;
