package Overnet::Program::IRC::Dispatcher;

use strictures 2;
use Moo;
use Overnet::Program::IRC::Command::Auth;
use Overnet::Program::IRC::Command::Channel;

our $VERSION = '0.001';

has server => (
  is       => 'ro',
  required => 1,
  weak_ref => 1,
);
has parser => (
  is       => 'ro',
  required => 1,
);

no Moo;

my %CONNECTION_COMMAND_HANDLERS = (
  CAP => sub {
    my ($server, $client_id, $client, $command, $params) = @_;
    return Overnet::Program::IRC::Command::Auth::handle_cap($server, $client_id, $params,);
  },
  NICK => sub {
    my ($server, $client_id, $client, $command, $params) = @_;
    return $server->_handle_nick_command($client_id, $client, $params);
  },
  USER => sub {
    my ($server, $client_id, $client, $command, $params) = @_;
    return $server->_handle_user_command($client_id, $client, $params);
  },
  PING => sub {
    my ($server, $client_id, $client, $command, $params) = @_;
    return $server->_handle_ping_command($client_id, $params);
  },
  AUTHENTICATE => sub {
    my ($server, $client_id, $client, $command, $params) = @_;
    return Overnet::Program::IRC::Command::Auth::handle_authenticate($server, $client_id, $params,);
  },
  QUIT => sub {
    my ($server, $client_id, $client, $command, $params) = @_;
    return $server->_handle_quit_command($client_id, $params);
  },
);

my %REGISTERED_COMMAND_HANDLERS = (
  OVERNETKEY => sub {
    my ($server, $client_id, $client, $command, $params) = @_;
    return $server->_handle_overnetkey_command($client_id, $client, $params);
  },
  OVERNETAUTH => sub {
    my ($server, $client_id, $client, $command, $params) = @_;
    return Overnet::Program::IRC::Command::Auth::handle_overnetauth($server, $client_id, $params,);
  },
  OVERNETCHANNEL => sub {
    my ($server, $client_id, $client, $command, $params) = @_;
    return Overnet::Program::IRC::Command::Channel::handle_overnetchannel($server, $client_id, $params,);
  },
  USERHOST => sub {
    my ($server, $client_id, $client, $command, $params) = @_;
    return $server->_handle_userhost_command($client_id, $params);
  },
  WHO => sub {
    my ($server, $client_id, $client, $command, $params) = @_;
    return $server->_handle_who_command($client_id, $client, $params);
  },
  WHOIS => sub {
    my ($server, $client_id, $client, $command, $params) = @_;
    return $server->_handle_whois_command($client_id, $params);
  },
  MODE => sub {
    my ($server, $client_id, $client, $command, $params) = @_;
    return Overnet::Program::IRC::Command::Channel::handle_mode($server, $client_id, $params,);
  },
  KICK => sub {
    my ($server, $client_id, $client, $command, $params) = @_;
    return Overnet::Program::IRC::Command::Channel::handle_kick($server, $client_id, $params,);
  },
  INVITE => sub {
    my ($server, $client_id, $client, $command, $params) = @_;
    return Overnet::Program::IRC::Command::Channel::handle_invite($server, $client_id, $params,);
  },
  JOIN => sub {
    my ($server, $client_id, $client, $command, $params) = @_;
    return Overnet::Program::IRC::Command::Channel::handle_join($server, $client_id, $params,);
  },
  NAMES => sub {
    my ($server, $client_id, $client, $command, $params) = @_;
    return $server->_handle_names_command($client_id, $params);
  },
  PART => sub {
    my ($server, $client_id, $client, $command, $params) = @_;
    return Overnet::Program::IRC::Command::Channel::handle_part($server, $client_id, $params,);
  },
  PRIVMSG => sub {
    my ($server, $client_id, $client, $command, $params) = @_;
    return Overnet::Program::IRC::Command::Channel::handle_privmsg_or_notice($server, $client_id, $command, $params,);
  },
  NOTICE => sub {
    my ($server, $client_id, $client, $command, $params) = @_;
    return Overnet::Program::IRC::Command::Channel::handle_privmsg_or_notice($server, $client_id, $command, $params,);
  },
  TOPIC => sub {
    my ($server, $client_id, $client, $command, $params) = @_;
    return Overnet::Program::IRC::Command::Channel::handle_topic($server, $client_id, $params,);
  },
  LUSERS => sub {
    my ($server, $client_id, $client, $command, $params) = @_;
    $server->_send_lusers_reply($client_id);
    return 1;
  },
  LIST => sub {
    my ($server, $client_id, $client, $command, $params) = @_;
    return Overnet::Program::IRC::Command::Channel::handle_list($server, $client_id, $params,);
  },
);

sub dispatch_line {
  my ($self, $client_id, $line) = @_;
  my $server = $self->server;
  my $client = $server->{clients}{$client_id}
    or return 1;
  my $message = $self->parser->parse($line);
  if (!($message)) {
    return 1;
  }

  my $command = $message->{command};
  my @params  = @{$message->{params} || []};

  my $connection_result = $self->_dispatch_connection($client_id, $client, $command, \@params);
  if (defined $connection_result) {
    return $connection_result;
  }

  if (!$client->{registered}) {
    return $self->_dispatch_unregistered($client_id, $command);
  }

  return $self->_dispatch_registered($client_id, $client, $command, \@params);
}

sub _dispatch_connection {
  my ($self, $client_id, $client, $command, $params) = @_;
  my $handler = $CONNECTION_COMMAND_HANDLERS{$command};
  if (!(defined $handler)) {
    return;
  }
  return $handler->($self->server, $client_id, $client, $command, $params);
}

sub _dispatch_unregistered {
  my ($self, $client_id, $command) = @_;
  my $server = $self->server;
  if ($server->_command_requires_registration($command)) {
    $server->_send_not_registered($client_id);
    return 1;
  }

  $server->_send_unknown_command($client_id, $command);
  return 1;
}

sub _dispatch_registered {
  my ($self, $client_id, $client, $command, $params) = @_;
  my $server  = $self->server;
  my $handler = $REGISTERED_COMMAND_HANDLERS{$command};
  if (defined $handler) {
    return $handler->($server, $client_id, $client, $command, $params);
  }

  $server->_send_unknown_command($client_id, $command);
  return 1;
}

1;

=head1 NAME

Overnet::Program::IRC::Dispatcher - Route parsed IRC commands

=head1 DESCRIPTION

This internal collaborator owns command selection and registration-phase
routing. Command behavior remains in the server services and the dedicated
authentication and channel command modules.

=head1 SYNOPSIS

  my $dispatcher = Overnet::Program::IRC::Dispatcher->new(
    server => $server,
    parser => $parser,
  );
  $dispatcher->dispatch_line($client_id, $line);

=head1 VERSION

Version 0.001.

=head1 SUBROUTINES/METHODS

=head2 new

Creates a dispatcher for a server and parser.

=head2 server

Returns the weak server dependency used by selected command handlers.

=head2 parser

Returns the stateless IRC message parser.

=head2 dispatch_line

Parses and dispatches one line for a connected client.

=head1 DIAGNOSTICS

Unknown and registration-gated commands are translated into the same IRC
numerics as the server's existing command surface.

=head1 CONFIGURATION AND ENVIRONMENT

This module receives its server and parser dependencies during construction.

=head1 DEPENDENCIES

This module depends on Moo and the IRC command modules.

=head1 INCOMPATIBILITIES

No known incompatibilities.

=head1 BUGS AND LIMITATIONS

The dispatcher is private to the IRC server and intentionally relies on its
internal command service methods.

=head1 AUTHOR

Overnet project contributors.

=head1 LICENSE AND COPYRIGHT

Copyright the Overnet project contributors.

=cut
