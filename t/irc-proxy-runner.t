use strictures 2;

use File::Spec;
use FindBin;
use Test2::V0;

use lib grep { -d $_ } (
  File::Spec->catdir($FindBin::Bin, 'lib'),
  File::Spec->catdir($FindBin::Bin, '..', 'lib'),
  File::Spec->catdir($FindBin::Bin, '..', '..', 'core-perl', 'lib'),
);

use Overnet::Program::IRC::Script::Proxy;

subtest 'connection cleanup runs when a client disconnects normally' => sub {
  my @closed;
  my @read_handles;

  {
    no warnings qw(redefine once);
    local *Overnet::Program::IRC::Script::Proxy::_open_server_socket = sub {
      return 'server-socket';
    };
    local *Overnet::Program::IRC::Script::Proxy::_prepare_socket = sub {
      return 1;
    };
    local *Overnet::Program::IRC::Script::Proxy::_write_lines = sub {
      return 1;
    };
    local *Overnet::Program::IRC::Script::Proxy::_same_handle = sub {
      my ($handle, $client_socket) = @_;
      return $handle eq $client_socket ? 1 : 0;
    };
    local *Overnet::Program::IRC::Script::Proxy::_read_ready_lines = sub {
      my ($handle) = @_;
      push @read_handles, $handle;
      return 0;
    };
    local *Overnet::Program::IRC::Script::Proxy::_close_socket = sub {
      my ($socket, $description) = @_;
      push @closed, [$socket, $description];
      return 1;
    };
    local *IO::Select::new = sub {
      return bless {}, 't::irc_proxy_runner::FakeSelect';
    };

    Overnet::Program::IRC::Script::Proxy::_serve_connection({}, {}, 'client-socket');
  }

  is \@read_handles, ['client-socket'], 'the runner observed the client disconnect';
  is \@closed,
    [['server-socket', 'IRC upstream server socket'], ['client-socket', 'IRC proxy client socket'],],
    'both proxy sockets are closed on normal disconnect';
};

done_testing;

package t::irc_proxy_runner::FakeSelect;

sub can_read {
  return 'client-socket';
}

1;
