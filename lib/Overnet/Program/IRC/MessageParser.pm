package Overnet::Program::IRC::MessageParser;

use strictures 2;
use Moo;

our $VERSION = '0.001';

no Moo;

sub parse {
  my ($self, $line) = @_;
  my %message = (
    raw_line => $line,
    params   => [],
  );

  if ($line =~ s/\A\@(\S+)\s+//mxs) {
    $message{tags} = $self->parse_tags($1);
  }

  if ($line =~ s/\A:([^ ]+)\s+//mxs) {
    my $prefix = $1;
    $message{prefix} = $prefix;
    if ($prefix =~ /\A([^!@]+)!([^@]+)\@(.+)\z/mxs) {
      @message{qw(prefix_nick prefix_user prefix_host)} = ($1, $2, $3);
    } else {
      $message{prefix_nick} = $prefix;
    }
  }

  my ($command, $rest) = split /\ /mxs, $line, 2;
  if (!(defined $command && length $command)) {
    return;
  }

  $message{command} = uc($command);
  if (!(defined $rest)) {
    $rest = q{};
  }

  while (length $rest) {
    $rest =~ s/\A\ +//mxs;
    if (!(length $rest)) {
      last;
    }

    if ($rest =~ s/\A:(.*)\z//mxs) {
      push @{$message{params}}, $1;
      last;
    }

    if ($rest =~ s/\A([^ ]+)//mxs) {
      push @{$message{params}}, $1;
      next;
    }

    last;
  }

  return \%message;
}

sub parse_tags {
  my ($self, $raw) = @_;
  my %tags;
  for my $entry (split /;/mxs, $raw) {
    my ($name, $value) = split /=/mxs, $entry, 2;
    if (!(defined $name && length $name)) {
      next;
    }

    $tags{$name} = defined $value ? $value : q{};
  }
  return \%tags;
}

1;

=head1 NAME

Overnet::Program::IRC::MessageParser - Parse IRC wire messages

=head1 DESCRIPTION

This internal collaborator parses one IRC protocol line into normalized tags,
prefix fields, an uppercase command, and ordered parameters. It owns no server
or connection state.

=head1 SYNOPSIS

  my $parser  = Overnet::Program::IRC::MessageParser->new;
  my $message = $parser->parse('PRIVMSG #overnet :hello');

=head1 VERSION

Version 0.001.

=head1 SUBROUTINES/METHODS

=head2 new

Creates a parser.

=head2 parse

Parses one IRC protocol line, returning a message hash or C<undef> when no
command is present.

=head2 parse_tags

Parses an IRCv3 message-tag field.

=head1 DIAGNOSTICS

This parser reports malformed commandless lines by returning C<undef>.

=head1 CONFIGURATION AND ENVIRONMENT

This module requires no configuration.

=head1 DEPENDENCIES

This module depends on Moo.

=head1 INCOMPATIBILITIES

No known incompatibilities.

=head1 BUGS AND LIMITATIONS

IRCv3 tag escape decoding is outside the server's currently supported wire
surface.

=head1 AUTHOR

Overnet project contributors.

=head1 LICENSE AND COPYRIGHT

Copyright the Overnet project contributors.

=cut
