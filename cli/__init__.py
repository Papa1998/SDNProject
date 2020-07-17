"""Run Cisco IOS CLI commands and receive the output.

This module contains utility functions that run Cisco IOS CLI commands and provide
the output.

"""

__version__="1.2.1"

import re
import errors
import os
import urllib
import traceback
import sys
from collections import namedtuple, Iterable

import pnp

MAX_WAIT_TIME = None

class CLIError(Exception):
    """A base class for exceptions that are raised when a CLI cannot be run."""

class CLICommandError(CLIError):
    """A base class for exception that are raised when a single command cannot be run in IOS."""
    def __init__(self, command, message, *args):
        self.command = command
        self.message = '{}: There was a problem running the command: "{}"'.format(message, command)
        super(CLICommandError, self).__init__(self.message, *args)

class CLISyntaxError(CLICommandError):
    """Raised when there is a syntax error in a command."""
    def __init__(self, command, *args):
        self.message = 'SyntaxError'
        super(CLISyntaxError, self).__init__(command, self.message, *args)

class CLITimeoutError(CLICommandError):
    """Raised when a command takes too long to execute."""
    def __init__(self, command, output, *args):
        self.output = output
        self.message = 'TimeoutError'
        super(CLITimeoutError, self).__init__(command, self.message, *args)

class CLIConfigurationError(CLIError):
    """Raised when some commands in a bulk configuration fail.

    Contains a list of the commands, along with a list of the failures."""
    def __init__(self, commands, *args):
        self.commands = commands
        self.failed = [c for c in commands if not c.success]
        self.message = 'ConfigError: There was a problem with {} commands while configuring the device.'.format(len(self.failed))
        super(CLIConfigurationError, self).__init__(self.message, *args)


# validate a command
def valid(command):
    CONF_REGEX = '^(conf|confi|config|configu|configur|configure)$'
    commands = command.split(';')

    for cmd in commands:
        if re.match(CONF_REGEX, cmd.strip()): return False

    return True

def execute(command):
    """Execute Cisco IOS CLI exec-mode command and return the result.

    command_output = execute("show version")

    Args:
        command (str): The exec-mode command to run.

    Returns:
        str: The output of the command.

    Raises:
        CLISyntaxError: If there is a syntax error in the command.

    """

    command = command.strip('\n')

    if command == '':
        return ''

    if ";" in command or "\n" in command:
        raise CLICommandError(command, "You may not run multiple commands using execute().")

    if not valid(command):
        raise CLICommandError(command, "You have to specify the configuration mode")

    if MAX_WAIT_TIME == None:
        response = pnp.listener.cli_exec_request(command)
    else:
        response = pnp.listener.cli_exec_request(command, MAX_WAIT_TIME)

    if not response.success:
        if response.error_msg == "invalid cli command":
            raise CLISyntaxError(response.sent)
        else:
            raise CLICommandError(command, str(response))
    elif response.error_code == "TIMEOUT":
        raise CLITimeoutError(response.sent, response.text.strip('\n'))
    else:
        return response.text.strip('\n')


def executep(command):
    """Execute Cisco IOS CLI exec-mode command and print the result.

    executep("show version")

    Args:
        command (str): The exec-mode command to run.

    """

    try:
        text = execute(command)
        if len(text) > 0: print(text)
    except CLICommandError as cce:
        print(cce.message)
    except Exception as e:
        print(e)
        pnp.listener.log(pnp.PNP_LOG_LEVEL_ERROR)


class ConfigResult(namedtuple('ConfigResult', 'success command line output notes')):
    """Contains the result of a single line of configuration.

    success (bool): True if this line of configuration was configured successfully.
    command (str): The configuration command that was run.
    notes (str): In the event of an error, this string contains notes about what
        went wrong. It is not guaranteed to be the same across platforms.

    """

    def __str__(self):
        result = "SUCCESS" if self.success else "FAILURE"
        notes = " ({})".format(self.notes) if self.notes else ""
        return "Line {} {}: {}{}{}".format(self.line,  result, self.command, notes, self.output)


def configure(configuration):
    """Apply a configuration (set of Cisco IOS CLI config-mode commands) to the device
    and return a list of results.

    configuration = '''interface gigabitEthernet 0/0
                         no shutdown'''

    # push it through the Cisco IOS CLI.
    try:
        results = cli.configure(configuration)
        print "Success!"
    except CLIConfigurationError as e:
        print "Failed configurations:"
        for failure in e.failed:
            print failure

    Args:
        configuration (str or iterable): Configuration commands, separated by newlines.

    Returns:
        list(ConfigResult): A list of results, one for each line.

    Raises:
        CLISyntaxError: If there is a syntax error in the configuration.

    """

    if len(configuration) == 0:
        return []

    if not isinstance(configuration, basestring):
        configuration = "\n".join(configuration)

    if isinstance(configuration, unicode):
        configuration = configuration.encode('utf-8')

    responses = pnp.listener.cli_config_request(configuration)
    results = [ConfigResult(r.success, r.cli_string, int(r.line_number), r.text, r.error_code) for r in responses]

    if not all([r.success for r in results]):
        raise CLIConfigurationError(results)

    return results


def configurep(configuration):
    """Apply a configuration (set of Cisco IOS CLI config-mode commands) to the device
    and prints the result.

    configuration = '''interface gigabitEthernet 0/0
                         no shutdown'''

    # push it through the Cisco IOS CLI.
    configurep(configuration)

    Args:
        configuration (str or iterable): Configuration commands, separated by newlines.

    """

    try:
        results = configure(configuration)
        for r in results:
            print(r)
    except CLIConfigurationError as cce:
        print(cce.message)
        for c in cce.commands:
            print(c)
    except Exception as e:
        print(e)
        pnp.listener.log(pnp.PNP_LOG_LEVEL_ERROR)


_SUPERFLUOUS_CONFIG_LINE = "\nEnter configuration commands, one per line.  End with CNTL/Z.\n"


def cli(command):
    """Execute Cisco IOS CLI command(s) and return the result.

    A single command or a delimited batch of commands may be run. The
    delimiter is a space and a semicolon, " ;". Configuration commands must be
    in fully qualified form.

    output = cli("show version")
    output = cli("show version ; show ip interface brief")
    output = cli("configure terminal ; interface gigabitEthernet 0/0 ; no shutdown")

    Args:
        command (str): The exec or config CLI command(s) to be run.

    Returns:
        string: CLI output for show commands and an empty string for
            configuration commands.

    Raises:
        errors.cli_syntax_error: if the command is not valid.
        errors.cli_exec_error: if the execution of command is not successful.

    """

    command = command.strip()

    if command == '':
        return ''

    if not valid(command):
        raise errors.cli_exec_error("You have to specify the configuration mode")

    response = pnp.listener.cli_exec_request(command)

    if not response.success:
        if response.error_msg == "invalid cli command":
            raise errors.cli_syntax_error(response.sent)
        else:
            raise errors.cli_exec_error(str(response))
    else:
        text = response.text.replace(_SUPERFLUOUS_CONFIG_LINE, "")
        return text


def clip(command):
    """Execute Cisco IOS CLI command(s) and print the result.

    A single command or a delimited batch of commands may be run. The
    delimiter is a space and a semicolon, " ;". Configuration commands must be
    in fully qualified form.

    clip("show version")
    clip("show version ; show ip interface brief")
    clip("configure terminal ; interface gigabitEthernet 0/0 ; no shutdown")

    Args:
        command (str): The exec or config CLI command(s) to be run.

    """

    try:
        text = cli(command)
        if len(text) > 0: print(text)
    except errors.cli_exec_error as cee:
        print(cee)
    except errors.cli_syntax_error as cse:
        print(cse)
    except Exception as e:
        print(e)
        pnp.listener.log(pnp.PNP_LOG_LEVEL_ERROR)


