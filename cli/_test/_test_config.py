from collections import namedtuple
from itertools import chain

from cli import ConfigResult
from cli import execute

import re


# execute defaults

SHOW_COMMAND = "show banner login"
SHOW_COMMAND_CONFIG = "banner login .python test banner."
SHOW_COMMAND_OUTPUT = "python test banner"
TIMEOUT_COMMAND = 'show tech-support'


# configure defaults

class TestConfig(namedtuple('TestConfig', 'results no_commands config_lines')):

    @classmethod
    def flatten(cls, test_configs):
        results = list(chain.from_iterable([tc.results for tc in test_configs]))
        no_commands = list(chain.from_iterable([tc.no_commands for tc in test_configs]))
        config_lines = list(chain.from_iterable([tc.config_lines for tc in test_configs]))

        return cls(results, no_commands, config_lines)

"""
results: a list of ConfigResults objects, including the command and expected success of the command.
no_commands: a list of commands which reverse the configuration effect.
config_lines: a list of lines which will be present in the config after 
    running the above commands.
"""

SIMPLE_CONFIG_COMMANDS = [
        TestConfig(
            [ConfigResult(True, 'banner login .python login test banner.', 0, '', '')],
            ['no banner login'],
            ['banner login ^Cpython login test banner^C']),
        TestConfig(
            [ConfigResult(True, 'banner incoming .python incoming test banner.', 0, '', '')],
            ['no banner incoming'],
            ['banner incoming ^Cpython incoming test banner^C']),
        TestConfig(
            [ConfigResult(True, 'banner motd .python motd test banner.', 0, '', '')],
            ['no banner motd'],
            ['banner motd ^Cpython motd test banner^C']),
    ]

interfaces = execute('show ip interface')
interfaces = list(set(re.findall('(?:FortyGigabitEthernet|TenGigabitEthernet|GigabitEthernet|Loopback)[0-9]*/?[0-9]*/?[0-9]*', interfaces)))
NESTED_CONFIG_COMMANDS = []

for i in range(len(interfaces)):
    NESTED_CONFIG_COMMANDS.append(        
        TestConfig(
            [ 
                ConfigResult(True, "interface " + interfaces[i], 0, '', ''), 
                ConfigResult(True, " description python test " + str(i), 0, '', ''),
            ],
            [ "interface " + interfaces[i], " no description" ],
            [ "interface " + interfaces[i], " description python test " + str(i) ])
    )

GIBBERISH_CONFIG_COMMANDS = [
        TestConfig(
            [ConfigResult(False, "show gibberish", 0, '', '')],
            [],
            []),
        TestConfig(
            [ConfigResult(False, "show more gibberish", 0, '', '')],
            [],
            []),
    ]
