import unittest
from timeit import timeit
import json

import cli
import errors

from ._test_config import (
    SHOW_COMMAND, 
    SHOW_COMMAND_CONFIG, 
    SHOW_COMMAND_OUTPUT, 
    TIMEOUT_COMMAND,
)

GIBBERISH_COMMAND = "show gibberish"

# Positive cases

class CLIExecuteShowCommandTestCase(unittest.TestCase):
    def setUp(self):
        cli.configure(SHOW_COMMAND_CONFIG)
        self.r = cli.execute(SHOW_COMMAND)
        self.unicode_r = cli.execute(unicode(SHOW_COMMAND))

    def testContainsCorrectOutput(self):
        self.assertEqual(SHOW_COMMAND_OUTPUT, self.r, 
                "The result does not contain the correct output. {}\n{}".format(repr(self.r), repr(SHOW_COMMAND_OUTPUT)))

    def testResultContainsNoNewlinesBefore(self):
        self.assertFalse(self.r.startswith('\n'), "Results should not include and empty line at the beginning, such as that which the parser may output to separate the output from the preceding prompt.")
        
    def testResultContainsNoNewlinesAfter(self):
        self.assertFalse(self.r.endswith('\n'), "Results should not include an empty line at the end, such as that which the parser may output to separate the output from the following prompt.")

    def testCommandContainsNewlineBefore(self):
        r = cli.execute('\n' + SHOW_COMMAND)

    def testCommandContainsNewlineAfter(self):
        r = cli.execute(SHOW_COMMAND + '\n')

    def testUnicode(self):
        self.assertEqual(self.r, self.unicode_r, "Results should be the same for unicode or utf-8 input")

    def tearDown(self):
        pass


# Negative Cases

class CLIExecuteSyntaxErrorTestCase(unittest.TestCase):
    def testIncorrectSyntax(self):
        self.assertRaises(cli.CLISyntaxError, cli.execute, GIBBERISH_COMMAND)

class CLIExecuteTwoCommandsTestCase(unittest.TestCase):
    def testSemicolonSeparatedCommands(self):
        self.assertRaises(cli.CLICommandError, cli.execute, "{show_command} ; {show_command}".format(show_command=SHOW_COMMAND))

    def testNewlineSeparatedCommands(self):
        self.assertRaises(cli.CLICommandError, cli.execute, "{show_command}\n{show_command}".format(show_command=SHOW_COMMAND))

class CLIExecuteTimeoutErrorTestCase(unittest.TestCase):
    def setUp(self):
        self.old_max_wait_time = cli.MAX_WAIT_TIME
        cli.MAX_WAIT_TIME = 1

    def testTimeoutError(self):
        self.assertRaises(cli.CLITimeoutError, cli.execute, TIMEOUT_COMMAND)

    def testTimeoutErrorContainsOutput(self):
        try:
            response = cli.execute(TIMEOUT_COMMAND)
            self.fail("Command did not timeout, cannot check the timeout error.")
        except cli.CLITimeoutError as e:
            self.assertIsInstance(e.output, basestring)
            self.assertGreater(len(e.output), 0)
        
    def tearDown(self):
        cli.MAX_WAIT_TIME = self.old_max_wait_time

# TODO: Test Interactive commands.

# Boundary Cases

class CLIExecuteEmptyCommandTestCase(unittest.TestCase):
    def testEmptyCommand(self):
        t = timeit(stmt="cli.execute('')", setup="import cli", number=1)
        self.assertLess(t, 5.0, "Passing an empty command causes the program to hang too long.")


