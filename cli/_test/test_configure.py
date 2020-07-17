import unittest
from copy import deepcopy

import cli
import errors

from ._test_config import TestConfig, SIMPLE_CONFIG_COMMANDS, NESTED_CONFIG_COMMANDS, GIBBERISH_CONFIG_COMMANDS

PRINT_TEST_CONFIGS = False

CHAINED_SIMPLE_CONFIG_COMMANDS = TestConfig.flatten(SIMPLE_CONFIG_COMMANDS)
CHAINED_NESTED_CONFIG_COMMANDS = TestConfig.flatten(NESTED_CONFIG_COMMANDS)
CHAINED_GIBBERISH_CONFIG_COMMANDS = TestConfig.flatten(GIBBERISH_CONFIG_COMMANDS)
LARGE_SET_CONFIG_COMMANDS = TestConfig.flatten([CHAINED_SIMPLE_CONFIG_COMMANDS, CHAINED_NESTED_CONFIG_COMMANDS])

def load_tests(loader, testsuites, pattern):
    suite = unittest.TestSuite()
    for ts in testsuites:
        for testcase in ts:
            testcase.use_string = False
            suite.addTest(testcase)

            tc_copy = deepcopy(testcase)
            tc_copy.use_string = True
            suite.addTest(tc_copy)
    return suite


class TestCase(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        self.use_string = False
        super(TestCase, self).__init__(*args, **kwargs)

    def id(self):
        qualifier = ".String" if self.use_string else ".List"
        return unittest.TestCase.id(self) + qualifier

    def __str__(self):
        qualifier = " [String]" if self.use_string else " [List]"
        return unittest.TestCase.__str__(self) + qualifier

    def tearDown(self):
        cli.configure(self.test_config.no_commands)


class CLIConfigureTestCase():
    def runTestConfigs(self, test_config):
        self.test_config = test_config
        self.commands = [r.command for r in test_config.results]

        if PRINT_TEST_CONFIGS:
            print()
            print("\n".join(self.commands))

        if self.use_string:
            commands_to_run = "\n".join(self.commands)
        else:
            commands_to_run = self.commands

        try:
            self.results = cli.configure(commands_to_run)
            if any([not r.success for r in self.test_config.results]):
                self.fail("cli.configure should raise an exception if there are any problems with the result.")
        except cli.CLIConfigurationError as e:
            self.results = e.commands

    def testResultIsList(self):
        self.assertIs(type(self.results), list,
                "The result of cli.configure() must be a list.")

    def testListElementsAreConfigResult(self):
        for r in self.results:
            self.assertIs(type(r), cli.ConfigResult,
                    "Each element of the resultant list from cli.configure() must be of type cli.ConfigResult.")

    def testResultCommandsPresent(self):
        self.assertListEqual( [r.command for r in self.results], self.commands,
                "The results must all expose the command used, in the same order as they were passed.")

    def testResultLineNumbersMatch(self):
        actual = [(r.line, r.command) for r in self.results]
        expected = zip([n+1 for n in range(len(self.commands))], self.commands)
        self.assertListEqual(actual, expected,
                "The resulting line numbers must match up with the list of commands.")

    def testResultsHaveCorrectSuccessStatus(self):
        for i, r in enumerate(self.results):
            self.assertEqual(r.success, self.test_config.results[i].success)

    def testResultsHaveCorrectOutput(self):
        for r in self.results:
            if not r.success:
                self.assertGreater(len(r.output), 0)

    def testConfigLinesInRunningConfig(self):
        config = cli.execute('show running-config')
        for line in self.test_config.config_lines:
            self.assertIn(line, config)


# Positive Cases

class CLIConfigureOneLineTestCase(TestCase, CLIConfigureTestCase):
    def setUp(self):
        self.runTestConfigs(SIMPLE_CONFIG_COMMANDS[0])


class CLIConfigureMultiLineTestCase(TestCase, CLIConfigureTestCase):
    def setUp(self):
        self.runTestConfigs(CHAINED_SIMPLE_CONFIG_COMMANDS)


class CLIConfigureNestedTestCase(TestCase, CLIConfigureTestCase):
    def setUp(self):
        self.runTestConfigs(NESTED_CONFIG_COMMANDS[0])


class CLIConfigureMultiNestedTestCase(TestCase, CLIConfigureTestCase):
    def setUp(self):
        self.runTestConfigs(CHAINED_NESTED_CONFIG_COMMANDS)

class CLIConfigureLargeTestCase(TestCase, CLIConfigureTestCase):
    def setUp(self):
        self.runTestConfigs(LARGE_SET_CONFIG_COMMANDS)


# Negative Cases

class CLIConfigureGibberishTestCase(TestCase, CLIConfigureTestCase):
    def setUp(self):
        self.runTestConfigs(GIBBERISH_CONFIG_COMMANDS[0])


class CLIConfigureMultiGibberishTestCase(TestCase, CLIConfigureTestCase):
    def setUp(self):
        self.runTestConfigs(TestConfig.flatten(GIBBERISH_CONFIG_COMMANDS))


class CLIConfigureGibberishBeforeGoodCommandsTestCase(TestCase, CLIConfigureTestCase):
    def setUp(self):
        self.runTestConfigs(TestConfig.flatten([CHAINED_GIBBERISH_CONFIG_COMMANDS, CHAINED_NESTED_CONFIG_COMMANDS]))


class CLIConfigureGibberishAfterGoodCommandsTestCase(TestCase, CLIConfigureTestCase):
    def setUp(self):
        self.runTestConfigs(TestConfig.flatten([CHAINED_NESTED_CONFIG_COMMANDS, CHAINED_GIBBERISH_CONFIG_COMMANDS]))


# Boundary Cases

class CLIConfigureEmptyTestCase(TestCase, CLIConfigureTestCase):
    def setUp(self):
        self.runTestConfigs(TestConfig([], [], []))
