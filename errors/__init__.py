"""This module is deprecated, supported for backward compatibility only."""

class cli_syntax_error(Exception):
    """This exception is deprecated, supported for backwards compatibilty only."""
    def __init__(self, command):
        self.value = "Syntax error while parsing '{}'.Cmd exec error.".format(command)

    def __str__(self):
        return str(self.value)

class cli_exec_error(Exception):
    """This exception is deprecated, supported for backwards compatibilty only."""
    pass
