''' Communicate with IOS over PnP

This module contains utility functions that provide connection to PnP listener
on the target system, which allows to execute IOS CLI commands and provide 
the output.

'''

__version__ = '1.2.1'

from ._pnp import PnPError
from ._pnp import PnPInvalidTokenError
from ._pnp import PnPSocketError
from ._pnp import PnPParseError
from ._pnp import listener
from ._pnp import get_session_id
from ._pnp import PNP_LOG_LEVEL_DEBUG
from ._pnp import PNP_LOG_LEVEL_ERROR
