import base64
import time
import abc
import xml.etree.ElementTree as ElementTree
import os
import re
import urllib2

from . import _urllib2_uds

_CLI_EXEC_XPATH = ".//{urn:cisco:pnp:cli-exec}"
_CLI_CONFIG_XPATH = ".//{urn:cisco:pnp:cli-config}"
_EEM_EXEC_XPATH = ".//{urn:cisco:pnp:eem-proxy}"

DEBUG = False
LOGFILE = None

PNP_LOG_LEVEL_DEBUG = 1
PNP_LOG_LEVEL_ERROR = 2

DEFAULT_MAX_WAIT_TIME = 3600
MAX_WAIT_TIME = DEFAULT_MAX_WAIT_TIME

_PNP_INFO_KEYS = [
    'scheme',
    'host',
    'pnp_listener_path',
    'udi',
    'user', 'password',
    'http_user', 'http_password',
    'token',
    'token_file',
    'max_wait',
    'debug',
    'logfile',
    'session_id'
]

_PNP_INFO_ENV_VAR_PREFIX = "SHELL_SESSION_"

_PNP_SOCKET_PATH = '/cisco/nginx_shared/pnp_python.sock'
_PNP_SOCKET_ERR_MSG = 'Socket {} not present. Make sure to enable http server'.format(_PNP_SOCKET_PATH)

def _pnp_sock_exists():
    if _scheme == 'unixhttp':
        return os.path.exists(_PNP_SOCKET_PATH)
    return True

def _sanitize(s):
    ''' Sanitize string by applying backspace characters if any'''
    while True:
        t = re.sub('.\b', '', s, count=1)
        if len(s) == len(t):
            return re.sub('\b+', '', t)
        s = t

def _log_to_stdout(message):
    """Log to stdout if DEBUG is on"""
    if DEBUG:
        print("DEBUG ----------------------------------------")
        print(message)
    
def _log_to_file(message):
    """Log to a file if LOGFILE is defined"""
    if LOGFILE is not None: 
        with open(LOGFILE, 'a') as logfile:
            logfile.write("LOG ------------------------------------------\n")
            logfile.write(message + "\n")    
                              
def _pnp_log(message, level=PNP_LOG_LEVEL_DEBUG):
    """Log based on log levels"""
    
    _log_to_stdout(message)
    
    if level == PNP_LOG_LEVEL_ERROR or DEBUG:
        _log_to_file(message)
    
def _correlator():
    return "python_cli_api@" + str(time.time())

class PnPError(Exception):
    """A base class for exceptions that are raised due to a PnP fault."""

class PnPInvalidTokenError(PnPError):
    """Raised if the caller is not authorized to execute a command."""
    def __init__(self, message, *args):
        self.message = 'TokenError: {}'.format(message)
        super(PnPInvalidTokenError, self).__init__(self.message, *args)

class PnPSocketError(PnPError):
    """Raised if pnp socket error happens."""
    def __init__(self, message, *args):
        self.message = 'SocketError: {}'.format(message)
        super(PnPSocketError, self).__init__(self.message, *args)

class PnPParseError(PnPError):
    """Raised if pnp response is not parsable."""
    def __init__(self, message, *args):
        self.message = 'ParseError: Response is not xml parsable. {}'.format(message)
        super(PnPParseError, self).__init__(self.message, *args)
                
class ExecResponse(object):
    """A class that represents a PnP Exec CLI Service Response.

    An instance of this class is returned by the PnPListener.run_exec method.
    If the response is successful, it exposes the text output from the IOS
    parser. If the response is unsuccessful, it exposes the details of the
    error.

    Attributes:
        self.success (bool): True if the request was successful.
        self.sent (str): The original command that was run.
        self.text (str): The text output of the IOS Parser.
        error_severity (str): The severity of the error. Should be None if
            success is True.
        error_code (str): The error code. Should be None if success is True.
        error_msg (str): The error message. Should be None if success is True.

    r = listener.run_exec(command)
    if not r.success:
        print r.error_msg
        print r.error_severity
        print r.error_msg
    else:
        print r.text
    """


    @classmethod
    def from_xml_element(cls, exec_response):
        """Initialize a new ExecResponse object.

        response_element = root.find('.//{urn:cisco:pnp:cli-exec}response')
        response = ExecResponse.from_xml_element(response_element)

        Args:
            exec_response (str): An instance of xml.etree.ElementTree.Element
                that the "response" element of a PnP CLI Exec Service response.
        Returns: ExecResponse object
        """

        if exec_response is None:
            raise ValueError("exec_response must not be None")

        success = bool(exec_response.attrib['success'] == '1')
        match = exec_response.find(_CLI_EXEC_XPATH + "sent")
        sent = match.text if match is not None else None

        match = exec_response.find(_CLI_EXEC_XPATH + "text")
        text = match.text if match is not None else None

        try:
            error_severity = exec_response.find(_CLI_EXEC_XPATH + 'errorSeverity').text
            error_code = exec_response.find(_CLI_EXEC_XPATH + 'errorCode').text
            error_msg = exec_response.find(_CLI_EXEC_XPATH + 'errorMessage').text
        except:
            error_severity = None
            error_code = None
            error_msg = None

        return cls(success, sent, text, error_severity, error_code, error_msg)


    @classmethod
    def eem_from_xml_element(cls, exec_response):
        """Initialize a new ExecResponse object.

        response_element = root.find('.//{urn:cisco:pnp:eem-proxy')
        response = ExecResponse.eem_from_xml_element(response_element)

        Args:
            exec_response (str): An instance of xml.etree.ElementTree.Element
                that the "response" element of a PnP EEM response.
        Returns: ExecResponse object
        """

        if exec_response is None:
            raise ValueError("exec_response must not be None")

        success = bool(exec_response.attrib['success'] == '1')
        match = exec_response.find(_EEM_EXEC_XPATH + "EEM-Response")
        data = match.text if match is not None else None

        try:
            error_severity = exec_response.find(_EEM_EXEC_XPATH + 'errorSeverity').text
            error_code = exec_response.find(_EEM_EXEC_XPATH + 'errorCode').text
            error_msg = exec_response.find(_EEM_EXEC_XPATH + 'errorMessage').text
        except:
            error_severity = None
            error_code = None
            error_msg = None

        '''return cls(success, "", data, error_severity, error_code, error_msg) '''
        return success, "", data, error_severity, error_code, error_msg


    def __init__(self, success, sent, text, 
            error_severity, error_code, error_msg):
        """Initializes an ExecResponse directly.

        Do not initialize this class directly. Instead, use 
        ExecResponse.from_xml_element()

        Args:
            success (bool): True if the request was successful.
            sent (str): The original command that was run.
            text (str): The text output of the IOS Parser.
            error_severity (str): The severity of the error. Should be None if
                success is True.
            error_code (str): The error code. Should be None if success is 
                True.
            error_msg (str): The error message. Should be None if success is 
                True.
        """
        self.success = success
        self.sent = sent
        self.text = text
        self.error_severity = error_severity
        self.error_code = error_code
        self.error_msg = error_msg

    def __repr__(self):
        if self.success:
            return self.text.strip()
        else:
            return "{}: {} - {}".format(
                    self.error_severity,
                    self.error_code,
                    self.error_msg
                )


class ConfigResultEntry(object):

    @classmethod
    def from_xml_element(cls, result_entry):
        line_number = result_entry.attrib.get('lineNumber', '')

        cli_string = result_entry.attrib.get('cliString', '')

        success_element = result_entry.find(_CLI_CONFIG_XPATH + 'success')
        if success_element is not None:
            success = True
            change = success_element.attrib['change']
            mode = success_element.attrib['mode']
            error_code = None
            error_type = None
        else:
            success = False
            change = None
            mode = None
            failure_element = result_entry.find(_CLI_CONFIG_XPATH + 'failure')
            error_code = failure_element.attrib['errorCode']
            error_type = failure_element.attrib['errorType']

        text_element = result_entry.find(_CLI_CONFIG_XPATH + 'text')
        text = text_element.text if text_element is not None else ""

        return cls(success, change, mode, error_code, error_type, line_number, cli_string, text)

    def __init__(self, success, change, mode, error_code, error_type, line_number, cli_string, text):
        self.success = success
        self.change = change
        self.mode = mode
        self.error_code = error_code
        self.error_type = error_type
        self.line_number = line_number
        self.cli_string = cli_string
        self.text = text


    def __repr__(self):
        if self.success:
            status = "SUCCESS {} {}".format(self.mode, self.change)
        else:
            status = "{} {}\n{}".format( self.error_type, self.error_code, self.text)

        return "{:3}: {} - {}".format( self.line_number, self.cli_string, status) 


class PnPCredential(object):
    __metaclass__ = abc.ABCMeta
    def __init__(self, basic_auth=None):
        if not basic_auth:
            self.use_basic_auth = False
        elif isinstance(basic_auth, tuple):
            self.use_basic_auth = True
            self.http_username = basic_auth[0]
            self.http_password = basic_auth[1]
        else:
            raise ValueError("When using a session ID for PnP authentication "
                    "with HTTP basic authentication, basic_auth must be a "
                    "tuple(user, pass). Got {}".format(type(basic_auth)))

    @abc.abstractmethod
    def xml_format(self):
        """Return the credential formatted as an xml attribute."""
        return

class PnPUsernameCredential(PnPCredential):

    PNP_CRED_USERNAME_FMT = 'usr="{username}" pwd="{password}"'

    def __init__(self, username, password, use_basic_auth=True):
        self.username = username
        self.password = password
        if use_basic_auth:
            super(PnPUsernameCredential, self).__init__(basic_auth=(username, password))


    def xml_format(self):
        return self.PNP_CRED_USERNAME_FMT.format(
                username=self.username,
                password=self.password
            )

    def __str__(self):
        result = "{}, {}".format(self.username, self.password)
        if self.use_basic_auth:
            result += ", HTTP Basic: {}, {}".format(self.http_username, self.http_password)
        return result

class PnPSessionIDCredential(PnPCredential):
    
    PNP_CRED_SESSION_ID_FMT = 'sid="{sid}"'

    def __init__(self, sid, basic_auth=None):
        self.sid = sid
        super(PnPSessionIDCredential, self).__init__(basic_auth=basic_auth)
        
    def xml_format(self):
        return self.PNP_CRED_SESSION_ID_FMT.format(
                sid=self.sid
            )
    def __str__(self):
        result = "{}".format(self.sid)
        if self.use_basic_auth:
            result += ", HTTP Basic: {}, {}".format(self.http_username, self.http_password)
        return result

class PnPSessionIDFileCredential(PnPSessionIDCredential):

    def __init__(self, sid_file, basic_auth=None):
        self.sid_file = sid_file
        with open(sid_file) as f:
            sid = f.read()
        super(PnPSessionIDFileCredential, self).__init__(sid, basic_auth=basic_auth)
    
    def __getattribute__(self, name):
        if name == 'sid':
            with open(self.sid_file) as f:
                tmp = f.read()
                self.sid = tmp
            return tmp
        return super(PnPSessionIDFileCredential, self).__getattribute__(name)
            
class PnPListener(object):
    """A class that represents a remote PnP listener.

    Use this class to create objects that are cabable of sending and receiving
    PnP requests and responses without having to touch xml.

    listener = PnPListener(
            'http://5.1.33.101/application_name',
            'PID:WS-C3850-24T,VID:V03,SN:FOC1821X180',
            PnPCredential.from_username('user', 'password123')
        )

    response = listener.run_exec('show version')
    if response.success:
        print response.text
    """

    PNP_FMT = """\
    <?xml version="1.0" encoding="UTF-8"?>
     <pnp xmlns="urn:cisco:pnp" version="1.0" {credentials} udi="{udi}">
    {xml}
     </pnp>"""
    PNP_EXEC_CLI_FMT = """\
      <request correlator="{correlator}" xmlns="urn:cisco:pnp:cli-exec">
        <execCLI maxWait="PT{max_wait}S" xsd="false">
            <cmd>{command}</cmd>
        </execCLI>
      </request>"""
    PNP_CONFIG_CLI_FMT = """\
        <request correlator="{correlator}" xmlns="urn:cisco:pnp:cli-config">
          <configApply details="all"> 
            <config-data> 
              <cli-config-data-block>{command}</cli-config-data-block> 
            </config-data> 
          </configApply>
        </request>"""
    PNP_EXEC_EEM_FMT = """\
      <request correlator="{correlator}" xmlns="urn:cisco:pnp:eem-proxy">
        <eemProxy jobID="{jobid}">
        <EEM-Data-Format>1</EEM-Data-Format>
        <EEM-Data-Block>{command}</EEM-Data-Block>
        </eemProxy>
      </request>"""
    
    DEFAULT_REQUEST = 'NOT AVAILABLE'
    DEFAULT_RESPONSE = 'NOT AVAILABLE'

    def __init__(self, url, udi, cred):
        """Initialize a new PnPListener object.

        listener = PnPListener(
                'http://5.1.33.101/application_name',
                'PID:WS-C3850-24T,VID:V03,SN:FOC1821X180',
                PnPCredential.from_username('user', 'password123')
            )

        Args:
            url (str): The URL, including the protocol, where the PnP Listener
                is listening.
            udi (str): The UDI value. Run `show pnp summary | i Device UDI` on
                the IOS prompt to see the Device UDI.
            cred (PnPCredential): 
        Returns:
            ExecResponse: An object that contains information parsed out of the
                xml response
        """
            
        self.url = url
        self.udi = udi
        self.cred = cred
        self.req = PnPListener.DEFAULT_REQUEST
        self.res = PnPListener.DEFAULT_RESPONSE
    
    def _reset(self):
        self.req = PnPListener.DEFAULT_REQUEST
        self.res = PnPListener.DEFAULT_RESPONSE
        
    def _request(self, xml):

        request_xml = PnPListener.PNP_FMT.format(
                credentials=self.cred.xml_format(),
                udi=self.udi,
                xml=xml)
        _pnp_log("PnP exec request to {} with credentials {}".format(
                    self.url, self.cred))
        _pnp_log("PnP request:\n" + request_xml)
        
        self.req = request_xml
        request = urllib2.Request(self.url, request_xml)

        if self.cred.use_basic_auth:
            base64string = base64.b64encode('{}:{}'.format(
                self.cred.http_username, self.cred.http_password))
            request.add_header("Authorization", "Basic {}".format(base64string))   

        result = urllib2.urlopen(request)
        response_xml = _sanitize(result.read())
        _pnp_log("PnP response:\n" + response_xml)
        
        self.res = response_xml

        if isinstance(self.cred, PnPSessionIDCredential):

            root = ElementTree.fromstring(response_xml)
            
            if 'sid' not in root.attrib:
                log(PNP_LOG_LEVEL_ERROR)
                msg = "Token attribute was not present in the PnP response."
                _pnp_log(msg, PNP_LOG_LEVEL_ERROR)
                raise PnPInvalidTokenError(msg)

            new_sid = root.attrib['sid']
            if new_sid == self.cred.sid:
                _pnp_log("Response token matches request token.")
            else:
                _pnp_log("Response token does not match request token.")

            self.cred.sid = new_sid
            _pnp_log("New SID: " + self.cred.sid)

        return response_xml

    def log(self, level):
        _pnp_log('PnP REQUEST:\n{}'.format(self.req), level)
        _pnp_log('PnP RESPONSE:\n{}'.format(self.res), level)
        
    def cli_exec_request(self, command, max_wait=MAX_WAIT_TIME):
        """Make a request to the PnP Exec service.

        response = listener.run_exec('show version')

        Args:
            command (str): The command to be run.
        Keyword Args:
            max_wait (int): The time PnP should wait for the command to 
                execute, in seconds.
        Returns:
            ExecResponse: An object that contains information parsed out of the
                xml response
        """
        
        self._reset()
        
        if not _pnp_sock_exists():
            _pnp_log(_PNP_SOCKET_ERR_MSG, PNP_LOG_LEVEL_ERROR)
            raise PnPSocketError(_PNP_SOCKET_ERR_MSG)
            
        xml = PnPListener.PNP_EXEC_CLI_FMT.format(correlator=_correlator(), max_wait=str(max_wait), command=command)

        # parse the returned xml
        try:
            response = self._request(xml)
            root = ElementTree.fromstring(response)
        except ElementTree.ParseError as perr:
            log(PNP_LOG_LEVEL_ERROR)
            msg = str(perr)
            _pnp_log(msg, PNP_LOG_LEVEL_ERROR)
            raise PnPParseError(msg)

        response_element = root.find(_CLI_EXEC_XPATH + 'response')

        exec_response = ExecResponse.from_xml_element(response_element)

        return exec_response


    def eem_exec_request(self, command):
        """Make a request to the PnP EEM service.

        response = listener.run_exec('show version')

        Args:
            command (str): Data that needs to be sent to EEM handler.
        Returns:
            ExecResponse: An object that contains information parsed out of the
                xml response
        """
        
        self._reset()
        
        if not _pnp_sock_exists():
            _pnp_log(_PNP_SOCKET_ERR_MSG, PNP_LOG_LEVEL_ERROR)
            raise PnPSocketError(_PNP_SOCKET_ERR_MSG)
            
        xml = PnPListener.PNP_EXEC_EEM_FMT.format(correlator=_correlator(), jobid=get_session_id() , command=command)

        # parse the returned xml
        try:
            response = self._request(xml)
            root = ElementTree.fromstring(response)
        except ElementTree.ParseError as perr:
            log(PNP_LOG_LEVEL_ERROR)
            msg = str(perr)
            _pnp_log(msg, PNP_LOG_LEVEL_ERROR)
            raise PnPParseError(msg)

        response_element = root.find(_EEM_EXEC_XPATH + 'response')

        exec_response = ExecResponse.eem_from_xml_element(response_element)

        return exec_response


    def cli_config_request(self, command):
        """Make a request to the PnP Config service.

        command = '''\
                interface gigabitEthernet 0/0
                no shutdown'''
        success, response = listener.run_config(command)

        Args:
            command (str): The config command to be run.
        Returns:
            Tuple(
                Bool: True if the operation was successful, false otherwise.
                List[ConfigResultEntry]: A list of objects that contain
                    information parsed out of the xml response.
            )
        """
        
        self._reset()
        
        if not _pnp_sock_exists():
            _pnp_log(_PNP_SOCKET_ERR_MSG, PNP_LOG_LEVEL_ERROR)
            raise PnPSocketError(_PNP_SOCKET_ERR_MSG)
            
        xml = PnPListener.PNP_CONFIG_CLI_FMT.format(correlator=_correlator(), command=command)

        # parse the returned xml
        try:
            response = self._request(xml)
            root = ElementTree.fromstring(response)
        except ElementTree.ParseError as perr:
            log(PNP_LOG_LEVEL_ERROR)
            msg = str(perr)
            _pnp_log(msg, PNP_LOG_LEVEL_ERROR)
            raise PnPParseError(msg)

        response_element = root.find(_CLI_CONFIG_XPATH + 'response')
        success = bool(response_element.attrib['success'] == '1')
        if success:
            result_entries = root.findall(_CLI_CONFIG_XPATH + 'resultEntry')
            result_entries = [ConfigResultEntry.from_xml_element(e) for e in result_entries]
        else:
            result_entries = []

        # return the response
        return result_entries

# get information from the environment about how PnP should be used
_pnp_info = {x : os.environ[_PNP_INFO_ENV_VAR_PREFIX + x] for x in _PNP_INFO_KEYS if _PNP_INFO_ENV_VAR_PREFIX + x in os.environ}

try:
    #craft the url that the pnp listener will use. Use 'http' as the default scheme.
    _scheme = _pnp_info.get('scheme', 'http')
    _host = urllib2.quote(_pnp_info['host'], '') #'percent-encode' the host in case it's a path to a socket file.
    _url = "{}://{}{}".format(_scheme, _host, _pnp_info['pnp_listener_path'])
    _udi = _pnp_info['udi']
    _session_id = ''
    
    if 'session_id' in _pnp_info:
        _session_id = _pnp_info['session_id']
    
    # if a token is present, use it. If both token and token_file are present, use token.
    if 'token' in _pnp_info:
        _credential = PnPSessionIDCredential(_pnp_info['token'])
    elif 'token_file' in _pnp_info:
        _credential = PnPSessionIDFileCredential(_pnp_info['token_file'])
    else:
        _credential = PnPUsernameCredential(_pnp_info['user'], _pnp_info['password'])
    
    MAX_WAIT_TIME = int(_pnp_info.get('max_wait', DEFAULT_MAX_WAIT_TIME)) 
    DEBUG = DEBUG or bool(_pnp_info.get('debug', False))

    if 'logfile' in _pnp_info:
        if _pnp_info['logfile'] != '': 
            LOGFILE = _pnp_info['logfile']
     
         
except KeyError as e:
    e.args = ("The PnP Listener cannot be instantiated because the "
            "configuration key '{}' could not be found. Ensure that the "
            "environment is properly configured. See help(cli) for more."
            .format(e.args[0]),)
    raise

def get_session_id():
    return _session_id
    
# create a PnP listener
listener = PnPListener(_url, _udi, _credential)
