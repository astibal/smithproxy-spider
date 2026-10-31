"""Build the public import facade from Spider-owned compatibility objects.

Each generation gets its own module objects. LoadedAddon scopes their presence
in sys.modules; importing this factory never installs a mitmproxy package.
"""

from types import ModuleType

from addon_flow import ControlException, Error, Flow, HTTPFlow, TCPFlow, TCPMessage, UDPFlow, UDPMessage
from addon_http import Headers
from addon_connection import (
    Address, Connection, ConnectionState, Client, Server, TlsVersion,
    TransportProtocol, ProxyMode, RegularMode,
    TransparentMode, Socks5Mode, ReverseMode, UpstreamMode, WireGuardMode,
    LocalMode, TunMode, DnsMode, OsProxyMode, ServerSpec, parse_server_spec,
)
from addon_certs import Cert
from addon_websocket import Opcode, WebSocketMessage, WebSocketData, WebSocketMessageState
from addon_http_message import (
    Message, MessageData, Request, RequestData, Response, ResponseData,
    format_cookie_header, format_set_cookie_header,
    get_expiration_ts, group_cookies, is_expired, parse_cookie_header,
    parse_cookie_headers, parse_set_cookie_header, parse_set_cookie_headers,
    refresh_set_cookie_header,
)
from addon_multidict import CookieAttrs, MultiDict, MultiDictView
from addon_serializable import Serializable, SerializableDataclass, State
from addon_options import OptManager, OptionsError
from addon_manager import AddonManager, AddonManagerError, traverse
from addon_commands import (
    Command, CommandError, CommandManager, CommandParameter, ParseResult, argument,
    command, parsearg, typename, unquote, verify_arg_signature,
)
from addon_types import (
    ALL_MARKERS, Choice, Cmd, CmdArgs, CommandTypes, CutSpec, Data, Marker,
    Path, Space, TypeManager, Unknown,
)
from addon_hooks import Hook, ConfigureHook, RunningHook, DoneHook, UpdateHook, LoadHook
from addon_options import Loader
from addon_options import Options
from addon_exceptions import AddonHalt, FlowReadException, MitmproxyException
from addon_log import (
    ALERT, LOG_COLORS, LOGGING_LEVELS_TO_LOGENTRY, AddLogHook, Log, LogEntry,
    LogLevels, log_tier,
)
import addon_flowfilter
import addon_encoding
import addon_human
import addon_http_headers
import addon_http_validate
import addon_multipart
import addon_status_codes
import addon_strutils
import addon_url
import addon_dns
import addon_dns_domain_names
import addon_dns_https_records
import addon_io
import addon_script
import addon_tnetstring
import addon_contentviews
import addon_signals
import addon_typecheck


def compatibility_modules(*, options=None, master=None):
    modules = {}

    def module(name, *, package=False, exports=None, star_exports=None):
        result = ModuleType(name)
        result.__package__ = name if package else name.rpartition(".")[0]
        if package:
            # Never search disk for a reference package or unsupported submodule.
            result.__path__ = []
        if exports:
            result.__dict__.update(exports)
        if star_exports is not None:
            result.__all__ = tuple(star_exports)
        modules[name] = result
        parent, _, child = name.rpartition(".")
        if parent:
            setattr(modules[parent], child, result)
        return result

    module("mitmproxy", package=True)
    contentview_registry, add_contentview = addon_contentviews.create_contentviews()

    def contentview_metadata(message, flow):
        definitions = getattr(options, "protobuf_definitions", None)
        return addon_contentviews.make_metadata(message, flow, definitions)

    def prettify_contentview_message(
            message, flow, view_name="auto", registry=contentview_registry):
        definitions = getattr(options, "protobuf_definitions", None)
        return addon_contentviews.prettify_message(
            message,
            flow,
            view_name,
            registry=registry,
            protobuf_definitions=definitions,
        )

    def reencode_contentview_message(prettified, message, flow, view_name):
        definitions = getattr(options, "protobuf_definitions", None)
        return addon_contentviews.reencode_message(
            prettified,
            message,
            flow,
            view_name,
            registry=contentview_registry,
            protobuf_definitions=definitions,
        )

    module("mitmproxy.contentviews", exports={
        "Contentview": addon_contentviews.Contentview,
        "ContentviewResult": addon_contentviews.ContentviewResult,
        "ContentviewRegistry": addon_contentviews.ContentviewRegistry,
        "InteractiveContentview": addon_contentviews.InteractiveContentview,
        "SyntaxHighlight": addon_contentviews.SyntaxHighlight,
        "Metadata": addon_contentviews.Metadata,
        "add": add_contentview,
        "get_data": addon_contentviews.get_data,
        "make_metadata": contentview_metadata,
        "prettify_message": prettify_contentview_message,
        "reencode_message": reencode_contentview_message,
        # Spider's worker uses this generation-local registry to expose actual
        # custom renderers. It is intentionally outside the star-import API.
        "registry": contentview_registry,
    }, star_exports=addon_contentviews.__all__)
    module('mitmproxy.version', exports={
        # This is the public compatibility contract, not the Spider release.
        'FLOW_FORMAT_VERSION': 21,
        'MITMPROXY': 'mitmproxy 12.3.1',
        'VERSION': '12.3.1',
    })
    module("mitmproxy.net", package=True)
    server_spec = module("mitmproxy.net.server_spec", exports={
        "ServerSpec": ServerSpec,
        "parse": parse_server_spec,
    })
    module('mitmproxy.net.encoding', exports={
        name: getattr(addon_encoding, name)
        for name in (
            'CachedDecode', 'custom_decode', 'custom_encode', 'decode',
            'decode_brotli', 'decode_deflate', 'decode_gzip', 'decode_zstd',
            'encode', 'encode_brotli', 'encode_deflate', 'encode_gzip',
            'encode_zstd', 'identity',
        )
    }, star_exports=('encode', 'decode'))
    module("mitmproxy.net.http", package=True)
    module('mitmproxy.net.http.headers', exports={
        'assemble_content_type': addon_http_headers.assemble_content_type,
        'infer_content_encoding': addon_http_headers.infer_content_encoding,
        'parse_content_type': addon_http_headers.parse_content_type,
    })
    module('mitmproxy.net.http.validate', exports={
        'TransferEncoding': addon_http_validate.TransferEncoding,
        'parse_content_length': addon_http_validate.parse_content_length,
        'parse_transfer_encoding': addon_http_validate.parse_transfer_encoding,
        'validate_headers': addon_http_validate.validate_headers,
    })
    module('mitmproxy.net.http.multipart', exports={
        'decode': addon_multipart.decode,
        'decode_multipart': addon_multipart.decode_multipart,
        'encode': addon_multipart.encode,
        'encode_multipart': addon_multipart.encode_multipart,
    })
    status_codes = module('mitmproxy.net.http.status_codes', exports={
        name: getattr(addon_status_codes, name)
        for name in addon_status_codes.__all__
    })
    url = module('mitmproxy.net.http.url', exports={
        name: getattr(addon_url, name)
        for name in addon_url.__all__
    })
    module('mitmproxy.log', exports={
        'ALERT': ALERT,
        'LOG_COLORS': LOG_COLORS,
        'LOGGING_LEVELS_TO_LOGENTRY': LOGGING_LEVELS_TO_LOGENTRY,
        'AddLogHook': AddLogHook,
        'Log': Log,
        'LogEntry': LogEntry,
        'LogLevels': LogLevels,
        'log_tier': log_tier,
    })
    script = module('mitmproxy.script', package=True)
    module('mitmproxy.script.concurrent', exports={
        'concurrent': addon_script.concurrent,
    })
    # The package exports the decorator itself, not its implementation module.
    script.concurrent = addon_script.concurrent
    script.__all__ = ['concurrent']
    module('mitmproxy.io', package=True, exports={
        'FlowWriter': addon_io.FlowWriter,
        'FlowReader': addon_io.FlowReader,
        'FilteredFlowWriter': addon_io.FilteredFlowWriter,
        'read_flows_from_paths': addon_io.read_flows_from_paths,
    }, star_exports=(
        'FlowWriter', 'FlowReader', 'FilteredFlowWriter',
        'read_flows_from_paths',
    ))
    tnetstring_exports = {
        name: getattr(addon_tnetstring, name)
        for name in addon_tnetstring.__all__
    }
    tnetstring_exports.update({
        'parse': addon_tnetstring.parse,
        'split': addon_tnetstring.split,
    })
    module(
        'mitmproxy.io.tnetstring',
        exports=tnetstring_exports,
        star_exports=('dump', 'dumps', 'load', 'loads', 'pop'),
    )
    module('mitmproxy.flowfilter', exports={
        name: getattr(addon_flowfilter, name)
        for name in (
            'TFilter', 'FErr', 'FMarked', 'FHTTP', 'FWebSocket', 'FTCP',
            'FUDP', 'FDNS', 'FReq', 'FResp', 'FAll', 'FAsset',
            'FContentType', 'FContentTypeRequest', 'FContentTypeResponse',
            'FHead', 'FHeadRequest', 'FHeadResponse', 'FBod', 'FBodRequest',
            'FBodResponse', 'FMethod', 'FDomain', 'FUrl', 'FSrc', 'FDst',
            'FReplay', 'FReplayClient', 'FReplayServer', 'FMeta', 'FMarker',
            'FComment', 'FCode', 'FAnd', 'FOr', 'FNot', 'parse', 'match',
            'match_all',
        )
    })
    module('mitmproxy.utils', package=True)
    module('mitmproxy.utils.strutils', exports={
        name: getattr(addon_strutils, name)
        for name in (
            'MULTILINE_CONTENT', 'MULTILINE_CONTENT_LINE_CONTINUATION',
            'NO_ESCAPE', 'SINGLELINE_CONTENT', 'always_bytes', 'always_str',
            'bytes_to_escaped_str', 'clean_hanging_newline',
            'cut_after_n_lines', 'escape_control_characters',
            'escape_special_areas', 'escaped_str_to_bytes', 'hexdump',
            'is_mostly_bin', 'is_xml', 'split_special_areas',
            'unescape_special_areas',
        )
    })
    module('mitmproxy.utils.human', exports={
        'SIZE_UNITS': addon_human.SIZE_UNITS,
        'format_timestamp': addon_human.format_timestamp,
        'format_timestamp_with_milli': addon_human.format_timestamp_with_milli,
        'format_address': addon_human.format_address,
        'parse_size': addon_human.parse_size,
        'pretty_duration': addon_human.pretty_duration,
        'pretty_size': addon_human.pretty_size,
    })
    module('mitmproxy.utils.typecheck', exports={
        'check_option_type': addon_typecheck.check_option_type,
        'typespec_to_str': addon_typecheck.typespec_to_str,
    })
    module('mitmproxy.utils.signals', exports={
        'AsyncSignal': addon_signals.AsyncSignal,
        'SyncSignal': addon_signals.SyncSignal,
        'make_weak_ref': addon_signals.make_weak_ref,
    })
    if options is not None:
        log = master.log if master is not None else Log(None)
        module("mitmproxy.ctx", exports={"options": options, "log": log})
        if master is not None:
            modules['mitmproxy.ctx'].master = master
    module('mitmproxy.addonmanager', exports={
        'AddonManager': AddonManager, 'AddonManagerError': AddonManagerError,
        'LoadHook': LoadHook, 'Loader': Loader, 'traverse': traverse,
    })
    module('mitmproxy.hooks', exports={
        'Hook': Hook, 'ConfigureHook': ConfigureHook, 'RunningHook': RunningHook,
        'DoneHook': DoneHook, 'UpdateHook': UpdateHook,
        'all_hooks': {
            'add_log': AddLogHook, 'configure': ConfigureHook,
            'done': DoneHook, 'running': RunningHook, 'update': UpdateHook,
        },
    })
    module('mitmproxy.command', exports={
        'argument': argument, 'command': command,
        'Command': Command, 'CommandManager': CommandManager,
        'CommandParameter': CommandParameter,
        'ParseResult': ParseResult, 'parsearg': parsearg, 'typename': typename,
        'unquote': unquote, 'verify_arg_signature': verify_arg_signature,
    })
    module('mitmproxy.types', exports={
        'ALL_MARKERS': ALL_MARKERS, 'Choice': Choice, 'Cmd': Cmd,
        'CmdArgs': CmdArgs, 'CutSpec': CutSpec, 'Data': Data,
        'Marker': Marker, 'Path': Path, 'Space': Space, 'Unknown': Unknown,
        'CommandTypes': CommandTypes, 'TypeManager': TypeManager,
    })
    module("mitmproxy.http", exports={
        "Headers": Headers,
        "Message": Message,
        "MessageData": MessageData,
        "Request": Request,
        "RequestData": RequestData,
        "Response": Response,
        "ResponseData": ResponseData,
        "HTTPFlow": HTTPFlow,
        "WebSocketData": WebSocketData,
        "always_bytes": addon_strutils.always_bytes,
        "always_str": addon_strutils.always_str,
        "assemble_content_type": addon_http_headers.assemble_content_type,
        "infer_content_encoding": addon_http_headers.infer_content_encoding,
        "parse_content_type": addon_http_headers.parse_content_type,
        "status_codes": status_codes,
        "url": url,
    }, star_exports=('HTTPFlow', 'Message', 'Request', 'Response', 'Headers'))
    module("mitmproxy.flow", exports={"Error": Error, "Flow": Flow},
           star_exports=('Flow', 'Error'))
    module("mitmproxy.net.dns", package=True)
    dns_domain_names = module("mitmproxy.net.dns.domain_names", exports={
        "cache": addon_dns_domain_names.cache,
        "decompress_from_record_data": (
            addon_dns_domain_names.decompress_from_record_data
        ),
        "pack": addon_dns_domain_names.pack,
        "record_data_can_have_compression": (
            addon_dns_domain_names.record_data_can_have_compression
        ),
        "unpack": addon_dns_domain_names.unpack,
        "unpack_from": addon_dns_domain_names.unpack_from,
        "unpack_from_with_compression": (
            addon_dns_domain_names.unpack_from_with_compression
        ),
    })
    dns_https_records = module("mitmproxy.net.dns.https_records", exports={
        "HTTPSRecord": addon_dns.HTTPSRecord,
        "HTTPSRecordJSON": addon_dns_https_records.HTTPSRecordJSON,
        "SVCParamKeys": addon_dns.SVCParamKeys,
        "domain_names": dns_domain_names,
        "pack": addon_dns_https_records.pack,
        "unpack": addon_dns_https_records.unpack,
    })
    dns_types = module("mitmproxy.net.dns.types", exports={
        **{name: getattr(addon_dns.types, name)
           for name in addon_dns.types._values},
        "to_str": addon_dns.types.to_str,
        "from_str": addon_dns.types.from_str,
    })
    dns_classes = module("mitmproxy.net.dns.classes", exports={
        **{name: getattr(addon_dns.classes, name)
           for name in addon_dns.classes._values},
        "to_str": addon_dns.classes.to_str,
        "from_str": addon_dns.classes.from_str,
    })
    dns_op_codes = module("mitmproxy.net.dns.op_codes", exports={
        **{name: getattr(addon_dns.op_codes, name)
           for name in addon_dns.op_codes._values},
        "to_str": addon_dns.op_codes.to_str,
        "from_str": addon_dns.op_codes.from_str,
    })
    dns_response_codes = module("mitmproxy.net.dns.response_codes", exports={
        **{name: getattr(addon_dns.response_codes, name)
           for name in addon_dns.response_codes._values},
        "to_str": addon_dns.response_codes.to_str,
        "from_str": addon_dns.response_codes.from_str,
        "http_equiv_status_code": addon_dns.response_codes.http_equiv_status_code,
    })
    dns_exports = {
        "Question": addon_dns.Question,
        "ResourceRecord": addon_dns.ResourceRecord,
        "DNSMessage": addon_dns.DNSMessage,
        "DNSFlow": addon_dns.DNSFlow,
        "HTTPSRecord": addon_dns.HTTPSRecord,
        "SVCParamKeys": addon_dns.SVCParamKeys,
        "types": dns_types,
        "classes": dns_classes,
        "op_codes": dns_op_codes,
        "response_codes": dns_response_codes,
    }
    module("mitmproxy.dns", exports=dns_exports)
    modules["mitmproxy.dns"].domain_names = dns_domain_names
    modules["mitmproxy.dns"].flow = modules["mitmproxy.flow"]
    modules["mitmproxy.dns"].https_records = dns_https_records
    module('mitmproxy.connection', exports={
        'Address': Address,
        'Connection': Connection, 'ConnectionState': ConnectionState,
        'Client': Client, 'Server': Server,
        'TlsVersion': TlsVersion, 'TransportProtocol': TransportProtocol,
        'server_spec': server_spec,
    }, star_exports=('Connection', 'Client', 'Server', 'ConnectionState'))
    module('mitmproxy.proxy', package=True)
    module('mitmproxy.proxy.mode_specs', exports={
        'ProxyMode': ProxyMode, 'RegularMode': RegularMode,
        'TransparentMode': TransparentMode, 'Socks5Mode': Socks5Mode,
        'ReverseMode': ReverseMode, 'UpstreamMode': UpstreamMode,
        'WireGuardMode': WireGuardMode, 'LocalMode': LocalMode,
        'TunMode': TunMode, 'DnsMode': DnsMode, 'OsProxyMode': OsProxyMode,
        'TCP': 'tcp', 'UDP': 'udp', 'BOTH': 'both',
    })
    module('mitmproxy.certs', exports={'Cert': Cert})
    module('mitmproxy.websocket', exports={
        'Opcode': Opcode, 'WebSocketMessage': WebSocketMessage,
        'WebSocketData': WebSocketData,
        'WebSocketMessageState': WebSocketMessageState,
    })
    module("mitmproxy.tcp", exports={"TCPFlow": TCPFlow, "TCPMessage": TCPMessage},
           star_exports=('TCPFlow', 'TCPMessage'))
    module("mitmproxy.udp", exports={"UDPFlow": UDPFlow, "UDPMessage": UDPMessage},
           star_exports=('UDPFlow', 'UDPMessage'))
    module("mitmproxy.options", exports={
        "CONF_BASENAME": "mitmproxy",
        "CONF_DIR": "~/.mitmproxy",
        "CONTENT_VIEW_LINES_CUTOFF": 512,
        "KEY_SIZE": 2048,
        "Options": Options,
    })
    module("mitmproxy.optmanager", exports={"OptManager": OptManager})
    module("mitmproxy.exceptions", exports={
        "MitmproxyException": MitmproxyException,
        "FlowReadException": FlowReadException,
        "AddonHalt": AddonHalt,
        "AddonManagerError": AddonManagerError,
        "ControlException": ControlException,
        "OptionsError": OptionsError,
        "CommandError": CommandError,
    })
    module("mitmproxy.coretypes", package=True)
    module("mitmproxy.coretypes.serializable", exports={
        "Serializable": Serializable,
        "SerializableDataclass": SerializableDataclass,
        "State": State,
    })
    module("mitmproxy.coretypes.multidict", exports={
        "MultiDict": MultiDict,
        "MultiDictView": MultiDictView,
    })
    cookies = module("mitmproxy.net.http.cookies", exports={
        "CookieAttrs": CookieAttrs,
        "format_cookie_header": format_cookie_header,
        "format_set_cookie_header": format_set_cookie_header,
        "get_expiration_ts": get_expiration_ts,
        "group_cookies": group_cookies,
        "is_expired": is_expired,
        "parse_cookie_header": parse_cookie_header,
        "parse_cookie_headers": parse_cookie_headers,
        "parse_set_cookie_header": parse_set_cookie_header,
        "parse_set_cookie_headers": parse_set_cookie_headers,
        "refresh_set_cookie_header": refresh_set_cookie_header,
    })
    modules['mitmproxy.http'].cookies = cookies
    modules['mitmproxy.http'].encoding = modules['mitmproxy.net.encoding']
    modules['mitmproxy.http'].human = modules['mitmproxy.utils.human']
    modules['mitmproxy.http'].multipart = modules['mitmproxy.net.http.multipart']
    modules['mitmproxy.http'].multidict = modules['mitmproxy.coretypes.multidict']
    modules['mitmproxy.http'].flow = modules['mitmproxy.flow']
    modules['mitmproxy.http'].serializable = modules['mitmproxy.coretypes.serializable']
    modules['mitmproxy.http'].strutils = modules['mitmproxy.utils.strutils']
    modules['mitmproxy.connection'].certs = modules['mitmproxy.certs']
    modules['mitmproxy.connection'].human = modules['mitmproxy.utils.human']
    modules['mitmproxy.connection'].mode_specs = modules['mitmproxy.proxy.mode_specs']
    modules['mitmproxy.connection'].serializable = modules['mitmproxy.coretypes.serializable']
    modules['mitmproxy.flow'].connection = modules['mitmproxy.connection']
    modules['mitmproxy.flow'].serializable = modules['mitmproxy.coretypes.serializable']
    modules['mitmproxy.flow'].version = modules['mitmproxy.version']
    modules['mitmproxy.dns'].serializable = modules[
        'mitmproxy.coretypes.serializable'
    ]
    return modules
