"""HTTP status constants exposed by the mitmproxy addon facade.

The names and legacy reason phrases are a public compatibility contract. The
table is deliberately plain data; it does not import a reference runtime.
"""


_STATUS_TABLE = """
CONTINUE|100|Continue
SWITCHING|101|Switching Protocols
PROCESSING|102|Processing
EARLY_HINTS|103|Early Hints
OK|200|OK
CREATED|201|Created
ACCEPTED|202|Accepted
NON_AUTHORITATIVE_INFORMATION|203|Non-Authoritative Information
NO_CONTENT|204|No Content
RESET_CONTENT|205|Reset Content
PARTIAL_CONTENT|206|Partial Content
MULTI_STATUS|207|Multi-Status
ALREADY_REPORTED|208|Already Reported
IM_USED|226|IM Used
MULTIPLE_CHOICE|300|Multiple Choices
MOVED_PERMANENTLY|301|Moved Permanently
FOUND|302|Found
SEE_OTHER|303|See Other
NOT_MODIFIED|304|Not Modified
USE_PROXY|305|Use Proxy
TEMPORARY_REDIRECT|307|Temporary Redirect
PERMANENT_REDIRECT|308|Permanent Redirect
BAD_REQUEST|400|Bad Request
UNAUTHORIZED|401|Unauthorized
PAYMENT_REQUIRED|402|Payment Required
FORBIDDEN|403|Forbidden
NOT_FOUND|404|Not Found
NOT_ALLOWED|405|Method Not Allowed
NOT_ACCEPTABLE|406|Not Acceptable
PROXY_AUTH_REQUIRED|407|Proxy Authentication Required
REQUEST_TIMEOUT|408|Request Time-out
CONFLICT|409|Conflict
GONE|410|Gone
LENGTH_REQUIRED|411|Length Required
PRECONDITION_FAILED|412|Precondition Failed
PAYLOAD_TOO_LARGE|413|Payload Too Large
REQUEST_URI_TOO_LONG|414|Request-URI Too Long
UNSUPPORTED_MEDIA_TYPE|415|Unsupported Media Type
REQUESTED_RANGE_NOT_SATISFIABLE|416|Requested Range not satisfiable
EXPECTATION_FAILED|417|Expectation Failed
IM_A_TEAPOT|418|I'm a teapot
MISDIRECTED_REQUEST|421|Misdirected Request
UNPROCESSABLE_CONTENT|422|Unprocessable Content
LOCKED|423|Locked
FAILED_DEPENDENCY|424|Failed Dependency
TOO_EARLY|425|Too Early
UPGRADE_REQUIRED|426|Upgrade Required
PRECONDITION_REQUIRED|428|Precondition Required
TOO_MANY_REQUESTS|429|Too Many Requests
REQUEST_HEADER_FIELDS_TOO_LARGE|431|Request Header Fields Too Large
NO_RESPONSE|444|No Response
UNAVAILABLE_FOR_LEGAL_REASONS|451|Unavailable For Legal Reasons
CLIENT_CLOSED_REQUEST|499|Client Closed Request
INTERNAL_SERVER_ERROR|500|Internal Server Error
NOT_IMPLEMENTED|501|Not Implemented
BAD_GATEWAY|502|Bad Gateway
SERVICE_UNAVAILABLE|503|Service Unavailable
GATEWAY_TIMEOUT|504|Gateway Time-out
HTTP_VERSION_NOT_SUPPORTED|505|HTTP Version not supported
VARIANT_ALSO_NEGOTIATES|506|Variant Also Negotiates
INSUFFICIENT_STORAGE_SPACE|507|Insufficient Storage Space
LOOP_DETECTED|508|Loop Detected
NOT_EXTENDED|510|Not Extended
NETWORK_AUTHENTICATION_REQUIRED|511|Network Authentication Required
"""


RESPONSES = {}
_constant_names = []
for _row in _STATUS_TABLE.strip().splitlines():
    _name, _code_text, _reason = _row.split('|', 2)
    _code = int(_code_text)
    globals()[_name] = _code
    RESPONSES[_code] = _reason
    _constant_names.append(_name)

__all__ = tuple(_constant_names) + ('RESPONSES',)

del _code, _code_text, _constant_names, _name, _reason, _row
