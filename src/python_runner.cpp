#include "python_runner.hpp"

#include <nlohmann/json.hpp>

#include <cerrno>
#include <csignal>
#include <string>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

namespace spider {
namespace {

constexpr char python_harness[] = R"PY(
import base64, json, signal, sys, textwrap, traceback

def timed_out(_signum, _frame):
    raise TimeoutError("script exceeded the 2 s execution limit")

signal.signal(signal.SIGALRM, timed_out)
signal.alarm(2)
logs = []

class Api:
    def __init__(self, request):
        self.bytes = base64.b64decode(request.get("content", ""), validate=True)
        self.text = self.bytes.decode("utf-8", errors="replace")
        self.side = request.get("side", "")
        self.session_id = request.get("session_id", "")
        self.session_label = request.get("session_label", "")

    def print(self, *values):
        logs.append(" ".join(str(value) for value in values))

    def hexdump(self, limit=256, width=16):
        data = self.bytes[:max(0, int(limit))]
        rows = []
        for offset in range(0, len(data), width):
            chunk = data[offset:offset + width]
            hexa = " ".join(f"{value:02x}" for value in chunk)
            text = "".join(chr(value) if 32 <= value < 127 else "." for value in chunk)
            rows.append(f"{offset:08x}  {hexa:<{width * 3 - 1}}  |{text}|")
        return "\n".join(rows)

try:
    request = json.load(sys.stdin)
    api = Api(request)
    source = "def __spider_script(api):\n" + textwrap.indent(request.get("script", "pass"), "    ")
    namespace = {"print": api.print}
    exec(compile(source, "<spider-script>", "exec"), namespace)
    result = namespace["__spider_script"](api)
    if result is None:
        replacement = None
    elif isinstance(result, str):
        replacement = base64.b64encode(result.encode()).decode()
    elif isinstance(result, (bytes, bytearray, memoryview)):
        replacement = base64.b64encode(bytes(result)).decode()
    else:
        raise TypeError("script must return None, str, bytes, bytearray, or memoryview")
    response = {"ok": True, "logs": logs, "replacement": replacement}
except BaseException as error:
    response = {"ok": False, "logs": logs,
                "error": "".join(traceback.format_exception_only(type(error), error)).strip()}
finally:
    signal.alarm(0)

sys.stdout.write(json.dumps(response, separators=(",", ":")))
)PY";

nlohmann::json failure(const std::string& message) {
    return {{"ok", false}, {"logs", nlohmann::json::array()}, {"error", message}};
}

} // namespace

nlohmann::json run_python_script(const nlohmann::json& request) {
    int sockets[2]{};
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0) {
        return failure("cannot create Python worker channel");
    }
    const auto pid = ::fork();
    if (pid < 0) {
        ::close(sockets[0]);
        ::close(sockets[1]);
        return failure("cannot start Python worker");
    }
    if (pid == 0) {
        ::close(sockets[0]);
        ::dup2(sockets[1], STDIN_FILENO);
        ::dup2(sockets[1], STDOUT_FILENO);
        ::close(sockets[1]);
        ::execlp("python3", "python3", "-I", "-c", python_harness, nullptr);
        ::_exit(127);
    }

    ::close(sockets[1]);
    const auto input = request.dump();
    std::size_t sent{};
    while (sent < input.size()) {
        const auto count = ::send(sockets[0], input.data() + sent, input.size() - sent, MSG_NOSIGNAL);
        if (count > 0) sent += static_cast<std::size_t>(count);
        else if (count < 0 && errno == EINTR) continue;
        else break;
    }
    ::shutdown(sockets[0], SHUT_WR);

    std::string output;
    char buffer[4096];
    while (output.size() <= 1024 * 1024) {
        const auto count = ::recv(sockets[0], buffer, sizeof(buffer), 0);
        if (count > 0) output.append(buffer, static_cast<std::size_t>(count));
        else if (count < 0 && errno == EINTR) continue;
        else break;
    }
    ::close(sockets[0]);
    int status{};
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    if (output.size() > 1024 * 1024) return failure("Python script output exceeded 1 MiB");
    try {
        return nlohmann::json::parse(output);
    } catch (const nlohmann::json::exception&) {
        return failure("Python worker failed without a valid response");
    }
}

} // namespace spider
