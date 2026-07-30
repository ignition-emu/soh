#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

using sail_socket_t = SOCKET;
// recv()/send() take an int length on Winsock but size_t on POSIX; naming the
// type keeps both free of narrowing-conversion warnings.
using sail_iolen_t = int;
#define SAIL_INVALID_SOCKET INVALID_SOCKET
#define SAIL_SOCKET_ERROR SOCKET_ERROR
#define sail_close_socket closesocket
// Winsock never raises SIGPIPE, so no send() flag is needed.
#define SAIL_SEND_FLAGS 0

#else // !_WIN32

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>

using sail_socket_t = int;
using sail_iolen_t = size_t;
#define SAIL_INVALID_SOCKET (-1)
#define SAIL_SOCKET_ERROR (-1)
#define sail_close_socket ::close
// Linux suppresses SIGPIPE per-call; macOS/BSD lack MSG_NOSIGNAL and use the
// SO_NOSIGPIPE socket option instead (applied in HandleConnection). Without one
// of the two, a client vanishing mid-response would kill the whole game.
#ifdef MSG_NOSIGNAL
#define SAIL_SEND_FLAGS MSG_NOSIGNAL
#else
#define SAIL_SEND_FLAGS 0
#endif

#endif // _WIN32

#include "SailServer.h"
#include "soh/SaveManager.h"
#include "soh/SohGui/SohGui.hpp"
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>

SailServer* SailServer::Instance;

// ---------------------------------------------------------------------------
// Minimal inline SHA-1 (public domain, RFC 3174 reference implementation)
// ---------------------------------------------------------------------------
namespace {

struct SHA1Context {
    uint32_t intermediate_hash[5];
    uint32_t length_low;
    uint32_t length_high;
    int_least16_t message_block_index;
    uint8_t message_block[64];
    bool computed;
    bool corrupted;
};

static void SHA1ProcessMessageBlock(SHA1Context* ctx) {
    const uint32_t K[] = { 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 };
    uint32_t W[80];
    for (int t = 0; t < 16; ++t)
        W[t] = ((uint32_t)ctx->message_block[t * 4] << 24) |
               ((uint32_t)ctx->message_block[t * 4 + 1] << 16) |
               ((uint32_t)ctx->message_block[t * 4 + 2] << 8) |
               ((uint32_t)ctx->message_block[t * 4 + 3]);
    for (int t = 16; t < 80; ++t) {
        uint32_t x = W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16];
        W[t] = (x << 1) | (x >> 31);
    }
    uint32_t A = ctx->intermediate_hash[0], B = ctx->intermediate_hash[1],
             C = ctx->intermediate_hash[2], D = ctx->intermediate_hash[3],
             E = ctx->intermediate_hash[4];
    for (int t = 0; t < 80; ++t) {
        uint32_t tmp = ((A << 5) | (A >> 27)) + E + W[t];
        if (t < 20)      tmp += ((B & C) | ((~B) & D)) + K[0];
        else if (t < 40) tmp += (B ^ C ^ D) + K[1];
        else if (t < 60) tmp += ((B & C) | (B & D) | (C & D)) + K[2];
        else             tmp += (B ^ C ^ D) + K[3];
        E = D; D = C; C = (B << 30) | (B >> 2); B = A; A = tmp;
    }
    ctx->intermediate_hash[0] += A; ctx->intermediate_hash[1] += B;
    ctx->intermediate_hash[2] += C; ctx->intermediate_hash[3] += D;
    ctx->intermediate_hash[4] += E;
    ctx->message_block_index = 0;
}

static void SHA1Input(SHA1Context* ctx, const uint8_t* data, size_t len) {
    while (len--) {
        ctx->message_block[ctx->message_block_index++] = *data++;
        ctx->length_low += 8;
        if (ctx->message_block_index == 64)
            SHA1ProcessMessageBlock(ctx);
    }
}

static void SHA1PadMessage(SHA1Context* ctx) {
    ctx->message_block[ctx->message_block_index++] = 0x80;
    if (ctx->message_block_index > 55) {
        while (ctx->message_block_index < 64) ctx->message_block[ctx->message_block_index++] = 0;
        SHA1ProcessMessageBlock(ctx);
    }
    while (ctx->message_block_index < 56) ctx->message_block[ctx->message_block_index++] = 0;
    ctx->message_block[56] = (ctx->length_high >> 24) & 0xFF;
    ctx->message_block[57] = (ctx->length_high >> 16) & 0xFF;
    ctx->message_block[58] = (ctx->length_high >>  8) & 0xFF;
    ctx->message_block[59] =  ctx->length_high        & 0xFF;
    ctx->message_block[60] = (ctx->length_low  >> 24) & 0xFF;
    ctx->message_block[61] = (ctx->length_low  >> 16) & 0xFF;
    ctx->message_block[62] = (ctx->length_low  >>  8) & 0xFF;
    ctx->message_block[63] =  ctx->length_low         & 0xFF;
    SHA1ProcessMessageBlock(ctx);
}

static std::array<uint8_t, 20> sha1(const std::string& input) {
    SHA1Context ctx{};
    ctx.intermediate_hash[0] = 0x67452301;
    ctx.intermediate_hash[1] = 0xEFCDAB89;
    ctx.intermediate_hash[2] = 0x98BADCFE;
    ctx.intermediate_hash[3] = 0x10325476;
    ctx.intermediate_hash[4] = 0xC3D2E1F0;
    SHA1Input(&ctx, reinterpret_cast<const uint8_t*>(input.data()), input.size());
    SHA1PadMessage(&ctx);
    std::array<uint8_t, 20> digest{};
    for (int i = 0; i < 5; ++i) {
        digest[i * 4 + 0] = (ctx.intermediate_hash[i] >> 24) & 0xFF;
        digest[i * 4 + 1] = (ctx.intermediate_hash[i] >> 16) & 0xFF;
        digest[i * 4 + 2] = (ctx.intermediate_hash[i] >>  8) & 0xFF;
        digest[i * 4 + 3] =  ctx.intermediate_hash[i]        & 0xFF;
    }
    return digest;
}

// ---------------------------------------------------------------------------
// Minimal base64 encoder (RFC 4648, standard alphabet)
// ---------------------------------------------------------------------------
static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64(const uint8_t* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t b = (uint32_t)data[i] << 16;
        if (i + 1 < len) b |= (uint32_t)data[i + 1] << 8;
        if (i + 2 < len) b |= (uint32_t)data[i + 2];
        out += B64[(b >> 18) & 0x3F];
        out += B64[(b >> 12) & 0x3F];
        out += (i + 1 < len) ? B64[(b >> 6) & 0x3F] : '=';
        out += (i + 2 < len) ? B64[(b >> 0) & 0x3F] : '=';
    }
    return out;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static bool recvAll(sail_socket_t s, char* buf, int len) {
    int received = 0;
    while (received < len) {
        auto r = recv(s, buf + received, static_cast<sail_iolen_t>(len - received), 0);
        if (r <= 0) return false;
        received += static_cast<int>(r);
    }
    return true;
}

// Winsock needs explicit teardown; POSIX sockets need none.
static void sailNetShutdown() {
#ifdef _WIN32
    WSACleanup();
#endif
}

// Winsock reports through WSAGetLastError(); POSIX through errno.
static std::string lastSocketError() {
#ifdef _WIN32
    return std::to_string(WSAGetLastError());
#else
    return std::strerror(errno);
#endif
}

// SO_RCVTIMEO/SO_SNDTIMEO take a DWORD of milliseconds on Winsock but a
// struct timeval on POSIX — passing the wrong one silently leaves the socket
// blocking forever.
static void setSocketTimeout(sail_socket_t s, int option, int millis) {
#ifdef _WIN32
    DWORD timeout = static_cast<DWORD>(millis);
    setsockopt(s, SOL_SOCKET, option, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
#else
    timeval tv{};
    tv.tv_sec = millis / 1000;
    tv.tv_usec = (millis % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, option, &tv, sizeof(tv));
#endif
}

// Send everything, tolerating short writes (POSIX send() may return < len).
static bool sendAll(sail_socket_t s, const char* buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        auto n = send(s, buf + sent, static_cast<sail_iolen_t>(len - sent), SAIL_SEND_FLAGS);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return {};
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// SailServer implementation
// ---------------------------------------------------------------------------

void SailServer::Start() {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        SPDLOG_ERROR("[SailServer] WSAStartup failed");
        return;
    }
#endif

    sail_socket_t sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == SAIL_INVALID_SOCKET) {
        SPDLOG_ERROR("[SailServer] socket() failed: {}", lastSocketError());
        sailNetShutdown();
        return;
    }

    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(43384);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SAIL_SOCKET_ERROR) {
        SPDLOG_ERROR("[SailServer] bind() failed: {}", lastSocketError());
        sail_close_socket(sock);
        sailNetShutdown();
        return;
    }

    if (listen(sock, SOMAXCONN) == SAIL_SOCKET_ERROR) {
        SPDLOG_ERROR("[SailServer] listen() failed: {}", lastSocketError());
        sail_close_socket(sock);
        sailNetShutdown();
        return;
    }

#ifndef _WIN32
    // POSIX close() does not reliably wake a thread blocked in accept(), so the
    // listen socket gets a receive timeout and AcceptLoop re-checks mRunning.
    // Winsock's closesocket() does unblock accept(), so this is POSIX-only.
    setSocketTimeout(sock, SO_RCVTIMEO, 250);
#endif

    mListenSocket = static_cast<uintptr_t>(sock);
    mRunning = true;
    mAcceptThread = std::thread(&SailServer::AcceptLoop, this);
    SPDLOG_INFO("[SailServer] Listening on ws://127.0.0.1:43384");
}

void SailServer::Stop() {
    mRunning = false;
    sail_socket_t sock = static_cast<sail_socket_t>(mListenSocket);
    if (sock != SAIL_INVALID_SOCKET) {
#ifndef _WIN32
        // Nudge any in-flight accept() before closing the descriptor.
        shutdown(sock, SHUT_RDWR);
#endif
        sail_close_socket(sock);
        mListenSocket = static_cast<uintptr_t>(SAIL_INVALID_SOCKET);
    }
    if (mAcceptThread.joinable()) {
        mAcceptThread.join();
    }
    sailNetShutdown();
}

void SailServer::AcceptLoop() {
    sail_socket_t listenSock = static_cast<sail_socket_t>(mListenSocket);
    while (mRunning) {
        sail_socket_t client = accept(listenSock, nullptr, nullptr);
        if (client == SAIL_INVALID_SOCKET) {
#ifndef _WIN32
            // The listen socket carries a receive timeout so this loop can
            // observe mRunning; those wakeups are not errors.
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                continue;
            }
#endif
            break; // Socket closed by Stop(), or real error
        }
        HandleConnection(static_cast<uintptr_t>(client));
    }
}

void SailServer::HandleConnection(uintptr_t clientHandle) {
    sail_socket_t client = static_cast<sail_socket_t>(clientHandle);

    setSocketTimeout(client, SO_RCVTIMEO, 500);
    setSocketTimeout(client, SO_SNDTIMEO, 500);

#if !defined(_WIN32) && !defined(MSG_NOSIGNAL) && defined(SO_NOSIGPIPE)
    // macOS/BSD: suppress SIGPIPE per-socket since MSG_NOSIGNAL is unavailable.
    int nosigpipe = 1;
    setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, sizeof(nosigpipe));
#endif

    if (!PerformHandshake(clientHandle)) {
        sail_close_socket(client);
        return;
    }

    std::string payload;
    if (!ReadFrame(clientHandle, payload)) {
        sail_close_socket(client);
        return;
    }

    std::string response = DispatchCommand(payload);
    WriteTextFrame(clientHandle, response);
    sail_close_socket(client);
}

bool SailServer::PerformHandshake(uintptr_t clientHandle) {
    sail_socket_t client = static_cast<sail_socket_t>(clientHandle);

    // Read HTTP upgrade request until we see the end of headers
    std::string request;
    request.reserve(512);
    char ch;
    while (request.size() < 4096) {
        auto r = recv(client, &ch, 1, 0);
        if (r <= 0) return false;
        request += ch;
        if (request.size() >= 4 && request.substr(request.size() - 4) == "\r\n\r\n")
            break;
    }

    // Extract Sec-WebSocket-Key
    const std::string keyHeader = "Sec-WebSocket-Key:";
    auto pos = request.find(keyHeader);
    if (pos == std::string::npos) return false;
    pos += keyHeader.size();
    auto end = request.find("\r\n", pos);
    if (end == std::string::npos) return false;
    std::string clientKey = trim(request.substr(pos, end - pos));

    // Compute accept key: base64(SHA1(clientKey + magic))
    static const char* magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    auto digest = sha1(clientKey + magic);
    std::string acceptKey = base64(digest.data(), digest.size());

    // Send HTTP 101
    std::string response =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: " + acceptKey + "\r\n"
        "\r\n";
    return sendAll(client, response.data(), response.size());
}

bool SailServer::ReadFrame(uintptr_t clientHandle, std::string& out) {
    sail_socket_t client = static_cast<sail_socket_t>(clientHandle);

    // Read 2-byte frame header
    uint8_t header[2];
    if (!recvAll(client, reinterpret_cast<char*>(header), 2)) return false;

    // Validate: FIN=1, opcode=1 (text), MASK=1
    bool fin    = (header[0] & 0x80) != 0;
    uint8_t op  =  header[0] & 0x0F;
    bool masked = (header[1] & 0x80) != 0;
    if (!fin || op != 0x1 || !masked) return false;

    uint64_t payloadLen = header[1] & 0x7F;
    if (payloadLen == 126) {
        uint8_t ext[2];
        if (!recvAll(client, reinterpret_cast<char*>(ext), 2)) return false;
        payloadLen = ((uint64_t)ext[0] << 8) | ext[1];
    } else if (payloadLen == 127) {
        return false; // Too large; our commands are tiny
    }

    // Read masking key
    uint8_t mask[4];
    if (!recvAll(client, reinterpret_cast<char*>(mask), 4)) return false;

    // Read and unmask payload
    std::string payload(static_cast<size_t>(payloadLen), '\0');
    if (!recvAll(client, payload.data(), static_cast<int>(payloadLen))) return false;
    for (size_t i = 0; i < payload.size(); ++i)
        payload[i] ^= mask[i % 4];

    out = std::move(payload);
    return true;
}

void SailServer::WriteTextFrame(uintptr_t clientHandle, const std::string& payload) {
    sail_socket_t client = static_cast<sail_socket_t>(clientHandle);
    // Server-to-client frames are not masked (RFC 6455 §5.1)
    uint8_t header[4];
    int headerLen;
    size_t len = payload.size();
    if (len < 126) {
        header[0] = 0x81;
        header[1] = static_cast<uint8_t>(len);
        headerLen = 2;
    } else {
        header[0] = 0x81;
        header[1] = 126;
        header[2] = static_cast<uint8_t>((len >> 8) & 0xFF);
        header[3] = static_cast<uint8_t>(len & 0xFF);
        headerLen = 4;
    }
    if (!sendAll(client, reinterpret_cast<const char*>(header), static_cast<size_t>(headerLen))) {
        return;
    }
    sendAll(client, payload.data(), len);
}

std::string SailServer::DispatchCommand(const std::string& jsonText) {
    nlohmann::json req;
    try {
        req = nlohmann::json::parse(jsonText);
    } catch (...) {
        return R"({"result":"error","message":"invalid json"})";
    }

    std::string cmd;
    try {
        cmd = req.at("command").get<std::string>();
    } catch (...) {
        return R"({"result":"error","message":"missing command"})";
    }

    if (cmd == "ping") {
        return R"({"result":"pong"})";
    }

    if (cmd == "save_state" || cmd == "load_state") {
        int slot;
        try {
            slot = req.at("slot").get<int>();
        } catch (...) {
            return R"({"result":"error","message":"missing slot"})";
        }

        if (slot < 0 || slot >= SaveManager::MaxFiles) {
            return R"({"result":"error","message":"slot out of range"})";
        }

        try {
            if (cmd == "save_state") {
                SaveManager::Instance->SaveFile(slot);
                SaveManager::Instance->ThreadPoolWait();
            } else {
                SaveManager::Instance->LoadFile(slot);
            }
        } catch (const std::exception& e) {
            nlohmann::json err;
            err["result"] = "error";
            err["message"] = e.what();
            return err.dump();
        } catch (...) {
            return R"({"result":"error","message":"unknown exception"})";
        }
        return R"({"result":"ok"})";
    }

    if (cmd == "toggle_menu") {
        SohGui::ShowEscMenu();
        return R"({"result":"ok"})";
    }

    return R"({"result":"error","message":"unknown command"})";
}
