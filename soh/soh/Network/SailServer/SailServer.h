#pragma once
#ifdef __cplusplus

#include <atomic>
#include <string>
#include <thread>

// SailServer: minimal WebSocket server listening on 127.0.0.1:43384.
// Implements the Ignition save-state remote-control protocol.
// Each incoming connection is handled synchronously: read one JSON command,
// execute it, write one JSON response, close the socket.
// Raw sockets (Winsock2 on Windows, BSD sockets elsewhere) — no SDL2_net
// dependency, so this builds regardless of BUILD_REMOTE_CONTROL.
class SailServer {
  public:
    static SailServer* Instance;

    void Start();
    void Stop();

  private:
    std::thread mAcceptThread;
    std::atomic<bool> mRunning{ false };
    // Stored as uintptr_t to avoid pulling winsock2.h into the header.
    // All-bits-set is the invalid sentinel on both platforms: INVALID_SOCKET is
    // (SOCKET)(~0) on Windows, and -1 widens to the same value on POSIX.
    uintptr_t mListenSocket{ ~uintptr_t(0) };

    void AcceptLoop();
    void HandleConnection(uintptr_t client);
    bool PerformHandshake(uintptr_t client);
    bool ReadFrame(uintptr_t client, std::string& out);
    void WriteTextFrame(uintptr_t client, const std::string& payload);
    std::string DispatchCommand(const std::string& json);
};

#endif // __cplusplus
