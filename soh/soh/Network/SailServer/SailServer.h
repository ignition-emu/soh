#pragma once
#ifdef _WIN32
#ifdef __cplusplus

#include <atomic>
#include <string>
#include <thread>

// SailServer: minimal WebSocket server listening on 127.0.0.1:43384.
// Implements the Ignition save-state remote-control protocol.
// Each incoming connection is handled synchronously: read one JSON command,
// execute it, write one JSON response, close the socket.
// Windows-only (raw Winsock2, no SDL2_net dependency).
class SailServer {
  public:
    static SailServer* Instance;

    void Start();
    void Stop();

  private:
    std::thread mAcceptThread;
    std::atomic<bool> mRunning{ false };
    // Stored as uintptr_t to avoid pulling winsock2.h into the header.
    // INVALID_SOCKET on Windows is (SOCKET)(~0), i.e. all bits set.
    uintptr_t mListenSocket{ ~uintptr_t(0) };

    void AcceptLoop();
    void HandleConnection(uintptr_t client);
    bool PerformHandshake(uintptr_t client);
    bool ReadFrame(uintptr_t client, std::string& out);
    void WriteTextFrame(uintptr_t client, const std::string& payload);
    std::string DispatchCommand(const std::string& json);
};

#endif // __cplusplus
#endif // _WIN32
