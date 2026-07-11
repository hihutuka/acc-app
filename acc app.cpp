// acc app.cpp : このファイルには 'main' 関数が含まれています。プログラム実行の開始と終了がそこで行われます。
//

#define WIN32_LEAN_AND_MEAN

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using BYTE = unsigned char;
using BOOL = int;
using DWORD = unsigned long;
using HANDLE = void*;
using HCRYPTPROV = std::uintptr_t;
using HCRYPTHASH = std::uintptr_t;
using LPCSTR = const char*;
using LPCWSTR = const wchar_t*;
using LPVOID = void*;
using LPCVOID = const void*;
using SIZE_T = std::size_t;
using SOCKET = std::uintptr_t;
using WORD = unsigned short;

constexpr BOOL FALSE = 0;
constexpr BOOL TRUE = 1;
constexpr WORD MakeWord(BYTE low, BYTE high)
{
    return static_cast<WORD>((static_cast<WORD>(high) << 8) | low);
}

struct in_addr
{
    std::uint32_t s_addr;
};

struct sockaddr
{
    unsigned short sa_family;
    char sa_data[14];
};

struct sockaddr_in
{
    short sin_family;
    unsigned short sin_port;
    in_addr sin_addr;
    char sin_zero[8];
};

struct WSAData
{
    unsigned short wVersion;
    unsigned short wHighVersion;
    char szDescription[257];
    char szSystemStatus[129];
    unsigned short iMaxSockets;
    unsigned short iMaxUdpDg;
    char* lpVendorInfo;
};
using WSADATA = WSAData;

constexpr SOCKET INVALID_SOCKET = static_cast<SOCKET>(~0ull);
constexpr int SOCKET_ERROR = -1;
constexpr int AF_INET = 2;
constexpr int SOCK_STREAM = 1;
constexpr int IPPROTO_TCP = 6;
constexpr int SD_BOTH = 2;
constexpr DWORD FILE_MAP_READ = 0x0004;
constexpr DWORD PROV_RSA_AES = 24;
constexpr DWORD CRYPT_VERIFYCONTEXT = 0xF0000000;
constexpr DWORD CALG_SHA1 = 0x00008004;
constexpr DWORD HP_HASHVAL = 0x0002;
constexpr DWORD CRYPT_STRING_BASE64 = 0x00000001;
constexpr DWORD CRYPT_STRING_NOCRLF = 0x40000000;
constexpr int SOMAXCONN = 0x7fffffff;
constexpr std::uint32_t INADDR_ANY = 0x00000000;
constexpr unsigned short htons(unsigned short value)
{
    return static_cast<unsigned short>((value << 8) | (value >> 8));
}
constexpr std::uint32_t htonl(std::uint32_t value)
{
    return ((value & 0x000000FFu) << 24) |
           ((value & 0x0000FF00u) << 8) |
           ((value & 0x00FF0000u) >> 8) |
           ((value & 0xFF000000u) >> 24);
}

extern "C"
{
    __declspec(dllimport) HANDLE __stdcall OpenFileMappingW(DWORD, BOOL, LPCWSTR);
    __declspec(dllimport) LPVOID __stdcall MapViewOfFile(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
    __declspec(dllimport) BOOL __stdcall UnmapViewOfFile(LPCVOID);
    __declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE);

    __declspec(dllimport) int __stdcall WSAStartup(unsigned short, WSADATA*);
    __declspec(dllimport) int __stdcall WSACleanup();
    __declspec(dllimport) SOCKET __stdcall socket(int, int, int);
    __declspec(dllimport) int __stdcall bind(SOCKET, const sockaddr*, int);
    __declspec(dllimport) int __stdcall listen(SOCKET, int);
    __declspec(dllimport) SOCKET __stdcall accept(SOCKET, sockaddr*, int*);
    __declspec(dllimport) int __stdcall recv(SOCKET, char*, int, int);
    __declspec(dllimport) int __stdcall send(SOCKET, const char*, int, int);
    __declspec(dllimport) int __stdcall shutdown(SOCKET, int);
    __declspec(dllimport) int __stdcall closesocket(SOCKET);

    __declspec(dllimport) BOOL __stdcall CryptAcquireContextW(HCRYPTPROV*, LPCWSTR, LPCWSTR, DWORD, DWORD);
    __declspec(dllimport) BOOL __stdcall CryptCreateHash(HCRYPTPROV, DWORD, std::uintptr_t, DWORD, HCRYPTHASH*);
    __declspec(dllimport) BOOL __stdcall CryptHashData(HCRYPTHASH, const BYTE*, DWORD, DWORD);
    __declspec(dllimport) BOOL __stdcall CryptGetHashParam(HCRYPTHASH, DWORD, BYTE*, DWORD*, DWORD);
    __declspec(dllimport) BOOL __stdcall CryptDestroyHash(HCRYPTHASH);
    __declspec(dllimport) BOOL __stdcall CryptReleaseContext(HCRYPTPROV, DWORD);
    __declspec(dllimport) BOOL __stdcall CryptBinaryToStringA(const BYTE*, DWORD, DWORD, char*, DWORD*);
}

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Advapi32.lib")

namespace
{
    constexpr const wchar_t* kPhysicsMappingName = L"Local\\acpmf_physics";
    constexpr const wchar_t* kGraphicsMappingName = L"Local\\acpmf_graphics";
    constexpr const wchar_t* kStaticMappingName = L"Local\\acpmf_static";
    constexpr std::uint16_t kWebSocketPort = 8081;
    constexpr std::string_view kWebSocketGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    std::string Trim(std::string value)
    {
        const auto first = value.find_first_not_of(" \t\r\n");
        if (first == std::string::npos)
        {
            return {};
        }

        const auto last = value.find_last_not_of(" \t\r\n");
        return value.substr(first, last - first + 1);
    }
}

struct TelemetrySnapshot
{
    // ===== Physics =====
    int packetId = 0;

    float throttle = 0.0f;
    float brake = 0.0f;

    float fuel = 0.0f;
    float fuelPerLap = 0.0f;

    int gear = 0;
    int rpm = 0;

    float steerAngle = 0.0f;
    float speedKmh = 0.0f;

    // ===== Graphics =====

    int currentLap = 0;
    int position = 0;

    std::string currentLapTime;
    std::string lastLapTime;
    std::string bestLapTime;

    bool isInPit = false;
    bool isInPitLane = false;

    int flag = 0;

    int rainIntensity = 0;
    int trackGripStatus = 0;
    float idealLineGrip = 0.0f;

    // ===== Static =====

    float trackLength = 0.0f;
    float maxFuel = 0.0f;

    bool connected = false;

    std::string ToJson() const
    {
        std::ostringstream oss;

        oss << "{";

        oss << "\"packetId\":" << packetId << ",";
        oss << "\"throttle\":" << throttle << ",";
        oss << "\"brake\":" << brake << ",";
        oss << "\"fuel\":" << fuel << ",";
        oss << "\"fuelPerLap\":" << fuelPerLap << ",";

        oss << "\"gear\":" << gear << ",";
        oss << "\"rpm\":" << rpm << ",";
        oss << "\"steerAngle\":" << steerAngle << ",";
        oss << "\"speedKmh\":" << speedKmh << ",";

        oss << "\"lap\":" << currentLap << ",";
        oss << "\"position\":" << position << ",";

        oss << "\"currentLapTime\":\"" << currentLapTime << "\",";
        oss << "\"lastLapTime\":\"" << lastLapTime << "\",";
        oss << "\"bestLapTime\":\"" << bestLapTime << "\",";

        oss << "\"isInPit\":" << (isInPit ? "true" : "false") << ",";
        oss << "\"isInPitLane\":" << (isInPitLane ? "true" : "false") << ",";

        oss << "\"flag\":" << flag << ",";
        oss << "\"rainIntensity\":" << rainIntensity << ",";
        oss << "\"trackGripStatus\":" << trackGripStatus << ",";
        oss << "\"idealLineGrip\":" << idealLineGrip << ",";

        oss << "\"trackLength\":" << trackLength << ",";
        oss << "\"maxFuel\":" << maxFuel << ",";

        oss << "\"connected\":" << (connected ? "true" : "false");

        oss << "}";

        return oss.str();
    }
};

struct StrategyAdvice
{
    bool pitRecommended = false;
    int estimatedLapsRemaining = 0;
    std::string summary;
};

struct TelemetryFrame
{
    TelemetrySnapshot telemetry;
    StrategyAdvice strategy;

    std::string ToJson() const
    {
        std::ostringstream oss;
        oss << "{";
        oss << "\"telemetry\":" << telemetry.ToJson() << ",";
        oss << "\"strategy\":{";
        oss << "\"pitRecommended\":" << (strategy.pitRecommended ? "true" : "false") << ",";
        oss << "\"estimatedLapsRemaining\":" << strategy.estimatedLapsRemaining << ",";
        oss << "\"summary\":\"" << strategy.summary << "\"";
        oss << "}";
        oss << "}";
        return oss.str();
    }
};

class SharedMemoryReader
{
public:
    SharedMemoryReader()
        : startTime_(std::chrono::steady_clock::now())
    {
    }

    ~SharedMemoryReader()
    {
        if (physicsView_ != nullptr)
        {
            UnmapViewOfFile(physicsView_);
            physicsView_ = nullptr;
        }

        if (physicsMapping_ != nullptr)
        {
            CloseHandle(physicsMapping_);
            physicsMapping_ = nullptr;
        }
    }

    bool Connect()
    {
        if (connected_)
        {
            return true;
        }

        physicsMapping_ = OpenFileMappingW(FILE_MAP_READ, FALSE, kPhysicsMappingName);
        if (physicsMapping_ == nullptr)
        {
            return false;
        }

        physicsView_ = static_cast<PhysicsView*>(MapViewOfFile(physicsMapping_, FILE_MAP_READ, 0, 0, sizeof(PhysicsView)));
        if (physicsView_ == nullptr)
        {
            CloseHandle(physicsMapping_);
            physicsMapping_ = nullptr;
            return false;
        }

        connected_ = true;
        return true;
    }

    TelemetrySnapshot ReadSnapshot()
    {
        if (!connected_ && !Connect())
        {
            return CreateFallbackSnapshot();
        }

        if (physicsView_ == nullptr)
        {
            return CreateFallbackSnapshot();
        }

        TelemetrySnapshot snapshot;
        snapshot.packetId = physicsView_->packetId;
        snapshot.throttle = physicsView_->gas;
        snapshot.brake = physicsView_->brake;
        snapshot.fuel = physicsView_->fuel;
        snapshot.gear = physicsView_->gear;
        snapshot.rpm = physicsView_->rpm;
        snapshot.steerAngle = physicsView_->steerAngle;
        snapshot.speedKmh = physicsView_->speedKmh;
        snapshot.connected = true;
        return snapshot;
    }

private:
    struct PhysicsView
    {
        int packetId;
        float gas;
        float brake;
        float fuel;
        int gear;
        int rpm;
        float steerAngle;
        float speedKmh;
    };

    struct ACCPhysics
    {
        int packetId;

        float gas;
        float brake;
        float fuel;

        int gear;
        int rpm;

        float steerAngle;

        float speedKmh;

        float fuelXLap;
    };

    struct GraphicsView
    {
        int packetId;

        int status;

        int session;

        char currentTime[32];

        char lastTime[32];

        char bestTime[32];

        int completedLaps;

        int position;

        int isInPit;

        int isInPitLane;

        int flag;
    };

    struct StaticView
    {
        float trackLength;
        float maxFuel;
    };

    TelemetrySnapshot CreateFallbackSnapshot() const
    {
        using namespace std::chrono;

        const auto elapsed = duration_cast<duration<float>>(steady_clock::now() - startTime_).count();
        TelemetrySnapshot snapshot;
        snapshot.packetId = static_cast<int>(elapsed * 20.0f);
        snapshot.throttle = (std::sin(elapsed) + 1.0f) * 0.5f;
        snapshot.brake = (std::cos(elapsed * 0.7f) + 1.0f) * 0.15f;
        snapshot.fuel = 60.0f - elapsed * 0.05f;
        snapshot.gear = static_cast<int>(elapsed) % 6 + 1;
        snapshot.rpm = 3500 + static_cast<int>(std::sin(elapsed * 2.0f) * 1200.0f);
        snapshot.steerAngle = std::sin(elapsed * 1.8f) * 0.3f;
        snapshot.speedKmh = 80.0f + std::sin(elapsed * 0.9f) * 25.0f;
        snapshot.connected = false;
        return snapshot;
    }
    HANDLE physicsMapping_ = nullptr;
    HANDLE graphicsMapping_ = nullptr;

    PhysicsView* physicsView_ = nullptr;
    GraphicsView* graphicsView_ = nullptr;

    bool connected_ = false;
    mutable std::chrono::steady_clock::time_point startTime_;
};

class TelemetryService
{
public:
    TelemetryService()
    {
        reader_.Connect();
    }

    TelemetryFrame Sample()
    {
        TelemetryFrame frame;
        frame.telemetry = reader_.ReadSnapshot();
        frame.strategy = BuildStrategy(frame.telemetry);
        return frame;
    }

private:
    StrategyAdvice BuildStrategy(const TelemetrySnapshot& snapshot) const
    {
        StrategyAdvice advice;
        advice.estimatedLapsRemaining = snapshot.fuel > 0.0f ? static_cast<int>(snapshot.fuel / 2.7f) : 0;

        if (snapshot.fuel < 10.0f)
        {
            advice.pitRecommended = true;
            advice.summary = "Fuel low: pit window is open.";
        }
        else if (snapshot.brake > 0.65f)
        {
            advice.pitRecommended = true;
            advice.summary = "High brake usage detected. Check tire and brake condition.";
        }
        else
        {
            advice.summary = "Telemetry stable. Maintain pace.";
        }

        return advice;
    }

    SharedMemoryReader reader_;
};

class WebSocketServer
{
public:
    WebSocketServer()
    {
        WSADATA data{};
        WSAStartup(MakeWord(2, 2), &data);
    }

    ~WebSocketServer()
    {
        Stop();
        WSACleanup();
    }

    bool Start(std::uint16_t port)
    {
        if (running_)
        {
            return true;
        }

        listenSocket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSocket_ == INVALID_SOCKET)
        {
            return false;
        }

        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        address.sin_addr.s_addr = htonl(INADDR_ANY);

        if (bind(listenSocket_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR)
        {
            closesocket(listenSocket_);
            listenSocket_ = INVALID_SOCKET;
            return false;
        }

        if (listen(listenSocket_, SOMAXCONN) == SOCKET_ERROR)
        {
            closesocket(listenSocket_);
            listenSocket_ = INVALID_SOCKET;
            return false;
        }

        running_ = true;
        acceptThread_ = std::thread(&WebSocketServer::AcceptLoop, this);
        return true;
    }

    void Stop()
    {
        running_ = false;

        if (listenSocket_ != INVALID_SOCKET)
        {
            shutdown(listenSocket_, SD_BOTH);
            closesocket(listenSocket_);
            listenSocket_ = INVALID_SOCKET;
        }

        if (acceptThread_.joinable())
        {
            acceptThread_.join();
        }

        std::lock_guard<std::mutex> lock(clientsMutex_);
        for (SOCKET client : clients_)
        {
            shutdown(client, SD_BOTH);
            closesocket(client);
        }
        clients_.clear();
    }

    void Broadcast(const std::string& message)
    {
        const std::string frame = BuildTextFrame(message);
        std::lock_guard<std::mutex> lock(clientsMutex_);

        auto it = clients_.begin();
        while (it != clients_.end())
        {
            const int sent = send(*it, frame.data(), static_cast<int>(frame.size()), 0);
            if (sent == SOCKET_ERROR)
            {
                shutdown(*it, SD_BOTH);
                closesocket(*it);
                it = clients_.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }

private:
    void AcceptLoop()
    {
        while (running_)
        {
            sockaddr_in clientAddress{};
            int clientSize = sizeof(clientAddress);
            SOCKET clientSocket = accept(listenSocket_, reinterpret_cast<sockaddr*>(&clientAddress), &clientSize);
            if (clientSocket == INVALID_SOCKET)
            {
                if (running_)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                }
                continue;
            }

            if (HandleClient(clientSocket))
            {
                std::lock_guard<std::mutex> lock(clientsMutex_);
                clients_.push_back(clientSocket);
            }
            else
            {
                shutdown(clientSocket, SD_BOTH);
                closesocket(clientSocket);
            }
        }
    }

    bool HandleClient(SOCKET clientSocket)
    {
        std::string request;
        request.reserve(2048);

        std::array<char, 1024> buffer{};
        while (request.find("\r\n\r\n") == std::string::npos)
        {
            const int received = recv(clientSocket, buffer.data(), static_cast<int>(buffer.size()), 0);
            if (received <= 0)
            {
                return false;
            }

            request.append(buffer.data(), received);
            if (request.size() > 8192)
            {
                return false;
            }
        }

        const std::string headerKey = "Sec-WebSocket-Key:";
        const auto keyPosition = request.find(headerKey);
        if (keyPosition == std::string::npos)
        {
            return false;
        }

        const auto lineEnd = request.find("\r\n", keyPosition);
        const auto keyValue = request.substr(keyPosition + headerKey.size(), lineEnd - (keyPosition + headerKey.size()));
        const std::string acceptKey = ComputeAcceptKey(Trim(keyValue));

        std::ostringstream response;
        response << "HTTP/1.1 101 Switching Protocols\r\n"
                 << "Upgrade: websocket\r\n"
                 << "Connection: Upgrade\r\n"
                 << "Sec-WebSocket-Accept: " << acceptKey << "\r\n\r\n";

        const std::string responseText = response.str();
        return send(clientSocket, responseText.data(), static_cast<int>(responseText.size()), 0) != SOCKET_ERROR;
    }

    static std::string ComputeAcceptKey(const std::string& clientKey)
    {
        const std::string input = clientKey + std::string(kWebSocketGuid);

        HCRYPTPROV cryptoProvider = 0;
        HCRYPTHASH hash = 0;
        std::array<BYTE, 20> hashBytes{};
        DWORD hashLength = static_cast<DWORD>(hashBytes.size());

        if (!CryptAcquireContextW(&cryptoProvider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        {
            return {};
        }

        if (!CryptCreateHash(cryptoProvider, CALG_SHA1, 0, 0, &hash))
        {
            CryptReleaseContext(cryptoProvider, 0);
            return {};
        }

        CryptHashData(hash, reinterpret_cast<const BYTE*>(input.data()), static_cast<DWORD>(input.size()), 0);
        CryptGetHashParam(hash, HP_HASHVAL, hashBytes.data(), &hashLength, 0);

        DWORD base64Size = 0;
        CryptBinaryToStringA(hashBytes.data(), hashLength, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &base64Size);
        std::string result(base64Size, '\0');
        CryptBinaryToStringA(hashBytes.data(), hashLength, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, result.data(), &base64Size);
        if (!result.empty() && result.back() == '\0')
        {
            result.pop_back();
        }

        CryptDestroyHash(hash);
        CryptReleaseContext(cryptoProvider, 0);
        return result;
    }

    static std::string BuildTextFrame(const std::string& message)
    {
        std::string frame;
        frame.reserve(message.size() + 10);
        frame.push_back(static_cast<char>(0x81));

        const std::size_t size = message.size();
        if (size <= 125)
        {
            frame.push_back(static_cast<char>(size));
        }
        else if (size <= 65535)
        {
            frame.push_back(static_cast<char>(126));
            frame.push_back(static_cast<char>((size >> 8) & 0xFF));
            frame.push_back(static_cast<char>(size & 0xFF));
        }
        else
        {
            frame.push_back(static_cast<char>(127));
            for (int shift = 56; shift >= 0; shift -= 8)
            {
                frame.push_back(static_cast<char>((size >> shift) & 0xFF));
            }
        }

        frame.append(message);
        return frame;
    }

    std::atomic<bool> running_{false};
    SOCKET listenSocket_ = INVALID_SOCKET;
    std::thread acceptThread_;
    std::mutex clientsMutex_;
    std::vector<SOCKET> clients_;
};

int main()
{
    TelemetryService telemetryService;
    WebSocketServer server;

    if (!server.Start(kWebSocketPort))
    {
        std::cerr << "WebSocket server failed to start." << std::endl;
        return 1;
    }

    std::cout << "ACC bridge started on ws://localhost:" << kWebSocketPort << std::endl;

    while (true)
    {
        const TelemetryFrame frame = telemetryService.Sample();
        const std::string payload = frame.ToJson();
        server.Broadcast(payload);
        std::cout << payload << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}
