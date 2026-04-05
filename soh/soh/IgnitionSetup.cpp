#include "IgnitionSetup.h"
#include "Extractor/Extract.h"
#include <atomic>
#include <filesystem>
#include <cstdio>
#include <string>

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#include <limits.h>
#endif

// Get the directory containing the running executable without depending on
// libultraship Context (which may not be initialized yet).
static std::string GetExeDirectory() {
#ifdef _WIN32
    char buf[MAX_PATH];
    DWORD len = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    if (len > 0 && len < MAX_PATH) {
        return std::filesystem::path(buf).parent_path().string();
    }
#else
    char buf[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len > 0) {
        buf[len] = '\0';
        return std::filesystem::path(buf).parent_path().string();
    }
#endif
    // Fallback: current working directory
    return std::filesystem::current_path().string();
}

extern "C" int SohIgnitionExtract(const char* romPath) {
    if (romPath == nullptr || romPath[0] == '\0') {
        fprintf(stderr, "ignition-extract: no ROM path provided\n");
        return 1;
    }

    if (!std::filesystem::exists(romPath)) {
        fprintf(stderr, "ignition-extract: ROM file not found: %s\n", romPath);
        return 1;
    }

    // installPath = where soh.exe and assets/ live
    std::string installPath = GetExeDirectory();
    // exportDir = where the OTR file should be written — same as install dir
    // so Ignition can find it next to soh.exe
    std::string exportDir = installPath;

    if (!std::filesystem::exists(installPath + "/assets")) {
        fprintf(stderr, "ignition-extract: missing 'assets/' folder at %s\n", installPath.c_str());
        return 1;
    }

    Extractor extract;
    if (!extract.RunFileStandalone(std::string(romPath))) {
        fprintf(stderr, "ignition-extract: ROM validation failed for %s\n", romPath);
        return 1;
    }

    std::atomic<size_t> extractCount = 0, totalExtract = 0;
    extract.CallZapd(installPath, exportDir, &extractCount, &totalExtract);

    std::string otrFile = extract.IsMasterQuest() ? "oot-mq.o2r" : "oot.o2r";
    std::string otrPath = exportDir + "/" + otrFile;
    if (!std::filesystem::exists(otrPath)) {
        fprintf(stderr, "ignition-extract: extraction completed but %s was not produced\n", otrFile.c_str());
        return 1;
    }

    fprintf(stdout, "ignition-extract: successfully generated %s\n", otrPath.c_str());
    return 0;
}
