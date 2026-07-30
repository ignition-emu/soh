#include "IgnitionSetup.h"
#include "Extractor/Extract.h"
#include <atomic>
#include <filesystem>
#include <cstdio>
#include <string>

#ifdef _WIN32
#include <Windows.h>
#else
#include <cstdlib>
#include <unistd.h>
#include <limits.h>
#endif

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

// Get the directory containing the running executable without depending on
// libultraship Context (which may not be initialized yet). This is where
// assets/ and the ZAPD extractor live, and inside an AppImage or an .app bundle
// it is read-only.
static std::string GetExeDirectory() {
#ifdef _WIN32
    char buf[MAX_PATH];
    DWORD len = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    if (len > 0 && len < MAX_PATH) {
        return std::filesystem::path(buf).parent_path().string();
    }
#elif defined(__APPLE__)
    // macOS has no /proc; ask dyld where we were loaded from.
    char buf[PATH_MAX];
    uint32_t size = sizeof(buf);
    if (_NSGetExecutablePath(buf, &size) == 0) {
        std::error_code ec;
        auto resolved = std::filesystem::weakly_canonical(std::filesystem::path(buf), ec);
        if (!ec) {
            return resolved.parent_path().string();
        }
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

// Where generated files must land. Normally that is next to the executable, but
// an AppImage runs from a read-only squashfs mount, so /proc/self/exe points
// somewhere unwritable and nothing Ignition can see. AppImage exports APPIMAGE
// as the absolute path of the .AppImage file itself, and Ignition installs that
// file into the directory it later searches for oot.o2r.
static std::string GetOutputDirectory() {
#ifndef _WIN32
    if (const char* appImage = std::getenv("APPIMAGE"); appImage != nullptr && appImage[0] != '\0') {
        return std::filesystem::path(appImage).parent_path().string();
    }
#endif
    return GetExeDirectory();
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

    // installPath = where assets/ (incl. the ZAPD extractor) lives; may be
    // read-only when packaged. exportDir = where the OTR must be written, which
    // is the directory Ignition searches next to the binary it launched.
    std::string installPath = GetExeDirectory();
    std::string exportDir = GetOutputDirectory();

    if (!std::filesystem::exists(installPath + "/assets")) {
        // In a macOS .app the binary sits in Contents/MacOS while CMake installs
        // assets under Contents/Resources, so look one level over before giving up.
        std::string resources =
            (std::filesystem::path(installPath).parent_path() / "Resources").string();
        if (std::filesystem::exists(resources + "/assets")) {
            installPath = resources;
        } else {
            fprintf(stderr, "ignition-extract: missing 'assets/' folder at %s\n", installPath.c_str());
            return 1;
        }
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
