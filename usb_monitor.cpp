
#include <iostream>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <chrono>
#include <thread>
#include <map>
#include <cstdlib>
#include <unistd.h>
#include <sys/inotify.h>
#include <limits.h>
#include <yara.h>
#include <openssl/evp.h>

namespace fs = std::filesystem;
using namespace std::chrono;

static const std::string pathToAGLRootDirectory        = "/var/lib/av";
static const std::string pathToQuarantineBaseFolder   = pathToAGLRootDirectory + "/quarantine";
static const std::string pathToRestoredFiles         = pathToAGLRootDirectory + "/restored_allow.csv";
static const std::string pathToManifestFile      = pathToAGLRootDirectory + "/quarantine_manifest.csv";
static const std::string kDefaultLogPath   = "/var/log/av/usb_monitor.log";

static bool directoryCheck(const std::string& p) {
    std::error_code ec;
    return fs::exists(p, ec) && fs::is_directory(p, ec);
}

static void aglBootDirectoryCheck() {
    std::error_code ec;
    fs::create_directories(pathToAGLRootDirectory, ec);
    fs::create_directories(pathToQuarantineBaseFolder, ec);
    fs::create_directories("/var/log/av", ec);
    (void)ec;
}

static std::string setPathFormat(const std::string& p) {
    std::error_code ec;
    fs::path ph(p);
    fs::path canon = fs::weakly_canonical(ph, ec);
    if (!ec && !canon.empty()) return canon.string();
    fs::path abs = fs::absolute(ph, ec);
    return (!ec && !abs.empty()) ? abs.string() : p;
}


static std::string hashGenerator(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    unsigned char md[EVP_MAX_MD_SIZE]; unsigned int md_len = 0;
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    char buf[8192];
    while (f.good()) { f.read(buf, sizeof(buf)); std::streamsize got = f.gcount();
        if (got > 0) EVP_DigestUpdate(ctx, buf, (size_t)got); }
    EVP_DigestFinal_ex(ctx, md, &md_len);
    EVP_MD_CTX_free(ctx);
    std::ostringstream os; os << std::hex << std::setfill('0');
    for (unsigned i=0;i<md_len;++i) os << std::setw(2) << (int)md[i];
    return os.str();
}


static bool restoreCheck(const std::string& file) {
    const std::string p = setPathFormat(file);
    const std::string h = hashGenerator(p);
    if (h.empty()) return false;

    const std::string base = fs::path(p).filename().string();

    std::ifstream in{pathToRestoredFiles};
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        auto c = line.find(',');
        if (c == std::string::npos) continue;

        std::string ap = setPathFormat(line.substr(0, c));
        std::string ah = line.substr(c + 1);

        if ((ap == p && ah == h) ||
            (fs::path(ap).filename().string() == base && ah == h)) {
            std::cout << "[ALLOW] Persistent allow matched: " << p << "\n";
            return true; // DO NOT remove the entry
        }
    }
    return false;
}

static void quarantine_file(const std::string& filepath, const std::string& rule_name) {
    aglBootDirectoryCheck();
    auto now_c = std::time(nullptr);
    std::tm* tm = std::localtime(&now_c);
    std::ostringstream ts; ts << std::put_time(tm, "%Y%m%d_%H%M%S");
    std::string stamp = ts.str();

    fs::path src = filepath;
    fs::path dst = fs::path(pathToQuarantineBaseFolder) / (src.filename().string() + "_" + stamp);
    std::error_code ec;

    fs::rename(src, dst, ec);
    if (ec == std::errc::cross_device_link) {
        ec.clear();
        fs::copy_file(src, dst, fs::copy_options::overwrite_existing, ec);
        if (!ec) fs::remove(src, ec);
    }

    if (!ec) {
        fs::permissions(dst, fs::perms::owner_read, fs::perm_options::replace, ec);
        std::ofstream mf(pathToManifestFile, std::ios::app);
        mf << stamp << ',' << rule_name << ',' << filepath << ',' << dst.string() << ",quarantined\n";
        std::cout << "[QUARANTINED] " << rule_name << " -> " << dst.string() << "\n";
    } else {
        std::cerr << "[ERROR] quarantine failed for " << filepath << " (" << ec.message() << ")\n";
    }
}

struct YaraCtx {
    YR_RULES* rules = nullptr;
    ~YaraCtx(){ if (rules) yr_rules_destroy(rules); yr_finalize(); }
};

static void compiler_cb(int error_level,
                        const char* file_name,
                        int line_number,
                        const YR_RULE* rule,        
                        const char* message,
                        void* /*user_data*/) {
    const char* lvl = (error_level == YARA_ERROR_LEVEL_ERROR) ? "ERROR" : "WARN";
    const char* rid = (rule && rule->identifier) ? rule->identifier : nullptr;
    std::cerr << "[YARA " << lvl << "] "
              << (file_name ? file_name : "<rules>") << ":" << line_number
              << (rid ? std::string(" (rule: ") + rid + ")" : "")
              << ": " << (message ? message : "") << "\n";
}

static bool yara_init_once(const std::string& rulefile, YaraCtx& ctx) {
    if (yr_initialize() != ERROR_SUCCESS) { std::cerr << "[ERROR] YARA init failed\n"; return false; }
    YR_COMPILER* comp = nullptr;
    if (yr_compiler_create(&comp) != ERROR_SUCCESS) { std::cerr << "[ERROR] YARA compiler create\n"; return false; }
    yr_compiler_set_callback(comp, compiler_cb, nullptr);
    FILE* rf = fopen(rulefile.c_str(), "r");
    if (!rf) { std::cerr << "[ERROR] Cannot open rule file: " << rulefile << "\n"; yr_compiler_destroy(comp); return false; }
    int errs = yr_compiler_add_file(comp, rf, nullptr, rulefile.c_str());
    fclose(rf);
    if (errs != 0) { std::cerr << "[ERROR] YARA compiler errors in rules (" << errs << ")\n"; yr_compiler_destroy(comp); return false; }
    if (yr_compiler_get_rules(comp, &ctx.rules) != ERROR_SUCCESS) {
        std::cerr << "[ERROR] YARA get_rules\n"; yr_compiler_destroy(comp); return false;
    }
    yr_compiler_destroy(comp);
    return true;
}

struct ScanResult { std::string file; std::vector<std::string> rules; };
static int yara_cb(YR_SCAN_CONTEXT*, int msg, void* msg_data, void* usr) {
    if (msg == CALLBACK_MSG_RULE_MATCHING) {
        auto* rule = static_cast<YR_RULE*>(msg_data);
        auto* sr   = static_cast<ScanResult*>(usr);
        sr->rules.emplace_back(rule->identifier);
    }
    return CALLBACK_CONTINUE;
}

static void scan_file_with_rules(YaraCtx& yc, const std::string& filepath) {
    ScanResult sr{ filepath, {} };
    yr_rules_scan_file(yc.rules, filepath.c_str(), 0, yara_cb, &sr, 0);
if (!sr.rules.empty()) {
    if (restoreCheck(filepath)) {
        std::cout << "[MATCHED] (allowed) " << sr.rules.front()
                  << " in " << filepath << " -> skip quarantine\n";
    } else {
        quarantine_file(filepath, sr.rules.front());
    }
}

}
static void scan_directory_yara(YaraCtx& yc, const fs::path& dir) {
    try {
        fs::recursive_directory_iterator it(dir, fs::directory_options::skip_permission_denied), end;
        for (; it != end; ++it) {
            const auto& entry = *it;
            auto name = entry.path().filename().string();
            if (entry.is_directory() &&
                (name == "System Volume Information" || name == "lost+found" || (!name.empty() && name.front()=='.'))) {
                it.disable_recursion_pending();
                continue;
            }
            if (entry.is_regular_file()) {
                scan_file_with_rules(yc, entry.path().string());
            }
        }
    } catch (const fs::filesystem_error& e) {
        std::cerr << "[WARN] scan_directory_yara: " << e.what() << "\n";
    }
}

static std::string pick_watch_dir(std::string cli, const char* env) {
    if (!cli.empty() && directoryCheck(cli)) return cli;
    if (env && *env && directoryCheck(env)) return env;
    if (const char* su = std::getenv("SUDO_USER")) {
        for (auto& d : {"/run/media/" + std::string(su), "/media/" + std::string(su)}) if (directoryCheck(d)) return d;
    }
    if (const char* u = std::getenv("USER")) {
        for (auto& d : {"/run/media/" + std::string(u), "/media/" + std::string(u)}) if (directoryCheck(d)) return d;
    }
    if (directoryCheck("/run/media")) return "/run/media";
    if (directoryCheck("/media"))     return "/media";
    std::error_code ec;
    fs::create_directories("/media/root", ec);
    return "/media/root";
}

static void monitor_usb_and_scan(const std::string& rulefile, const std::string& watch_dir) {
    aglBootDirectoryCheck();

    YaraCtx yc;
    if (!yara_init_once(rulefile, yc)) return;

    int fd = inotify_init1(IN_NONBLOCK);
    if (fd < 0) { perror("inotify_init1"); return; }

    const uint32_t base_mask = IN_CREATE | IN_MOVED_TO;
    const uint32_t file_mask = IN_CLOSE_WRITE | IN_MOVED_TO;

    int wd_base = inotify_add_watch(fd, watch_dir.c_str(), base_mask);
    if (wd_base < 0) { perror("inotify_add_watch"); close(fd); return; }

    std::map<int, std::string> wd2path; wd2path[wd_base] = watch_dir;
    std::cout << "[USB Monitor] Watching mounts at: " << watch_dir << "\n";

    for (auto& entry : fs::directory_iterator(watch_dir)) {
        if (entry.is_directory()) {
            std::string mount = entry.path().string();
            std::cout << "[BOOTSTRAP] scanning existing: " << mount << "\n";
            scan_directory_yara(yc, mount);
            int wd = inotify_add_watch(fd, mount.c_str(), file_mask);
            if (wd >= 0) { wd2path[wd] = mount; std::cout << "[USB Monitor] Watching files in: " << mount << "\n"; }
        }
    }

    const size_t buf_len = 1024 * (sizeof(inotify_event) + NAME_MAX + 1);
    std::vector<char> buffer(buf_len);

    while (true) {
        ssize_t len = read(fd, buffer.data(), buf_len);
        if (len <= 0) { std::this_thread::sleep_for(milliseconds(200)); continue; }

        size_t i = 0;
        while (i < (size_t)len) {
            auto* ev = reinterpret_cast<inotify_event*>(&buffer[i]);
            std::string parent = wd2path.count(ev->wd) ? wd2path[ev->wd] : "";

            if (ev->len) {
                std::string full = parent.empty() ? "" : (parent + "/" + ev->name);

                // New mount directory (created or moved into the base)
                if ((ev->mask & (IN_CREATE | IN_MOVED_TO)) && (ev->mask & IN_ISDIR) && parent == watch_dir) {
                    std::cout << "[USB Monitor] USB mount: " << full << "\n";
                    scan_directory_yara(yc, full);
                    int wd = inotify_add_watch(fd, full.c_str(), file_mask);
                    if (wd >= 0) { wd2path[wd] = full; std::cout << "[USB Monitor] Watching files in: " << full << "\n"; }
                }
                // File events under a mount (only when writes complete or file moved in)
                else if (parent != watch_dir && !(ev->mask & IN_ISDIR) &&
                         (ev->mask & (IN_CLOSE_WRITE | IN_MOVED_TO)) && !full.empty()) {
                    std::string np = setPathFormat(full);
                    std::cout << "[USB Monitor] File event: " << np << "\n";
                    std::error_code fec;
                    if (fs::exists(np, fec) && fs::is_regular_file(np, fec))
                        scan_file_with_rules(yc, np);
                }
            }
            i += sizeof(inotify_event) + ev->len;
        }
    }
}

static void usage(const char* prog) {
    std::cerr << "Usage: " << prog << " <rules.yar> [watch_dir]\n"
              << "   or: " << prog << " --rules <rules.yar> [--watch <dir>] [--log <file>]\n";
}

struct Args {
    std::string rules;
    std::string watch;
    std::string log = kDefaultLogPath; // kept for future use; logs currently via stdout/stderr
};

static Args parse_args(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        if ((s == "--rules" || s == "-r") && i+1 < argc)      a.rules = argv[++i];
        else if ((s == "--watch" || s == "-w") && i+1 < argc) a.watch = argv[++i];
        else if ((s == "--log"   || s == "-l") && i+1 < argc) a.log   = argv[++i];
        else if (a.rules.empty()) a.rules = s;     // positional 1
        else if (a.watch.empty()) a.watch = s;     // positional 2
        else { std::cerr << "Unknown arg: " << s << "\n"; usage(argv[0]); std::exit(1); }
    }
    if (a.rules.empty()) { usage(argv[0]); std::exit(1); }
    aglBootDirectoryCheck();
    std::error_code ec;
    fs::create_directories(fs::path(a.log).parent_path(), ec);
    a.watch = pick_watch_dir(a.watch, std::getenv("AV_WATCH_DIR"));
    return a;
}

int main(int argc, char* argv[]) {
    Args args = parse_args(argc, argv);

    std::error_code ec;
    if (!fs::exists(args.watch, ec) || !fs::is_directory(args.watch, ec)) {
        std::cerr << "[ERROR] Watch dir not found or not a directory: " << args.watch << "\n";
        return 1;
    }
    monitor_usb_and_scan(args.rules, args.watch);
    return 0;
}
