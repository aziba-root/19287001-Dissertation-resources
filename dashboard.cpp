
#include "crow.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <map>
#include <vector>
#include <array>
#include <mutex>
#include <chrono>
#include <ctime>
#include <cstdlib>     
#include <openssl/evp.h>

namespace fs = std::filesystem;


static const fs::path pathToManifestFile = "/var/lib/av/quarantine_manifest.csv";
static const fs::path pathToQuarantine = "/var/lib/av/quarantine";
static const fs::path pathToRestoredFiles = "/var/lib/av/restored_allow.csv";

static std::mutex g_manifest_mu;

struct RuleInfo { const char* desc; const char* severity; };
static const std::map<std::string, RuleInfo> kRuleMap = {
    {"AV_ReverseShell_IVI",      {"IVI Python Reverse Shell Detected", "high"}},
    {"AV_Firmware_Tamper",       {"Unauthorized Firmware Tampering",    "high"}},
    {"AV_Config_Manipulation",   {"Malicious Config/Map Injection",     "medium"}},
    {"AV_CANDiagnostics_Abuse",  {"CAN Diagnostics Command Abuse",      "medium"}},
    {"AV_OTA_ExternalFetch",     {"OTA External URL Download",          "high"}},
    {"AV_HighLevel_File_Access", {"High-Level File Access Attempt",     "high"}},
    {"AV_Command_Injection",     {"Script Command Injection",           "medium"}},
    {"AV_Autorun_Inf",           {"Windows autorun.inf Presence",       "low"}},
    {"AV_CAN_Exfiltration",      {"CAN-Bus Exfiltration Pattern",       "high"}},
};

struct Row {
    std::string stamp, rule, original, quarantine, status;
};

static std::string timestampLayout(const std::string& ts) {
    std::tm tm{}; std::istringstream ss(ts);
    ss >> std::get_time(&tm, "%Y%m%d_%H%M%S");
    if (ss.fail()) return ts;
    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return out.str();
}
static std::string pathDirectory(const std::string& p) {
    try { return fs::path(p).filename().string(); }
    catch (...) { return p; }
}
static std::string fileHashing(const fs::path& path) {
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
static std::string timeStamp() {
    std::time_t t = std::time(nullptr);
    std::tm* tm = std::localtime(&t);
    std::ostringstream ts; ts << std::put_time(tm, "%Y%m%d_%H%M%S");
    return ts.str();
}

static std::vector<Row> readFromManifestFile() {
    std::vector<Row> rows;
    std::ifstream in(pathToManifestFile);
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        std::array<std::string,5> f{};
        size_t start=0; int i=0;
        while (i<5) {
            size_t pos = line.find(',', start);
            if (pos == std::string::npos) pos = line.size();
            f[i++] = line.substr(start, pos-start);
            start = pos + (pos<line.size());
            if (pos==line.size()) break;
        }
        if (i==5) rows.push_back({f[0],f[1],f[2],f[3],f[4]});
    }
    return rows;
}
static void writetoManifestFile(const std::vector<Row>& rows) {
    fs::create_directories(pathToManifestFile.parent_path());
    const std::string tmp = pathToManifestFile.string() + ".tmp";
    {
        std::ofstream out(tmp, std::ios::trunc);
        for (auto& r : rows) {
            out << r.stamp << ',' << r.rule << ',' << r.original << ','
                << r.quarantine << ',' << r.status << '\n';
        }
    }
    fs::rename(tmp, pathToManifestFile);
}

static void restoreHash(const fs::path& original_path, const std::string& sha_hex) {
    std::error_code ec;
    fs::path abs = fs::weakly_canonical(original_path, ec);
    if (ec) abs = fs::absolute(original_path);
    if (sha_hex.empty()) return;
    fs::create_directories(pathToRestoredFiles.parent_path());
    std::ofstream out(pathToRestoredFiles, std::ios::app);
    out << abs.string() << ',' << sha_hex << '\n';
    out.flush();
}


static bool driveDetector(const std::string& p, std::string& label, std::string& mp) {
    std::error_code ec;
    fs::path ph = fs::weakly_canonical(fs::path(p), ec);
    if (ec) ph = fs::path(p);

    std::vector<std::string> parts;
    for (auto &comp : ph) parts.push_back(comp.string());
    if (parts.size() < 3) return false;
    if (!(parts[0] == "/" && parts[1] == "media")) return false;

    label = parts[2];
    mp = std::string("/media/") + label;
    return true;
}

static bool driveMountCheck(const std::string& mp, bool& ro_out) {
    ro_out = false;
    std::ifstream f("/proc/mounts");
    if (!f) return false;
    std::string dev, mnt, fstype, opts;
    std::string rest;
    while (f >> dev >> mnt >> fstype >> opts) {
        std::getline(f, rest);

        for (size_t pos = 0; (pos = mnt.find("\\040", pos)) != std::string::npos; ++pos)
            mnt.replace(pos, 4, " ");
        if (mnt == mp) {
            ro_out = (opts.find(",ro") != std::string::npos || opts.rfind("ro,",0)==0 || opts=="ro");
            return true;
        }
    }
    return false;
}

static bool driveRWCheck(const std::string& dest_path, std::string& why) {
    std::string label, mp;
    if (!driveDetector(dest_path, label, mp)) {
        return true;
    }

    bool ro = false;
    if (!driveMountCheck(mp, ro)) {

        std::error_code ec;
        fs::create_directories(mp, ec);

        std::ostringstream oss;
        oss << "sh -lc '"
            << "dev=$(blkid -L \"" << label << "\" 2>/dev/null); "
            << "fstype=\"\"; "
            << "[ -n \"$dev\" ] && fstype=$(blkid -o value -s TYPE \"$dev\" 2>/dev/null); "
            << "[ -z \"$fstype\" ] && fstype=vfat; "
            << "if [ -n \"$dev\" ]; then "
            << "  mount -t \"$fstype\" -o rw \"$dev\" \"" << mp << "\"; "
            << "else "
            << "  mount -t \"$fstype\" -o rw -L \"" << label << "\" \"" << mp << "\"; "
            << "fi "
            << "|| { "
            << "  if [ -z \"$dev\" ]; then dev=$(blkid -L \"" << label << "\" 2>/dev/null); fi; "
            << "  case \"$fstype\" in "
            << "    vfat)  command -v fsck.vfat  >/dev/null 2>&1 && fsck.vfat  -a -w \"$dev\" >/dev/null 2>&1 || true ;; "
            << "    exfat) command -v fsck.exfat >/dev/null 2>&1 && fsck.exfat -a    \"$dev\" >/dev/null 2>&1 || true ;; "
            << "    ntfs)  command -v ntfsfix    >/dev/null 2>&1 && ntfsfix         \"$dev\" >/dev/null 2>&1 || true ;; "
            << "    ext*)  fsck -t \"$fstype\" -a \"$dev\" >/dev/null 2>&1 || true ;; "
            << "    *) : ;; "
            << "  esac; "
            << "  if [ -n \"$dev\" ]; then "
            << "    mount -t \"$fstype\" -o rw \"$dev\" \"" << mp << "\"; "
            << "  else "
            << "    mount -t \"$fstype\" -o rw -L \"" << label << "\" \"" << mp << "\"; "
            << "  fi; "
            << "}'";

        (void)std::system(oss.str().c_str());

        if (!driveMountCheck(mp, ro)) {
            why = "destination device \"" + label + "\" not mounted";
            return false;
        }
    }

    if (ro) {
        std::ostringstream oss;
        oss << "sh -lc 'mount -o remount,rw \"" << mp << "\" || true'";
        (void)std::system(oss.str().c_str());

        bool ro2 = false;
        if (!driveMountCheck(mp, ro2) || ro2) {
            why = "destination device is read-only";
            return false;
        }
    }

    return true;
}

static bool fileRestoration(Row& r, std::string& err) {
    if (r.quarantine.empty()) { err = "no quarantine path"; return false; }

    std::error_code ec;

    fs::path src = pathToQuarantine / fs::path(r.quarantine).filename();

    fs::path dst_canon = fs::weakly_canonical(r.original, ec);
    fs::path dst = ec ? fs::path(r.original) : dst_canon;
    ec.clear();

    {
        std::string why;
        if (!driveRWCheck(dst.string(), why)) {
            err = "USB not ready: " + why;
            return false;
        }
    }

    if (!fs::exists(src)) { err = "quarantine file missing"; return false; }

    {
        std::string h = fileHashing(src);
        if (h.empty()) { err = "hash failed"; return false; }
        restoreHash(dst, h);
    }

    fs::create_directories(dst.parent_path(), ec); ec.clear();
    fs::rename(src, dst, ec);
    if (ec == std::errc::cross_device_link) {
        fs::copy_file(src, dst, fs::copy_options::overwrite_existing, ec);
        if (!ec) fs::remove(src, ec);
    }
    if (ec) { err = ec.message(); return false; }

    fs::permissions(dst,
        fs::perms::owner_read | fs::perms::owner_write,
        fs::perm_options::add, ec);

    r.status = "allowed";
    return true;
}


static int sendToQuarantine(std::string& msg) {
    auto rows = readFromManifestFile();
    int acted = 0;
    for (auto& r : rows) {
        if (r.status != "allowed") continue;

        std::string why;
        (void)driveRWCheck(r.original, why);

        fs::path src = r.original;
        if (!fs::exists(src)) continue;
        fs::create_directories(pathToQuarantine);
        fs::path dst = pathToQuarantine / (fs::path(src).filename().string() + "_" + timeStamp());
        std::error_code ec;
        fs::rename(src, dst, ec);
        if (ec == std::errc::cross_device_link) {
            fs::copy_file(src, dst, fs::copy_options::overwrite_existing, ec);
            if (!ec) fs::remove(src, ec);
        }
        if (!ec) {
            r.quarantine = dst.filename().string();
            r.status = "quarantined";
            ++acted;
        }
    }
    writetoManifestFile(rows);
    msg = "requarantined=" + std::to_string(acted);
    return acted;
}

int main() {
    crow::SimpleApp malwareDetector;

    CROW_ROUTE(malwareDetector, "/api/log").methods("GET"_method)
    ([] {
        std::lock_guard<std::mutex> lk(g_manifest_mu);
        auto rows = readFromManifestFile();

        crow::json::wvalue j = crow::json::wvalue::list();
        size_t idx = 0;
        for (auto& r : rows) {
            crow::json::wvalue row;
            row["stamp"]      = r.stamp;
            row["rule"]       = r.rule;
            row["original"]   = r.original;
            row["quarantine"] = r.quarantine;
            row["status"]     = r.status;
            j[idx++] = std::move(row);
        }
        return crow::response{j};
    });

    CROW_ROUTE(malwareDetector, "/api/restore").methods("POST"_method)
    ([](const crow::request& req){
        std::string q = req.url_params.get("quarantine") ? req.url_params.get("quarantine") : "";
        if (q.empty()) return crow::response(400, "missing quarantine param");

        std::lock_guard<std::mutex> lk(g_manifest_mu);
        auto rows = readFromManifestFile();
        std::string err; bool done=false;
        for (auto& r : rows) {
            if (r.quarantine == q) {
                if (!fileRestoration(r, err)) return crow::response(500, "restore failed: " + err);
                done=true; break;
            }
        }
        if (!done) return crow::response(404, "row not found");
        writetoManifestFile(rows);
        return crow::response(200, "ok");
    });

    CROW_ROUTE(malwareDetector, "/api/allowlist/clear").methods("POST"_method)
    ([]{
        fs::create_directories(pathToRestoredFiles.parent_path());
        std::ofstream out(pathToRestoredFiles, std::ios::trunc); 
        return crow::response(200, "cleared");
    });

    CROW_ROUTE(malwareDetector, "/api/requarantine-allowed").methods("POST"_method)
    ([]{
        std::lock_guard<std::mutex> lk(g_manifest_mu);
        std::string msg;
        sendToQuarantine(msg);
        return crow::response(200, msg);
    });

CROW_ROUTE(malwareDetector, "/quarantine_manifest.json")
([&]() {
    std::lock_guard<std::mutex> lk(g_manifest_mu);
    auto recs = readFromManifestFile();
    crow::json::wvalue items = crow::json::wvalue::list();
    size_t idx = 0;

    bool any_high = false;
    for (const auto& r : recs) {
        crow::json::wvalue row;
        row["time"] = timestampLayout(r.stamp);

        auto it = kRuleMap.find(r.rule);
        std::string severity = "medium";
        if (it != kRuleMap.end()) { row["rule"] = it->second.desc; severity = it->second.severity; }
        else { row["rule"] = r.rule; }
        row["severity"] = severity;

        std::string pretty = r.original;
        row["original"]        = r.original;
        row["original_pretty"] = pretty;

        row["quarantine"]       = r.quarantine;
        row["quarantine_label"] = pathDirectory(r.quarantine);
        row["status"]           = r.status;

        if (r.status == "quarantined" && severity == "high") any_high = true;
        items[idx++] = std::move(row);
    }

    crow::json::wvalue resp;
    resp["items"] = std::move(items);
    resp["meta"]["any_high"] = any_high;
    return crow::response{resp};
});

    CROW_ROUTE(malwareDetector, "/restore").methods(crow::HTTPMethod::Post)
    ([&](const crow::request& req){
        auto body = crow::json::load(req.body);
        if (!body || !body.has("quarantine"))
            return crow::response(400, "Missing fields");

        const std::string q = body["quarantine"].s();

        std::lock_guard<std::mutex> lk(g_manifest_mu);
        auto rows = readFromManifestFile();
        std::string err; bool done=false;
        for (auto& r : rows) {
            if (r.quarantine == q) {
                if (!fileRestoration(r, err)) return crow::response(500, "restore failed: " + err);
                done=true; break;
            }
        }
        if (!done) return crow::response(404, "row not found");
        writetoManifestFile(rows);

        crow::json::wvalue out;
        out["status"]     = "ok";
        out["quarantine"] = q;
        return crow::response{out};
    });

    CROW_ROUTE(malwareDetector, "/clear_whitelist").methods(crow::HTTPMethod::Post)
    ([&]{
        std::lock_guard<std::mutex> lk(g_manifest_mu);
        int changed = 0;
        std::string msg;
        changed = sendToQuarantine(msg);
        std::ofstream al(pathToRestoredFiles, std::ios::trunc);
        crow::json::wvalue out;
        out["re_quarantined"] = changed;
        return crow::response{out};
    });

    CROW_ROUTE(malwareDetector, "/download/manifest.csv")
    ([&]{
        std::ifstream in(pathToManifestFile, std::ios::binary);
        if (!in) return crow::response(404);
        std::ostringstream buf; buf << in.rdbuf();
        crow::response res(buf.str());
        res.code = 200;
        res.set_header("Content-Type", "text/csv");
        res.set_header("Content-Disposition", "attachment; filename=quarantine_manifest.csv");
        return res;
    });

    CROW_ROUTE(malwareDetector, "/")([](){
        const char* html = R"HTML(
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<link href="https://cdn.jsdelivr.net/npm/tailwindcss@2/dist/tailwind.min.css" rel="stylesheet">
<title>USB Malware Detection System</title>
<style>.ivi-card{box-shadow:0 6px 20px rgba(0,0,0,.08);}</style>
</head>
<body class="bg-gray-100">
  <div class="max-w-6xl mx-auto p-4 md:p-6">
    <div class="flex items-center justify-between mb-4">
      <h1 class="text-2xl md:text-3xl font-bold">Malware Detection Alert Dashboard</h1>
      <div class="space-x-2">
        <a class="bg-blue-200 hover:bg-blue-300 px-3 py-2 rounded text-sm" href="/download/manifest.csv">Download Report</a>
        <button id="btnClearWL" class="bg-yellow-100 hover:bg-yellow-200 text-yellow-800 px-3 py-2 rounded text-sm">Quarantine Allowed Files</button>
        <button id="btnRefresh" class="bg-green-600 hover:bg-green-700 text-white px-3 py-2 rounded text-sm">Refresh</button>
      </div>
    </div>

    <div id="highBanner" class="hidden mb-4 p-3 rounded bg-red-50 text-red-700 border border-red-200 text-center">
      <strong>Attention:</strong> Suspicious Activity Detected! Please take action where necessary otherwise, contact your local dealership.
    </div>

    <div class="ivi-card bg-white rounded">
      <div class="overflow-x-auto">
        <table class="min-w-full">
          <thead class="bg-gray-200">
            <tr>
              <th class="px-4 py-3 text-left text-xs font-semibold text-gray-600">Time</th>
              <th class="px-4 py-3 text-left text-xs font-semibold text-gray-600">Rule</th>
              <th class="px-4 py-3 text-left text-xs font-semibold text-gray-600">Original File</th>
              <th class="px-4 py-3 text-left text-xs font-semibold text-gray-600">Quarantine</th>
              <th class="px-4 py-3 text-left text-xs font-semibold text-gray-600">Status</th>
              <th class="px-4 py-3 text-left text-xs font-semibold text-gray-600">Action</th>
            </tr>
          </thead>
          <tbody id="tbody" class="divide-y divide-gray-100"></tbody>
        </table>
      </div>
    </div>
  </div>

<script>
function sevBadge(sev){
  const map={high:'bg-red-100 text-red-800',medium:'bg-yellow-100 text-yellow-800',low:'bg-green-100 text-green-800'};
  const c=map[sev]||map.medium; return '<span class="inline-block px-2 py-0.5 rounded text-xs '+c+'">'+sev+'</span>';
}
function statusBadge(st){
  const map={quarantined:'bg-yellow-100 text-yellow-800', allowed:'bg-green-100 text-green-800'};
  const c=map[st]||map.quarantined; return '<span class="inline-block px-2 py-0.5 rounded text-xs '+c+'">'+st+'</span>';
}
async function loadTable(){
  const res=await fetch('/quarantine_manifest.json',{cache:'no-store'});
  const data=await res.json();
  document.getElementById('highBanner').classList.toggle('hidden', !(data.meta && data.meta.any_high));
  const tb=document.getElementById('tbody'); tb.innerHTML='';
  let items = (data.items||[]);
  items = items.filter(it => it.status === 'quarantined' || it.status === 'allowed');
  items.forEach((it)=>{
    const tr=document.createElement('tr'); tr.className='hover:bg-gray-50';
    const c1=document.createElement('td'); c1.className='px-4 py-3 text-sm'; c1.textContent=it.time;
    const c2=document.createElement('td'); c2.className='px-4 py-3 text-sm';
    c2.innerHTML='<div class="flex items-center space-x-2"><span>'+it.rule+'</span>'+sevBadge(it.severity)+'</div>';
    const c3=document.createElement('td'); c3.className='px-4 py-3 text-sm'; c3.textContent=(it.original_pretty||it.original);
    const c4=document.createElement('td'); c4.className='px-4 py-3 text-sm'; c4.innerHTML='<span class="text-gray-700">'+(it.quarantine_label||it.quarantine)+'</span>';
    const c5=document.createElement('td'); c5.className='px-4 py-3 text-sm'; c5.innerHTML=statusBadge(it.status);
    const c6=document.createElement('td'); c6.className='px-4 py-3 text-sm';
    const btn=document.createElement('button');
    btn.className='bg-blue-600 hover:bg-blue-700 text-white text-xs px-3 py-1.5 rounded';
    btn.textContent='Restore';
    if (it.status==='allowed') {
      btn.disabled=true; btn.classList.add('opacity-50','cursor-not-allowed');
    } else {
      btn.onclick=async()=>{
        btn.disabled=true; btn.classList.add('opacity-50','cursor-not-allowed');
        try {
          const res = await fetch('/restore',{
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({original:it.original,quarantine:it.quarantine})
          });
          if(!res.ok) throw new Error('restore failed');
          c5.innerHTML = statusBadge('allowed');
          setTimeout(loadTable, 200);
        } catch(e) {
          btn.disabled=false; btn.classList.remove('opacity-50','cursor-not-allowed');
        }
      };
    }
    c6.appendChild(btn);
    tr.appendChild(c1); tr.appendChild(c2); tr.appendChild(c3); tr.appendChild(c4); tr.appendChild(c5); tr.appendChild(c6);
    tb.appendChild(tr);
  });
}
document.getElementById('btnRefresh').onclick=loadTable;
document.getElementById('btnClearWL').onclick=async()=>{ await fetch('/clear_whitelist',{method:'POST'}); loadTable(); };
loadTable(); setInterval(loadTable,5000);
</script>
</body>
</html>
)HTML";
        return crow::response{html};
    });

    malwareDetector.port(18080).multithreaded().run();
}
