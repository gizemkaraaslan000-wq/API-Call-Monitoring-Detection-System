/*
 * ============================================================
 *   API Call Monitoring & Threat Detection System
 *   Nesne Yonelimli Programlama (OOP) Proje Odevi
 * ============================================================
 *
 *  OOP Prensipleri:
 *   [SOYUTLAMA]    - DetectionRule soyut taban sinifi
 *   [POLIMORFIZM]  - checkBehavior() saf sanal fonksiyon
 *   [KALITIM]      - RansomwareRule, CodeInjectionRule : DetectionRule
 *   [KAPSULLEME]   - DetectionEngine sinifinda private uye degiskenler
 * ============================================================
 */

#include <iostream>
#include <string>
#include <vector>
#include <memory>       // std::unique_ptr, std::make_unique
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <ctime>

// ─────────────────────────────────────────────
//  RENK KODLARI (konsol ciktisi icin)
// ─────────────────────────────────────────────
namespace Color {
    const std::string RED     = "\033[1;31m";
    const std::string YELLOW  = "\033[1;33m";
    const std::string GREEN   = "\033[1;32m";
    const std::string CYAN    = "\033[1;36m";
    const std::string MAGENTA = "\033[1;35m";
    const std::string WHITE   = "\033[1;37m";
    const std::string RESET   = "\033[0m";
    const std::string DIM     = "\033[2m";
}

// ─────────────────────────────────────────────────────────────
//  1) APICall YAPISI
//     Bir API cagrisini temsil eder.
//     [KAPSULLEME]: Veriler tek bir yapida bir araya getirilmis.
// ─────────────────────────────────────────────────────────────
struct APICall {
    std::string processName;          // Cagrıyı yapan islem adi (ornek: "malware.exe")
    std::string apiName;              // Cagrilan Windows API adi (ornek: "CreateFile")
    std::vector<std::string> args;    // API'ye gecilen argumanlar
    std::string timestamp;            // Cagri zamani (ISO 8601 formati)

    // Yapici: Tum alanlari alir, timestamp otomatik atanabilir
    APICall(const std::string& proc,
            const std::string& api,
            std::vector<std::string> arguments,
            const std::string& ts = "")
        : processName(proc), apiName(api), args(std::move(arguments)), timestamp(ts)
    {
        if (timestamp.empty()) {
            // Otomatik zaman damgasi
            std::time_t now = std::time(nullptr);
            char buf[20];
            std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
            timestamp = buf;
        }
    }

    // Okunakli cikti icin yardimci fonksiyon
    std::string toString() const {
        std::ostringstream oss;
        oss << "[" << timestamp << "] "
            << processName << " -> " << apiName << "(";
        for (size_t i = 0; i < args.size(); ++i) {
            oss << args[i];
            if (i + 1 < args.size()) oss << ", ";
        }
        oss << ")";
        return oss.str();
    }
};

// ─────────────────────────────────────────────────────────────
//  2) ALERT YAPISI
//     Bir tehdit tespiti sonucunu tutar.
// ─────────────────────────────────────────────────────────────
enum class Severity { LOW, MEDIUM, HIGH, CRITICAL };

std::string severityToString(Severity s) {
    switch (s) {
        case Severity::LOW:      return "LOW";
        case Severity::MEDIUM:   return "MEDIUM";
        case Severity::HIGH:     return "HIGH";
        case Severity::CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

std::string severityColor(Severity s) {
    switch (s) {
        case Severity::LOW:      return Color::GREEN;
        case Severity::MEDIUM:   return Color::YELLOW;
        case Severity::HIGH:     return Color::RED;
        case Severity::CRITICAL: return Color::MAGENTA;
    }
    return Color::WHITE;
}

struct Alert {
    std::string     ruleName;       // Tetiklenen kuralın adı
    Severity        severity;       // Tehdit seviyesi
    std::string     description;    // Aciklama
    const APICall*  triggerCall;    // Tetikleyen API cagrisi (ham isaretci, sahiplik yok)

    Alert(const std::string& rule, Severity sev,
          const std::string& desc, const APICall* call)
        : ruleName(rule), severity(sev), description(desc), triggerCall(call) {}
};

// ─────────────────────────────────────────────────────────────
//  3) DetectionRule — SOYUT TABAN SINIF
//
//  [SOYUTLAMA]:   Ortak arayuzu tanimlar; alt siniflar detayi doldurur.
//  [POLIMORFIZM]: checkBehavior() saf sanaldir (pure virtual).
//                 Her alt sinif kendi davranis analizini uygular.
// ─────────────────────────────────────────────────────────────
class DetectionRule {
public:
    // [KAPSULLEME] — ruleName ve description protected: sadece turev siniflar erisebilir
    DetectionRule(const std::string& name, const std::string& desc)
        : ruleName_(name), description_(desc) {}

    // Saf sanal fonksiyon: Alt siniflar MUTLAKA implement etmeli.
    // [POLIMORFIZM]: Hangi nesneye isaret ettigine gore dogru surum calisir.
    virtual std::vector<Alert> checkBehavior(
        const std::vector<APICall>& history,
        const APICall& current) const = 0;

    // Sanal yikici: Turev sinif nesneleri taban isaretci uzerinden dogru silinir.
    virtual ~DetectionRule() = default;

    // Getter'lar (Kapsulleme: uye degiskenler disaridan salt-okunur)
    const std::string& getName()        const { return ruleName_; }
    const std::string& getDescription() const { return description_; }

protected:
    std::string ruleName_;
    std::string description_;

    // Alt siniflar icin yardimci: gecmiste belirli API adi kac kez gecmis?
    int countAPI(const std::vector<APICall>& history,
                 const std::string& apiName,
                 const std::string& processName) const {
        int count = 0;
        for (const auto& call : history)
            if (call.apiName == apiName && call.processName == processName)
                ++count;
        return count;
    }

    // Argumanlarda belirli bir anahtar kelime var mi?
    bool argContains(const APICall& call, const std::string& keyword) const {
        for (const auto& arg : call.args)
            if (arg.find(keyword) != std::string::npos)
                return true;
        return false;
    }
};

// ─────────────────────────────────────────────────────────────
//  4-A) RansomwareRule — TUREV SINIF 1
//
//  [KALITIM]:     DetectionRule'dan turetildi, checkBehavior uzerine yazildi.
//  [POLIMORFIZM]: checkBehavior() fidye yazilimi davranis kalibini denetler.
//
//  Tespit Mantigi:
//   - Kisa surede cok sayida dosya YAZMA islemi (toplu sifreleme isareti)
//   - .encrypted / .locked / .cry uzantili dosya adlari
//   - Shadow Copy silme girisimleri (vssadmin / wmic)
// ─────────────────────────────────────────────────────────────
class RansomwareRule : public DetectionRule {
public:
    explicit RansomwareRule(int writeThreshold = 5)
        : DetectionRule("RansomwareRule",
                        "Fidye yazilimi davranisini tespit eder: "
                        "toplu dosya sifreleme, golge kopya silme.")
        , writeThreshold_(writeThreshold) {}

    // [POLIMORFIZM] — checkBehavior override
    std::vector<Alert> checkBehavior(
        const std::vector<APICall>& history,
        const APICall& current) const override
    {
        std::vector<Alert> alerts;

        // --- Kural 1: Golge kopya silme (kritik) ---
        if ((current.apiName == "ShellExecute" || current.apiName == "CreateProcess") &&
            (argContains(current, "vssadmin") || argContains(current, "wmic") ||
             argContains(current, "shadowcopy")))
        {
            alerts.emplace_back(
                ruleName_, Severity::CRITICAL,
                "Shadow Copy silme girişimi tespit edildi! "
                "Geri yükleme noktalarını hedef alıyor.",
                &current
            );
        }

        // --- Kural 2: Sifreleme uzantisi ---
        if (current.apiName == "MoveFile" || current.apiName == "CopyFile") {
            if (argContains(current, ".encrypted") ||
                argContains(current, ".locked")    ||
                argContains(current, ".cry")        ||
                argContains(current, ".ransom"))
            {
                alerts.emplace_back(
                    ruleName_, Severity::HIGH,
                    "Şüpheli dosya uzantısına yeniden adlandırma: "
                    "fidye yazılımı şifreleme kalıbı.",
                    &current
                );
            }
        }

        // --- Kural 3: Toplu dosya yazma ---
        if (current.apiName == "WriteFile") {
            int writeCount = countAPI(history, "WriteFile", current.processName);
            if (writeCount >= writeThreshold_) {
                alerts.emplace_back(
                    ruleName_, Severity::HIGH,
                    "Kısa sürede çok sayıda WriteFile çağrısı (" +
                    std::to_string(writeCount + 1) + "/" +
                    std::to_string(writeThreshold_) +
                    "). Toplu dosya şifreleme şüphesi.",
                    &current
                );
            }
        }

        return alerts;
    }

private:
    int writeThreshold_;   // Kac WriteFile sonra alarm verilecek
};

// ─────────────────────────────────────────────────────────────
//  4-B) CodeInjectionRule — TUREV SINIF 2
//
//  [KALITIM]:     DetectionRule'dan turetildi.
//  [POLIMORFIZM]: checkBehavior() kod enjeksiyonu kaliplarini denetler.
//
//  Tespit Mantigi:
//   - OpenProcess + WriteProcessMemory kombinasyonu
//   - VirtualAllocEx ile uzak proses bellek ayirma
//   - CreateRemoteThread ile uzak is parcacigi olusturma
// ─────────────────────────────────────────────────────────────
class CodeInjectionRule : public DetectionRule {
public:
    CodeInjectionRule()
        : DetectionRule("CodeInjectionRule",
                        "Klasik kod enjeksiyonu uclusunu tespit eder: "
                        "OpenProcess → VirtualAllocEx → WriteProcessMemory/CreateRemoteThread.") {}

    // [POLIMORFIZM] — checkBehavior override
    std::vector<Alert> checkBehavior(
        const std::vector<APICall>& history,
        const APICall& current) const override
    {
        std::vector<Alert> alerts;

        // --- Kural 1: VirtualAllocEx (uzak proses bellek ayirma) ---
        if (current.apiName == "VirtualAllocEx") {
            bool openedBefore = countAPI(history, "OpenProcess",
                                         current.processName) > 0;
            if (openedBefore) {
                alerts.emplace_back(
                    ruleName_, Severity::HIGH,
                    "OpenProcess ardından VirtualAllocEx: "
                    "uzak process bellek tahsisi tespit edildi.",
                    &current
                );
            }
        }

        // --- Kural 2: WriteProcessMemory ---
        if (current.apiName == "WriteProcessMemory") {
            bool virtAllocBefore = countAPI(history, "VirtualAllocEx",
                                             current.processName) > 0;
            bool openedBefore    = countAPI(history, "OpenProcess",
                                             current.processName) > 0;
            if (virtAllocBefore && openedBefore) {
                alerts.emplace_back(
                    ruleName_, Severity::CRITICAL,
                    "OpenProcess → VirtualAllocEx → WriteProcessMemory üçlüsü "
                    "tamamlandı! Klasik DLL/shellcode enjeksiyonu tespit edildi.",
                    &current
                );
            }
        }

        // --- Kural 3: CreateRemoteThread ---
        if (current.apiName == "CreateRemoteThread") {
            alerts.emplace_back(
                ruleName_, Severity::CRITICAL,
                "CreateRemoteThread çağrısı: uzak process'te thread oluşturma. "
                "Shellcode yürütme girişimi şüphesi.",
                &current
            );
        }

        return alerts;
    }
};

// ─────────────────────────────────────────────────────────────
//  4-C) SuspiciousNetworkRule — TUREV SINIF 3 (BONUS)
//
//  [KALITIM + POLIMORFIZM]: Ayni arayuz, farkli davranis.
//  Ag aktivitesi + dosya yazma birlikteligi (veri sizintisi).
// ─────────────────────────────────────────────────────────────
class SuspiciousNetworkRule : public DetectionRule {
public:
    SuspiciousNetworkRule()
        : DetectionRule("SuspiciousNetworkRule",
                        "Şüpheli ağ etkinliğini tespit eder: "
                        "veri sızdırma, C2 iletişimi kalıpları.") {}

    std::vector<Alert> checkBehavior(
        const std::vector<APICall>& history,
        const APICall& current) const override
    {
        std::vector<Alert> alerts;

        // Ag baglantisi + onceden dosya okuma → veri sizintisi
        if (current.apiName == "connect" || current.apiName == "WSASend") {
            bool readFileBefore = countAPI(history, "ReadFile",
                                           current.processName) > 0;
            if (readFileBefore) {
                alerts.emplace_back(
                    ruleName_, Severity::MEDIUM,
                    "Dosya okuma ardından ağ gönderimi: "
                    "veri sızdırma (exfiltration) şüphesi.",
                    &current
                );
            }
            // Bilinen kotu portlar
            if (argContains(current, ":4444") || argContains(current, ":1337") ||
                argContains(current, ":31337"))
            {
                alerts.emplace_back(
                    ruleName_, Severity::HIGH,
                    "Bilinen C2/backdoor portuna bağlantı girişimi tespit edildi.",
                    &current
                );
            }
        }

        return alerts;
    }
};

// ─────────────────────────────────────────────────────────────
//  5) DetectionEngine — ANA MOTOR SINIFI
//
//  [KAPSULLEME]:  rules_ ve history_ private; disaridan erisim yok.
//  [POLIMORFIZM]: Her kural nesnesi DetectionRule* uzerinden cagrilir.
//  [BELLEK YON.]: std::unique_ptr ile otomatik bellek yonetimi.
// ─────────────────────────────────────────────────────────────
class DetectionEngine {
public:
    DetectionEngine() = default;

    // Kural ekle — sahiplik unique_ptr ile motora devredilir
    // [KAPSULLEME]: Kural listesine sadece bu metot uzerinden ekleme yapilir
    void addRule(std::unique_ptr<DetectionRule> rule) {
        rules_.push_back(std::move(rule));
    }

    // Yeni bir API cagrisini isle
    // [POLIMORFIZM]: Her kural icin checkBehavior() sanal dispatch ile cagrilir
    std::vector<Alert> processCall(const APICall& call) {
        std::vector<Alert> allAlerts;

        // Mevcut tum kurallar uzerinden gec
        for (const auto& rule : rules_) {
            // Polimorfik cagri: hangi turev sinif olduguna bakilmaksizin dogru checkBehavior() calisir
            auto ruleAlerts = rule->checkBehavior(history_, call);
            allAlerts.insert(allAlerts.end(), ruleAlerts.begin(), ruleAlerts.end());
        }

        // Cagrıyı gecmise ekle
        history_.push_back(call);
        return allAlerts;
    }

    // Istatistikler
    size_t getTotalCallsProcessed() const { return history_.size(); }
    size_t getRuleCount()           const { return rules_.size(); }

    // Gecmis API cagrilarini getir (salt-okunur)
    const std::vector<APICall>& getHistory() const { return history_; }

    // Motoru temizle (gerekirse yeni senaryo icin)
    void reset() {
        history_.clear();
    }

private:
    // [KAPSULLEME] — private uye degiskenler: dogrudan disaridan erisilemiyor
    std::vector<std::unique_ptr<DetectionRule>> rules_;   // Kural listesi (unique_ptr)
    std::vector<APICall>                        history_; // Islenenmis API cagri gecmisi
};

// ─────────────────────────────────────────────────────────────
//  YARDIMCI: Cikti / Gorsel Fonksiyonlar
// ─────────────────────────────────────────────────────────────
void printBanner() {
    std::cout << Color::CYAN
              << "╔══════════════════════════════════════════════════════════╗\n"
              << "║     API CALL MONITORING & THREAT DETECTION SYSTEM       ║\n"
              << "║               OOP Proje Ödevi — C++17                   ║\n"
              << "╚══════════════════════════════════════════════════════════╝\n"
              << Color::RESET << "\n";
}

void printSectionHeader(const std::string& title) {
    std::cout << "\n" << Color::WHITE
              << "──────────────────────────────────────────────────────────\n"
              << "  📋  " << title << "\n"
              << "──────────────────────────────────────────────────────────\n"
              << Color::RESET;
}

void printAPICall(const APICall& call) {
    std::cout << Color::DIM << "  [API] " << Color::RESET
              << Color::GREEN << call.processName << Color::RESET
              << " → " << Color::CYAN << call.apiName << Color::RESET
              << "(";
    for (size_t i = 0; i < call.args.size(); ++i) {
        std::cout << Color::YELLOW << "\"" << call.args[i] << "\"" << Color::RESET;
        if (i + 1 < call.args.size()) std::cout << ", ";
    }
    std::cout << ")  " << Color::DIM << call.timestamp << Color::RESET << "\n";
}

void printAlerts(const std::vector<Alert>& alerts) {
    for (const auto& alert : alerts) {
        std::string col = severityColor(alert.severity);
        std::cout << col
                  << "  ⚠️  [" << severityToString(alert.severity) << "] "
                  << alert.ruleName << "\n"
                  << Color::RESET
                  << "      " << alert.description << "\n";
    }
}

void printSummary(const DetectionEngine& engine) {
    printSectionHeader("TARAMA ÖZETI");
    std::cout << "  Toplam işlenen API çağrısı : " << engine.getTotalCallsProcessed() << "\n"
              << "  Aktif kural sayısı         : " << engine.getRuleCount() << "\n";
}

// ─────────────────────────────────────────────────────────────
//  6) MAIN — Senaryo Simülasyonu
// ─────────────────────────────────────────────────────────────
int main() {
    printBanner();

    // ── Motor Kurulumu ──────────────────────────────────────
    // [KAPSULLEME + POLIMORFIZM + KALITIM]:
    //   unique_ptr<DetectionRule> ile polimorfik nesneler motora ekleniyor.
    //   Motor, icindeki kurallarin hangi turev sinif oldugunu bilmek zorunda degil.

    DetectionEngine engine;
    engine.addRule(std::make_unique<RansomwareRule>(4));      // 4. WriteFile'dan itibaren alarm
    engine.addRule(std::make_unique<CodeInjectionRule>());
    engine.addRule(std::make_unique<SuspiciousNetworkRule>());

    // ── Senaryo 1: Fidye Yazilimi Simülasyonu ──────────────
    printSectionHeader("SENARYO 1 — Ransomware Saldırısı Simülasyonu");
    std::cout << Color::DIM << "  (cryptolocker.exe normal dosya yazmadan başlıyor...)\n" << Color::RESET;

    std::vector<APICall> ransomScenario = {
        APICall("cryptolocker.exe", "OpenFile",    {"C:\\Users\\victim\\Documents\\report.docx"}, "2024-06-01 10:00:01"),
        APICall("cryptolocker.exe", "ReadFile",    {"C:\\Users\\victim\\Documents\\report.docx"}, "2024-06-01 10:00:02"),
        APICall("cryptolocker.exe", "WriteFile",   {"C:\\Users\\victim\\Documents\\report.docx.encrypted"}, "2024-06-01 10:00:03"),
        APICall("cryptolocker.exe", "WriteFile",   {"C:\\Users\\victim\\Pictures\\photo.jpg.encrypted"},    "2024-06-01 10:00:04"),
        APICall("cryptolocker.exe", "WriteFile",   {"C:\\Users\\victim\\Desktop\\taxes.xlsx.encrypted"},   "2024-06-01 10:00:05"),
        APICall("cryptolocker.exe", "WriteFile",   {"C:\\Users\\victim\\Music\\song.mp3.encrypted"},       "2024-06-01 10:00:06"),
        APICall("cryptolocker.exe", "MoveFile",    {"C:\\Users\\victim\\Videos\\movie.mp4.encrypted"},     "2024-06-01 10:00:07"),
        APICall("cryptolocker.exe", "CreateProcess",{"vssadmin delete shadows /all /quiet"},               "2024-06-01 10:00:08"),
    };

    for (const auto& call : ransomScenario) {
        printAPICall(call);
        auto alerts = engine.processCall(call);
        printAlerts(alerts);
    }

    // ── Senaryo 2: Kod Enjeksiyonu Simülasyonu ─────────────
    engine.reset();
    printSectionHeader("SENARYO 2 — Process Injection (DLL Injection) Simülasyonu");
    std::cout << Color::DIM << "  (injector.exe meşru svchost.exe'ye sızıyor...)\n" << Color::RESET;

    std::vector<APICall> injectionScenario = {
        APICall("injector.exe", "OpenProcess",       {"PROCESS_ALL_ACCESS", "svchost.exe (PID:1234)"}, "2024-06-01 11:00:01"),
        APICall("injector.exe", "VirtualAllocEx",    {"hProcess=1234", "size=4096", "MEM_COMMIT|MEM_RESERVE"}, "2024-06-01 11:00:02"),
        APICall("injector.exe", "WriteProcessMemory",{"hProcess=1234", "lpBaseAddress=0x7FF0", "shellcode[...]"}, "2024-06-01 11:00:03"),
        APICall("injector.exe", "CreateRemoteThread",{"hProcess=1234", "lpStartAddress=0x7FF0"}, "2024-06-01 11:00:04"),
    };

    for (const auto& call : injectionScenario) {
        printAPICall(call);
        auto alerts = engine.processCall(call);
        printAlerts(alerts);
    }

    // ── Senaryo 3: Veri Sizintisi Simülasyonu ─────────────
    engine.reset();
    printSectionHeader("SENARYO 3 — Data Exfiltration (Veri Sızdırma) Simülasyonu");
    std::cout << Color::DIM << "  (spyware.exe hassas veriyi okuyup C2 sunucusuna gönderiyor...)\n" << Color::RESET;

    std::vector<APICall> networkScenario = {
        APICall("spyware.exe", "ReadFile",   {"C:\\confidential\\passwords.txt"}, "2024-06-01 12:00:01"),
        APICall("spyware.exe", "ReadFile",   {"C:\\confidential\\creditcards.csv"}, "2024-06-01 12:00:02"),
        APICall("spyware.exe", "connect",    {"192.168.100.55:4444"},             "2024-06-01 12:00:03"),
        APICall("spyware.exe", "WSASend",    {"data=<base64_encoded_stolen_data>","192.168.100.55:4444"}, "2024-06-01 12:00:04"),
    };

    for (const auto& call : networkScenario) {
        printAPICall(call);
        auto alerts = engine.processCall(call);
        printAlerts(alerts);
    }

    // ── Temiz Senaryo ───────────────────────────────────────
    engine.reset();
    printSectionHeader("SENARYO 4 — Temiz Uygulama (Alarm Olmamalı)");
    std::cout << Color::DIM << "  (notepad.exe normal bir metin dosyası kaydediyor...)\n" << Color::RESET;

    std::vector<APICall> cleanScenario = {
        APICall("notepad.exe", "OpenFile",  {"C:\\Users\\user\\Documents\\notes.txt"}, "2024-06-01 13:00:01"),
        APICall("notepad.exe", "ReadFile",  {"C:\\Users\\user\\Documents\\notes.txt"}, "2024-06-01 13:00:02"),
        APICall("notepad.exe", "WriteFile", {"C:\\Users\\user\\Documents\\notes.txt"}, "2024-06-01 13:00:03"),
        APICall("notepad.exe", "CloseFile", {"C:\\Users\\user\\Documents\\notes.txt"}, "2024-06-01 13:00:04"),
    };

    bool anyAlert = false;
    for (const auto& call : cleanScenario) {
        printAPICall(call);
        auto alerts = engine.processCall(call);
        if (!alerts.empty()) {
            printAlerts(alerts);
            anyAlert = true;
        }
    }
    if (!anyAlert)
        std::cout << Color::GREEN << "  ✅  Hiçbir tehdit tespit edilmedi.\n" << Color::RESET;

    // ── Ozet ────────────────────────────────────────────────
    printSummary(engine);
    std::cout << "\n" << Color::CYAN
              << "  Tüm senaryolar tamamlandı.\n"
              << Color::RESET << "\n";

    return 0;
}

/*
 * ════════════════════════════════════════════════════════════
 *  OOP PRENSİPLERİ ÖZET TABLOSU
 * ════════════════════════════════════════════════════════════
 *
 *  PRENSİP        │ NEREDE?
 * ────────────────┼──────────────────────────────────────────
 *  SOYUTLAMA      │ DetectionRule — saf sanal arayüz tanımlar,
 *                 │ uygulama detayı alt sınıflara bırakılır.
 * ────────────────┼──────────────────────────────────────────
 *  KALITIM        │ RansomwareRule, CodeInjectionRule,
 *                 │ SuspiciousNetworkRule : DetectionRule
 * ────────────────┼──────────────────────────────────────────
 *  POLİMORFİZM    │ DetectionEngine::processCall() içinde
 *                 │ rule->checkBehavior() sanal dispatch ile
 *                 │ doğru alt sınıf metodu çağrılır.
 * ────────────────┼──────────────────────────────────────────
 *  KAPSÜLLEME     │ DetectionEngine::rules_ ve history_
 *                 │ private; sadece addRule() ve
 *                 │ processCall() ile erişilir.
 *                 │ DetectionRule::ruleName_ protected.
 * ────────────────┼──────────────────────────────────────────
 *  BELLEK YÖN.    │ std::unique_ptr<DetectionRule> — RAII ile
 *                 │ otomatik bellek yönetimi, sızıntı yok.
 * ════════════════════════════════════════════════════════════
 */