#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/stat.h>
#include <ctype.h>          // tolower
#include <netdb.h>          // getaddrinfo
#ifdef __APPLE__
#include <mach-o/dyld.h>    // _NSGetExecutablePath
#endif
#include "database.h"
#include "attack-history-db.h"

#define BUF_SIZE 4096
#define RESP_SIZE 16384

// Base directory of the server binary — set at startup
static char BASE_DIR[1024] = ".";
static char LOG_FILE[1100] = "access.log";

#include <pthread.h>

// ── DDoS attack state (shared between attack thread and status endpoint) ──
typedef struct {
    int  running;
    int  total_requests;
    int  successful;
    int  failed;
    int  threads_active;
    int  stop_flag;
    double elapsed;
    double current_rps;
    char target_url[512];
    int  num_threads;
    int  requests_per_thread;
    time_t start_time;
} DDoSState;

static DDoSState ddos_state = {0};
static pthread_mutex_t ddos_mutex = PTHREAD_MUTEX_INITIALIZER;

// 1 = logged in, 0 = not logged in
int logged_in = 0;

// 1 = SQL injection defense enabled, 0 = disabled (start vulnerable)
int sql_defense_enabled = 0;

// 1 = DDoS defense enabled, 0 = disabled (start vulnerable)
int ddos_defense_enabled = 0;

// 1 = XSS defense enabled, 0 = disabled (start vulnerable)
int xss_defense_enabled = 0;

// ── DDoS IP blocklist ─────────────────────────────────────
#define MAX_BLOCKED_IPS 256
static char blocked_ips[MAX_BLOCKED_IPS][INET_ADDRSTRLEN];
static int  blocked_ip_count = 0;

typedef struct {
    int total_requests;
    int login_ok;
    int login_fail;
} Stats;

// Forward declaration so check_ddos can call write_log before it is defined
void write_log(const char *ip, const char *method, const char *path, const char *status);

// ── DDoS rate tracking ──────────────────────────────────────
#define DDOS_THRESHOLD   15
#define DDOS_WINDOW_SECS  5

typedef struct {
    char   ip[INET_ADDRSTRLEN];
    int    count;
    time_t window_start;
    int    already_logged;
} IpRate;

#define MAX_TRACKED_IPS 256
static IpRate ip_rates[MAX_TRACKED_IPS];
static int    ip_rate_count = 0;
static pthread_mutex_t rate_mutex = PTHREAD_MUTEX_INITIALIZER;

static void block_ip(const char *ip) {
    for (int i = 0; i < blocked_ip_count; i++) {
        if (strcmp(blocked_ips[i], ip) == 0) return;
    }
    if (blocked_ip_count < MAX_BLOCKED_IPS) {
        strncpy(blocked_ips[blocked_ip_count], ip, INET_ADDRSTRLEN - 1);
        blocked_ip_count++;
    }
}

static int is_blocked(const char *ip) {
    for (int i = 0; i < blocked_ip_count; i++) {
        if (strcmp(blocked_ips[i], ip) == 0) return 1;
    }
    return 0;
}

static void clear_blocklist(void) {
    blocked_ip_count = 0;
}

static void check_ddos(const char *ip) {
    time_t now = time(NULL);

    pthread_mutex_lock(&rate_mutex);

    // If already blocked, nothing more to do
    if (ddos_defense_enabled && is_blocked(ip)) {
        pthread_mutex_unlock(&rate_mutex);
        return;
    }

    for (int i = 0; i < ip_rate_count; i++) {
        if (strcmp(ip_rates[i].ip, ip) == 0) {
            if (now - ip_rates[i].window_start > DDOS_WINDOW_SECS) {
                // New window — reset but keep already_logged so we
                // can block again if another burst starts
                ip_rates[i].count        = 1;
                ip_rates[i].window_start = now;
                ip_rates[i].already_logged = 0;
                pthread_mutex_unlock(&rate_mutex);
                return;
            }
            ip_rates[i].count++;
            if (ip_rates[i].count >= DDOS_THRESHOLD && !ip_rates[i].already_logged) {
                ip_rates[i].already_logged = 1;
                char ts[64], desc[256];
                strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
                snprintf(desc, sizeof(desc),
                    "DDoS burst detected – %d requests in %ds from %s",
                    ip_rates[i].count, DDOS_WINDOW_SECS, ip);
                logAttackEvent(ts, ip, "DDoS", desc);
                write_log(ip, "DDOS", "/", desc);
                if (ddos_defense_enabled) block_ip(ip);
            }
            pthread_mutex_unlock(&rate_mutex);
            return;
        }
    }
    // New IP
    if (ip_rate_count < MAX_TRACKED_IPS) {
        strncpy(ip_rates[ip_rate_count].ip, ip, INET_ADDRSTRLEN - 1);
        ip_rates[ip_rate_count].ip[INET_ADDRSTRLEN - 1] = '\0';
        ip_rates[ip_rate_count].count          = 1;
        ip_rates[ip_rate_count].window_start   = now;
        ip_rates[ip_rate_count].already_logged = 0;
        ip_rate_count++;
    }
    pthread_mutex_unlock(&rate_mutex);
}

// Forward declarations
void send_users_page(int client_fd);
void send_add_user_form(int client_fd);
void handle_add_user_post(int client_fd, const char *body, const char *ip);
void handle_login_post(int client_fd, const char *body, const char *ip);
void send_dashboard_page(int client_fd);
void send_logs_page(int client_fd);
void send_stats_json(int client_fd);
void send_vulnerable_page(int client_fd);
void run_sql_attack(int client_fd, const char *ip);
void send_attack_history_page(int client_fd);
void send_enable_sql_defense_page(int client_fd, const char *ip);
void send_disable_sql_defense_page(int client_fd, const char *ip);
void handle_log_attack_post(int client_fd, const char *body, const char *ip);
void send_enable_xss_defense_page(int client_fd, const char *ip);
void send_disable_xss_defense_page(int client_fd, const char *ip);
void send_xss_defense_status(int client_fd);
void handle_ddos_attack_post(int client_fd, const char *body, const char *ip);
void handle_ddos_stop_post(int client_fd);
void handle_ddos_status_get(int client_fd);
void send_ddos_defense_page(int client_fd, const char *ip);
void send_enable_ddos_defense_page(int client_fd, const char *ip);
void send_disable_ddos_defense_page(int client_fd, const char *ip);
void handle_ddos_defense_status(int client_fd);
void send_ddos_dashboard(int client_fd);
void send_logo(int client_fd);
void handle_clear_ddos_blocklist(int client_fd, const char *ip);

static void url_decode(char *s);
static void get_form_field(const char *body, const char *name, char *out, size_t out_sz);
static int contains_ci(const char *haystack, const char *needle);
static int looks_like_sql_injection(const char *s);
static int sql_defense_handle_request(int client_fd,
                                      const char *username,
                                      const char *password,
                                      const char *ip);


// adding users and users handlers
void send_users_page(int client_fd);
void send_add_user_form(int client_fd);
void handle_add_user_post(int client_fd, const char *body, const char *ip);

// -----------------------------------------
// Stats / log reading
// -----------------------------------------

void compute_stats(Stats *s) {
    s->total_requests = 0;
    s->login_ok = 0;
    s->login_fail = 0;

    FILE *f = fopen(LOG_FILE, "r");
    if (!f) return;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        s->total_requests++;

        if (strstr(line, "LOGIN_OK")) {
            s->login_ok++;
        } else if (strstr(line, "LOGIN_FAIL")) {
            s->login_fail++;
        }
    }
    fclose(f);
}

// -----------------------------------------
// Static pages
// -----------------------------------------

// this is the Home page HTML
const char *index_page =
"HTTP/1.1 200 OK\r\n"
"Content-Type: text/html; charset=utf-8\r\n"
"Connection: close\r\n"
"\r\n"
"<!doctype html>"
"<html><head><title>SafeByte - CRTE</title>"
"<meta charset='utf-8'/>"
"<style>"
"*{box-sizing:border-box;margin:0;padding:0;}"
"body{font-family:'Segoe UI',Arial,sans-serif;background:linear-gradient(135deg,#0a0a0a 0%%,#1a1a2e 100%%);color:#eee;min-height:100vh;padding:40px 40px 60px;}"
".logo{position:absolute;top:20px;right:30px;width:150px;background:rgba(255,255,255,0.05);padding:8px;border-radius:8px;text-align:center;color:#00d4ff;font-weight:bold;font-size:14px;}"
".hero{max-width:1100px;margin:0 auto 50px;}"
"h1{font-size:52px;background:linear-gradient(45deg,#00d4ff,#ff6600);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:12px;line-height:1.1;}"
".tagline{color:#888;font-size:18px;margin-bottom:8px;}"
".divider{width:60px;height:3px;background:linear-gradient(90deg,#00d4ff,#ff6600);border-radius:2px;margin:20px 0 40px;}"
".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:24px;max-width:1100px;margin:0 auto;}"
".section-label{max-width:1100px;margin:0 auto 14px;font-size:12px;text-transform:uppercase;letter-spacing:2px;color:#555;font-weight:600;}"
".card{background:rgba(25,25,40,0.9);border:1px solid #2a2a3a;border-radius:14px;padding:24px;box-shadow:0 8px 32px rgba(0,0,0,0.4);transition:all 0.3s;}"
".card:hover{border-color:#00d4ff;transform:translateY(-3px);box-shadow:0 12px 40px rgba(0,212,255,0.15);}"
".card-header{display:flex;align-items:center;gap:14px;margin-bottom:18px;}"
".icon{width:46px;height:46px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:22px;flex-shrink:0;}"
".icon-blue{background:rgba(0,212,255,0.15);}"
".icon-red{background:rgba(255,68,68,0.15);}"
".icon-orange{background:rgba(255,102,0,0.15);}"
".icon-green{background:rgba(0,255,136,0.15);}"
".icon-purple{background:rgba(160,100,255,0.15);}"
".icon-yellow{background:rgba(255,200,0,0.15);}"
".card-title{font-size:17px;font-weight:700;color:#eee;margin-bottom:3px;}"
".card-subtitle{font-size:12px;color:#555;text-transform:uppercase;letter-spacing:1px;}"
".card-desc{font-size:14px;color:#888;line-height:1.6;margin-bottom:20px;}"
".card-link{display:inline-flex;align-items:center;gap:8px;padding:10px 20px;border-radius:8px;text-decoration:none;font-size:14px;font-weight:600;transition:all 0.3s;}"
".link-blue{background:rgba(0,212,255,0.12);color:#00d4ff;border:1px solid rgba(0,212,255,0.25);}"
".link-red{background:rgba(255,68,68,0.12);color:#ff4444;border:1px solid rgba(255,68,68,0.25);}"
".link-orange{background:rgba(255,102,0,0.12);color:#ff6600;border:1px solid rgba(255,102,0,0.25);}"
".link-green{background:rgba(0,255,136,0.12);color:#00ff88;border:1px solid rgba(0,255,136,0.25);}"
".link-purple{background:rgba(160,100,255,0.12);color:#a064ff;border:1px solid rgba(160,100,255,0.25);}"
".link-yellow{background:rgba(255,200,0,0.12);color:#ffc800;border:1px solid rgba(255,200,0,0.25);}"
".card-link:hover{transform:translateX(4px);filter:brightness(1.2);}"
".card-link::after{content:'→';}"
".spacer{height:32px;}"
"</style></head>"
"<body>"
"<img src='/logo' class='logo' alt='SafeByte'/>"

"<div class='hero'>"
"<h1>Cyber Resilience<br>Training Environment</h1>"
"<div class='tagline'>SafeByte Cybersecurity Training Platform</div>"
"<div class='divider'></div>"
"</div>"

"<div class='section-label'>⚔️ &nbsp;Attack Simulations</div>"
"<div class='grid'>"

"<div class='card'>"
"<div class='card-header'>"
"<div class='icon icon-red'>💉</div>"
"<div><div class='card-title'>SQL Injection</div><div class='card-subtitle'>Attack 2</div></div>"
"</div>"
"<div class='card-desc'>Exploit an intentionally vulnerable login form using classic SQL injection payloads to bypass authentication and dump the user database.</div>"
"<a href='/attack-sql' class='card-link link-red'>Launch Attack</a>"
"</div>"

"<div class='card'>"
"<div class='card-header'>"
"<div class='icon icon-orange'>🕷️</div>"
"<div><div class='card-title'>Stored XSS</div><div class='card-subtitle'>Attack 1</div></div>"
"</div>"
"<div class='card-desc'>Inject malicious scripts into a comment section that execute in every visitor's browser — demonstrating persistent cross-site scripting.</div>"
"<a href='/vulnerable' class='card-link link-orange'>Open Demo</a>"
"</div>"

"<div class='card'>"
"<div class='card-header'>"
"<div class='icon icon-red'>🌊</div>"
"<div><div class='card-title'>DDoS Attack</div><div class='card-subtitle'>Attack 3</div></div>"
"</div>"
"<div class='card-desc'>Simulate a distributed denial-of-service attack by flooding the server with concurrent requests across multiple threads.</div>"
"<a href='/ddos-dashboard' class='card-link link-red'>Launch Attack</a>"
"</div>"

"</div>"

"<div class='spacer'></div>"
"<div class='section-label'>🛡️ &nbsp;Defenses</div>"
"<div class='grid'>"

"<div class='card'>"
"<div class='card-header'>"
"<div class='icon icon-green'>🛡️</div>"
"<div><div class='card-title'>SQL Injection Defense</div><div class='card-subtitle'>Toggle Protection</div></div>"
"</div>"
"<div class='card-desc'>Enable input sanitization and parameterized query detection to block SQL injection attempts in real time.</div>"
"<a href='/enable-sql-defense' class='card-link link-green'>Enable Defense</a>"
"</div>"

"<div class='card'>"
"<div class='card-header'>"
"<div class='icon icon-green'>🚦</div>"
"<div><div class='card-title'>DDoS Defense</div><div class='card-subtitle'>Rate Limiting & IP Blocking</div></div>"
"</div>"
"<div class='card-desc'>Enable rate limiting to automatically detect and block IPs that exceed the request threshold — watch it stop the DDoS attack live.</div>"
"<a href='/ddos-defense' class='card-link link-green'>Open Defense Panel</a>"
"</div>"

"</div>"

"<div class='spacer'></div>"
"<div class='section-label'>📊 &nbsp;Monitoring & Management</div>"
"<div class='grid'>"

"<div class='card'>"
"<div class='card-header'>"
"<div class='icon icon-blue'>📈</div>"
"<div><div class='card-title'>Dashboard</div><div class='card-subtitle'>Live Stats</div></div>"
"</div>"
"<div class='card-desc'>View real-time request counts, login attempts, and system metrics updated every 2 seconds.</div>"
"<a href='/dashboard' class='card-link link-blue'>Open Dashboard</a>"
"</div>"

"<div class='card'>"
"<div class='card-header'>"
"<div class='icon icon-yellow'>🎯</div>"
"<div><div class='card-title'>Attack History</div><div class='card-subtitle'>Event Log</div></div>"
"</div>"
"<div class='card-desc'>Browse a full log of every attack event triggered during the session including SQL injection, XSS, and DDoS detections.</div>"
"<a href='/attack-history' class='card-link link-yellow'>View History</a>"
"</div>"

"<div class='card'>"
"<div class='card-header'>"
"<div class='icon icon-purple'>📋</div>"
"<div><div class='card-title'>Access Logs</div><div class='card-subtitle'>Request Log</div></div>"
"</div>"
"<div class='card-desc'>View the raw server access log showing every HTTP request, method, path, and status in chronological order.</div>"
"<a href='/logs' class='card-link link-purple'>View Logs</a>"
"</div>"

"<div class='card'>"
"<div class='card-header'>"
"<div class='icon icon-blue'>👥</div>"
"<div><div class='card-title'>User Management</div><div class='card-subtitle'>Database</div></div>"
"</div>"
"<div class='card-desc'>View all registered users in the SQLite database and add new ones — useful for demonstrating SQL injection impact.</div>"
"<a href='/users' class='card-link link-blue'>Manage Users</a>"
"</div>"

"</div>"
"</body></html>";

// the Login page HTML (GET)
const char *login_page =
"HTTP/1.1 200 OK\r\n"
"Content-Type: text/html; charset=utf-8\r\n"
"Connection: close\r\n"
"\r\n"
"<!doctype html>"
"<html><head><title>SafeByte - Login</title>"
"<style>"
"  body { font-family: 'Segoe UI', Arial, sans-serif; background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%); color: #eee; padding: 40px; min-height: 100vh; display: flex; align-items: center; justify-content: center; }"
"  .logo { position: absolute; top: 20px; right: 30px; width: 150px; background: rgba(255,255,255,0.05); padding: 8px; border-radius: 8px; text-align: center; color: #00d4ff; font-weight: bold; font-size: 14px; }"
"  .container { background: rgba(25, 25, 40, 0.9); border: 1px solid #333; border-radius: 12px; padding: 40px; max-width: 450px; width: 100%; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5); }"
"  h1 { font-size: 36px; background: linear-gradient(45deg, #00d4ff, #ff6600); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 10px; text-align: center; }"
"  .subtitle { color: #888; font-size: 14px; margin-bottom: 30px; text-align: center; }"
"  label { color: #aaa; font-size: 13px; margin-bottom: 8px; display: block; text-transform: uppercase; letter-spacing: 0.5px; }"
"  input { background: rgba(10, 10, 20, 0.8); border: 1px solid #444; border-radius: 6px; padding: 12px; color: #fff; font-size: 16px; width: 100%; margin-bottom: 20px; box-sizing: border-box; }"
"  input:focus { outline: none; border-color: #00d4ff; box-shadow: 0 0 10px rgba(0, 212, 255, 0.3); }"
"  button { background: linear-gradient(45deg, #00d4ff, #0099cc); color: white; border: none; border-radius: 8px; padding: 15px; font-size: 16px; font-weight: bold; cursor: pointer; width: 100%; text-transform: uppercase; letter-spacing: 1px; transition: all 0.3s; }"
"  button:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(0, 212, 255, 0.6); }"
"  .back-link { display: block; text-align: center; margin-top: 20px; color: #00d4ff; text-decoration: none; font-size: 14px; }"
"  .back-link:hover { text-decoration: underline; }"
"</style></head>"
"<body>"
"<div class='logo'>SafeByte</div>"
"<div class='container'>"
"<h1>Login</h1>"
"<div class='subtitle'>Cyber Resilience Training Environment</div>"
"<form method='POST' action='/login'>"
"<label>Username</label>"
"<input name='username' placeholder='Enter username' required>"
"<label>Password</label>"
"<input type='password' name='password' placeholder='Enter password' required>"
"<button type='submit'>Login</button>"
"</form>"
"<a href='/' class='back-link'>← Back to Home</a>"
"</div>"
"</body></html>";

// the 404 page
const char *not_found_page =
"HTTP/1.1 404 Not Found\r\n"
"Content-Type: text/html; charset=utf-8\r\n"
"Connection: close\r\n"
"\r\n"
"<!doctype html>"
"<html><head><title>Not found</title></head>"
"<body style='font-family: Arial; background:#111; color:#eee;'>"
"<h1>404 - Not Found</h1>"
"<p>The page you asked for does not exist.</p>"
"<p><a href='/' style='color:#4ea3ff;'>Back to home</a></p>"
"</body></html>";

// -----------------------------------------
// Logging helper
// -----------------------------------------

void write_log(const char *ip, const char *method, const char *path, const char *status) {
    FILE *f = fopen(LOG_FILE, "a");
    if (!f) return;

    time_t now = time(NULL);
    char timebuf[64];
    struct tm *tm_info = localtime(&now);
    if (tm_info) {
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        strcpy(timebuf, "unknown-time");
    }

    // one line per request
    fprintf(f, "[%s] %s %s %s (%s)\n", timebuf, ip, method, path, status);
    fclose(f);
}

// -----------------------------------------
// Dashboard
// -----------------------------------------

void send_dashboard_page(int client_fd) {
    char response[RESP_SIZE];

    int n = snprintf(response, sizeof(response),
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: text/html; charset=utf-8\r\n"
      "Connection: close\r\n"
      "\r\n"
      "<!doctype html>"
      "<html><head><title>SafeByte - Dashboard</title>"
      "<meta charset='utf-8'/>"
      "<style>"
      "body{font-family: 'Segoe UI', Arial, sans-serif; background: linear-gradient(135deg, #0a0a0a 0%%, #1a1a2e 100%%); color:#eee; padding:40px; min-height:100vh;}"
      ".logo{position:absolute; top:20px; right:30px; width:150px; background:rgba(255,255,255,0.05); padding:8px; border-radius:8px; text-align:center; color:#00d4ff; font-weight:bold; font-size:14px;}"
      "h1{font-size:48px; background:linear-gradient(45deg, #00d4ff, #ff6600); -webkit-background-clip:text; -webkit-text-fill-color:transparent; margin-bottom:10px;}"
      ".subtitle{color:#888; font-size:18px; margin-bottom:30px;}"
      ".status{background:rgba(25, 25, 40, 0.6); padding:15px; border-radius:8px; margin-bottom:30px; border-left:4px solid #00d4ff;}"
      ".card{background:rgba(25, 25, 40, 0.9); border:1px solid #333; border-radius:12px; padding:25px; margin-bottom:20px; box-shadow:0 8px 32px rgba(0,0,0,0.5);}"
      ".card h2{color:#00d4ff; font-size:22px; margin-bottom:15px;}"
      ".metric{margin:20px 0;}"
      ".metric-label{color:#aaa; font-size:13px; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:8px;}"
      ".metric-value{font-size:28px; font-weight:bold; color:#00d4ff; margin-bottom:8px;}"
      ".bar{height:20px; background:rgba(0,0,0,0.3); border-radius:10px; overflow:hidden; position:relative;}"
      ".bar-fill{height:100%%; transition:width 0.3s ease; border-radius:10px;}"
      ".bar-blue{background:linear-gradient(90deg, #00d4ff, #0099cc);}"
      ".bar-green{background:linear-gradient(90deg, #00ff88, #00cc66);}"
      ".bar-red{background:linear-gradient(90deg, #ff4444, #cc0000);}"
      ".link-section{margin-top:20px;}"
      ".link-section a{color:#00d4ff; text-decoration:none; font-size:16px; transition:all 0.3s; display:inline-block; margin-right:20px;}"
      ".link-section a:hover{transform:translateX(5px);}"
      ".back-link{display:inline-block; margin-top:30px; color:#00d4ff; text-decoration:none; font-size:14px;}"
      ".back-link:hover{text-decoration:underline;}"
      ".update-info{color:#666; font-size:12px; margin-top:10px; font-style:italic;}"
      "</style>"
      "</head><body>"
      
      "<div class='logo'>SafeByte</div>"
      "<h1>Dashboard</h1>"
      "<div class='subtitle'>System Statistics & Monitoring</div>"
      
      "<div class='status'>"
      "Login Status: %s"
      "</div>"
      
      "<div class='card'>"
      "<h2>📊 Attack & Defense Monitor</h2>"
      "<div class='metric'>"
      "<div class='metric-label'>Total Requests</div>"
      "<div class='metric-value' id='totalRequests'>-</div>"
      "<div class='bar'><div id='barTotal' class='bar-fill bar-blue' style='width:0%%'></div></div>"
      "</div>"
      
      "<div class='metric'>"
      "<div class='metric-label'>Successful Logins</div>"
      "<div class='metric-value' id='loginOk' style='color:#00ff88;'>-</div>"
      "<div class='bar'><div id='barOk' class='bar-fill bar-green' style='width:0%%'></div></div>"
      "</div>"
      
      "<div class='metric'>"
      "<div class='metric-label'>Failed Login Attempts</div>"
      "<div class='metric-value' id='loginFail' style='color:#ff4444;'>-</div>"
      "<div class='bar'><div id='barFail' class='bar-fill bar-red' style='width:0%%'></div></div>"
      "</div>"
      
      "<div class='update-info'>Updates every 2 seconds</div>"
      "</div>"

      "<div class='card'>"
      "<h2>📋 Quick Links</h2>"
      "<div class='link-section'>"
      "<a href='/logs'>→ View Live Logs</a>"
      "<a href='/users'>→ User Management</a>"
      "<a href='/ddos-dashboard'>→ DDoS Dashboard</a>"
      "</div>"
      "</div>"
      
      "<a href='/' class='back-link'>← Back to Home</a>"
                   
      "<script>"
      "async function loadStats() {"
      "  try{"
      "     const res = await fetch('/stats');"
      "     if(!res.ok) return;"
      "     const data = await res.json();"
      "     const total = data.total_requests || 0;"
      "     const ok = data.login_ok || 0;"
      "     const fail = data.login_fail || 0;"
      "     document.getElementById('totalRequests').textContent = total;"
      "     document.getElementById('loginOk').textContent = ok;"
      "     document.getElementById('loginFail').textContent = fail;"
      "     const max = Math.max(total, ok, fail, 1);"
      "     document.getElementById('barTotal').style.width = (total*100/max) + '%%';"
      "     document.getElementById('barOk').style.width = (ok*100/max) + '%%';"
      "     document.getElementById('barFail').style.width = (fail*100/max) + '%%';"
      "  }catch(e) { console.log(e); }"
      "}"
      "loadStats();"
      "setInterval(loadStats, 2000);"
      "</script>"

      "</body></html>",
      logged_in ? "You have logged in as admin." : "You are not logged in yet"
    );

    if (n > 0) {
        send(client_fd, response, (size_t)n, 0);
    }
}

// -----------------------------------------
// Logs page
// -----------------------------------------

void send_logs_page(int client_fd) {
    const size_t MAX_LINES = 200;   // show last 200 lines
    const size_t BUF_LINE = 512;

    FILE *f = fopen(LOG_FILE, "r");
    if (!f) {
        const char *msg =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "Connection: close\r\n\r\n"
            "<!doctype html>"
            "<html><head><title>SafeByte - Logs</title>"
            "<style>"
            "body{font-family: 'Segoe UI', Arial, sans-serif; background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%); color:#eee; padding:40px; min-height:100vh;}"
            ".logo{position:absolute; top:20px; right:30px; width:150px; background:rgba(255,255,255,0.05); padding:8px; border-radius:8px; text-align:center; color:#00d4ff; font-weight:bold; font-size:14px;}"
            "h1{font-size:48px; background:linear-gradient(45deg, #00d4ff, #ff6600); -webkit-background-clip:text; -webkit-text-fill-color:transparent; margin-bottom:10px;}"
            ".subtitle{color:#888; font-size:18px; margin-bottom:30px;}"
            ".card{background:rgba(25, 25, 40, 0.9); border:1px solid #333; border-radius:12px; padding:25px; box-shadow:0 8px 32px rgba(0,0,0,0.5);}"
            ".empty-state{text-align:center; padding:40px; color:#666;}"
            ".back-link{display:inline-block; margin-top:30px; color:#00d4ff; text-decoration:none; font-size:14px;}"
            ".back-link:hover{text-decoration:underline;}"
            "</style></head>"
            "<body>"
            "<div class='logo'>SafeByte</div>"
            "<h1>Request Logs</h1>"
            "<div class='subtitle'>System Access Log</div>"
            "<div class='card'>"
            "<div class='empty-state'>📋 No logs available yet</div>"
            "</div>"
            "<a href='/' class='back-link'>← Back to Home</a>"
            "</body></html>";
        send(client_fd, msg, strlen(msg), 0);
        return;
    }

    // Get file size
    struct stat st;
    fstat(fileno(f), &st);
    long filesize = st.st_size;

    long pos = filesize - 1;
    int lines = 0;
    fseek(f, pos, SEEK_SET);

    // Count lines from the end
    while (pos >= 0 && lines <= MAX_LINES) {
        fseek(f, pos, SEEK_SET);
        if (fgetc(f) == '\n') lines++;
        pos--;
    }
    pos = pos < 0 ? 0 : pos + 2; // start of first line to read

    fseek(f, pos, SEEK_SET);

    // Build response header
    char header[2048];
    int n = snprintf(header, sizeof(header),
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Type: text/html; charset=utf-8\r\n"
                     "Connection: close\r\n\r\n"
                     "<!doctype html>"
                     "<html><head><title>SafeByte - Logs</title>"
                     "<style>"
                     "body{font-family: 'Segoe UI', Arial, sans-serif; background: linear-gradient(135deg, #0a0a0a 0%%, #1a1a2e 100%%); color:#eee; padding:40px; min-height:100vh;}"
                     ".logo{position:absolute; top:20px; right:30px; width:150px; background:rgba(255,255,255,0.05); padding:8px; border-radius:8px; text-align:center; color:#00d4ff; font-weight:bold; font-size:14px;}"
                     "h1{font-size:48px; background:linear-gradient(45deg, #00d4ff, #ff6600); -webkit-background-clip:text; -webkit-text-fill-color:transparent; margin-bottom:10px;}"
                     ".subtitle{color:#888; font-size:18px; margin-bottom:30px;}"
                     ".card{background:rgba(25, 25, 40, 0.9); border:1px solid #333; border-radius:12px; padding:25px; box-shadow:0 8px 32px rgba(0,0,0,0.5);}"
                     ".card h2{color:#00d4ff; font-size:22px; margin-bottom:15px;}"
                     "pre{background:rgba(0,0,0,0.5); padding:20px; border-radius:8px; overflow-x:auto; font-family:'Courier New', monospace; font-size:13px; line-height:1.6; border-left:3px solid #00d4ff;}"
                     ".back-link{display:inline-block; margin-top:30px; color:#00d4ff; text-decoration:none; font-size:14px;}"
                     ".back-link:hover{text-decoration:underline;}"
                     ".update-info{color:#666; font-size:12px; margin-top:15px; font-style:italic;}"
                     "</style></head>"
                     "<body>"
                     "<div class='logo'>SafeByte</div>"
                     "<h1>Request Logs</h1>"
                     "<div class='subtitle'>Last %zu Requests</div>"
                     "<div class='card'>"
                     "<h2>📝 Access Log</h2>"
                     "<pre>",
                     MAX_LINES);
    send(client_fd, header, (size_t)n, 0);

    // Stream lines from file directly to socket
    char line[BUF_LINE];
    while (fgets(line, sizeof(line), f)) {
        send(client_fd, line, strlen(line), 0);
    }

    // Closing HTML
    const char *tail =
        "</pre>"
        "<div class='update-info'>Showing most recent log entries</div>"
        "</div>"
        "<a href='/' class='back-link'>← Back to Home</a>"
        "</body></html>";
    send(client_fd, tail, strlen(tail), 0);

    fclose(f);
}

// -----------------------------------------
// /stats JSON
// -----------------------------------------

void send_stats_json(int client_fd) {
    Stats s;
    compute_stats(&s);

    char body[512];
    int body_len = snprintf(body, sizeof(body),
                            "{ \"total_requests\": %d, \"login_ok\": %d, \"login_fail\": %d }",
                            s.total_requests, s.login_ok, s.login_fail);

    char response[RESP_SIZE];
    int n = snprintf(response, sizeof(response),
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Type: application/json; charset=utf-8\r\n"
                     "Connection: close\r\n"
                     "Content-Length: %d\r\n"
                     "\r\n"
                     "%.*s",
                     body_len, body_len, body);

    if (n > 0) {
        send(client_fd, response, (size_t)n, 0);
    }
}

// -----------------------------------------
// XSS vulnerable page
// -----------------------------------------

void send_xss_defense_status(int client_fd) {
    char resp[256];
    int n = snprintf(resp, sizeof(resp),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%d",
        xss_defense_enabled
    );

    send(client_fd, resp, n, 0);
}

void send_vulnerable_page(int client_fd) {
    const char *header =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Connection: close\r\n"
        "\r\n";

    send(client_fd, header, strlen(header), 0);

    char vuln_path[1100];
    snprintf(vuln_path, sizeof(vuln_path), "%s/vulnerable_page.html", BASE_DIR);

    FILE *f = fopen(vuln_path, "r");
    if (!f) {
        const char *err_body =
            "<!doctype html><html><head><title>Error</title></head>"
            "<body style='font-family: Arial; background:#111; color:#eee;'>"
            "<h1>Vulnerable page missing</h1>"
            "<p>Could not open vulnerable_page.html.</p>"
            "</body></html>";
        send(client_fd, err_body, strlen(err_body), 0);
        return;
    }

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    rewind(f);

    if (file_size < 0 || file_size > 100000) {
        fclose(f);
        const char *err_body =
            "<!doctype html><html><head><title>Error</title></head>"
            "<body style='font-family: Arial; background:#111; color:#eee;'>"
            "<h1>Page too large</h1>"
            "<p>Could not load vulnerable_page.html safely.</p>"
            "</body></html>";
        send(client_fd, err_body, strlen(err_body), 0);
        return;
    }

    char *file_content = malloc((size_t)file_size + 1);
    if (!file_content) {
        fclose(f);
        const char *err_body =
            "<!doctype html><html><head><title>Error</title></head>"
            "<body style='font-family: Arial; background:#111; color:#eee;'>"
            "<h1>Memory error</h1>"
            "<p>Could not allocate memory for vulnerable_page.html.</p>"
            "</body></html>";
        send(client_fd, err_body, strlen(err_body), 0);
        return;
    }

    size_t bytes_read = fread(file_content, 1, (size_t)file_size, f);
    file_content[bytes_read] = '\0';
    fclose(f);

    char injected_state[128];
    snprintf(injected_state, sizeof(injected_state),
        "<script>const XSS_DEFENSE = %d;</script>\n",
        xss_defense_enabled);

    send(client_fd, injected_state, strlen(injected_state), 0);
    send(client_fd, file_content, strlen(file_content), 0);

    free(file_content);
}

// -----------------------------------------
// /users & /add-user pages
// -----------------------------------------

// callback used by db_for_each_user to build table rows
static int users_page_row_cb(int id, const char *username, void *udata) {
    char **body_ptr = (char **)udata;
    char row[256];

    snprintf(row, sizeof(row),
             "<tr><td>%d</td><td>%s</td></tr>",
             id, username);

    size_t old_len = strlen(*body_ptr);
    size_t row_len = strlen(row);

    char *new_buf = realloc(*body_ptr, old_len + row_len + 1);
    if (!new_buf) return 1; // stop on alloc fail

    memcpy(new_buf + old_len, row, row_len + 1);
    *body_ptr = new_buf;

    return 0;
}

// GET /users  -> list all users from DB
void send_users_page(int client_fd) {
    char *rows = malloc(1);
    if (!rows) return;
    rows[0] = '\0';

    // iterate over users table; requires db_for_each_user in database.c
    db_for_each_user(users_page_row_cb, &rows);

    const char *head =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Connection: close\r\n"
        "\r\n"
        "<!doctype html>"
        "<html><head><title>SafeByte - Users</title>"
        "<style>"
        "body{font-family: 'Segoe UI', Arial, sans-serif; background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%); color:#eee; padding:40px; min-height:100vh;}"
        ".logo{position:absolute; top:20px; right:30px; width:150px; background:rgba(255,255,255,0.05); padding:8px; border-radius:8px; text-align:center; color:#00d4ff; font-weight:bold; font-size:14px;}"
        "h1{font-size:48px; background:linear-gradient(45deg, #00d4ff, #ff6600); -webkit-background-clip:text; -webkit-text-fill-color:transparent; margin-bottom:10px;}"
        ".subtitle{color:#888; font-size:18px; margin-bottom:30px;}"
        ".nav-links{margin-bottom:30px;}"
        ".nav-links a{color:#00d4ff; text-decoration:none; font-size:16px; margin-right:20px; transition:all 0.3s;}"
        ".nav-links a:hover{transform:translateX(5px); display:inline-block;}"
        ".card{background:rgba(25, 25, 40, 0.9); border:1px solid #333; border-radius:12px; padding:25px; box-shadow:0 8px 32px rgba(0,0,0,0.5);}"
        ".card h2{color:#00d4ff; font-size:22px; margin-bottom:20px;}"
        "table{width:100%; border-collapse:collapse; background:rgba(0,0,0,0.3); border-radius:8px; overflow:hidden;}"
        "th{background:rgba(0,212,255,0.1); color:#00d4ff; padding:15px; text-align:left; font-weight:600; text-transform:uppercase; font-size:12px; letter-spacing:1px;}"
        "td{padding:15px; border-top:1px solid rgba(255,255,255,0.05); color:#ccc;}"
        "tr:hover td{background:rgba(0,212,255,0.05);}"
        ".back-link{display:inline-block; margin-top:30px; color:#00d4ff; text-decoration:none; font-size:14px;}"
        ".back-link:hover{text-decoration:underline;}"
        "</style></head>"
        "<body>"
        "<div class='logo'>SafeByte</div>"
        "<h1>User Database</h1>"
        "<div class='subtitle'>Manage System Users</div>"
        "<div class='nav-links'>"
        "<a href='/'>→ Home</a>"
        "<a href='/add-user'>→ Add User</a>"
        "</div>"
        "<div class='card'>"
        "<h2>👥 Registered Users</h2>"
        "<table>"
        "<tr><th>ID</th><th>Username</th></tr>";

    const char *tail =
        "</table>"
        "</div>"
        "<a href='/' class='back-link'>← Back to Home</a>"
        "</body></html>";

    size_t len = strlen(head) + strlen(rows) + strlen(tail);
    char *resp = malloc(len + 1);
    if (!resp) {
        free(rows);
        return;
    }

    strcpy(resp, head);
    strcat(resp, rows);
    strcat(resp, tail);

    send(client_fd, resp, strlen(resp), 0);

    free(resp);
    free(rows);
}

// GET /add-user -> show form
void send_add_user_form(int client_fd) {
    const char *resp =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Connection: close\r\n"
        "\r\n"
        "<!doctype html>"
        "<html><head><title>SafeByte - Add User</title>"
        "<style>"
        "body{font-family: 'Segoe UI', Arial, sans-serif; background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%); color:#eee; padding:40px; min-height:100vh; display:flex; align-items:center; justify-content:center;}"
        ".logo{position:absolute; top:20px; right:30px; width:150px; background:rgba(255,255,255,0.05); padding:8px; border-radius:8px; text-align:center; color:#00d4ff; font-weight:bold; font-size:14px;}"
        ".container{background:rgba(25, 25, 40, 0.9); border:1px solid #333; border-radius:12px; padding:40px; max-width:450px; width:100%; box-shadow:0 8px 32px rgba(0,0,0,0.5);}"
        "h1{font-size:36px; background:linear-gradient(45deg, #00d4ff, #ff6600); -webkit-background-clip:text; -webkit-text-fill-color:transparent; margin-bottom:10px; text-align:center;}"
        ".subtitle{color:#888; font-size:14px; margin-bottom:30px; text-align:center;}"
        "label{color:#aaa; font-size:13px; margin-bottom:8px; display:block; text-transform:uppercase; letter-spacing:0.5px;}"
        "input{background:rgba(10, 10, 20, 0.8); border:1px solid #444; border-radius:6px; padding:12px; color:#fff; font-size:16px; width:100%; margin-bottom:20px; box-sizing:border-box;}"
        "input:focus{outline:none; border-color:#00d4ff; box-shadow:0 0 10px rgba(0, 212, 255, 0.3);}"
        "button{background:linear-gradient(45deg, #00d4ff, #0099cc); color:white; border:none; border-radius:8px; padding:15px; font-size:16px; font-weight:bold; cursor:pointer; width:100%; text-transform:uppercase; letter-spacing:1px; transition:all 0.3s;}"
        "button:hover{transform:translateY(-2px); box-shadow:0 6px 20px rgba(0, 212, 255, 0.6);}"
        ".link-section{margin-top:20px; text-align:center;}"
        ".link-section a{color:#00d4ff; text-decoration:none; font-size:14px; margin:0 10px;}"
        ".link-section a:hover{text-decoration:underline;}"
        "</style></head>"
        "<body>"
        "<div class='logo'>SafeByte</div>"
        "<div class='container'>"
        "<h1>Add User</h1>"
        "<div class='subtitle'>Create New System User</div>"
        "<form method='POST' action='/add-user'>"
        "<label>Username</label>"
        "<input name='username' placeholder='Enter username' required>"
        "<label>Password</label>"
        "<input type='password' name='password' placeholder='Enter password' required>"
        "<button type='submit'>Create User</button>"
        "</form>"
        "<div class='link-section'>"
        "<a href='/users'>→ View Users</a>"
        "<a href='/'>← Back to Home</a>"
        "</div>"
        "</div>"
        "</body></html>";

    send(client_fd, resp, strlen(resp), 0);
}

// ============================================================================
// SQL Injection Defense Functions
// ============================================================================

// Case-insensitive substring search
static int contains_ci(const char *haystack, const char *needle) {
    if (!haystack || !needle) return 0;
    
    size_t hlen = strlen(haystack);
    size_t nlen = strlen(needle);
    
    if (nlen > hlen) return 0;
    
    for (size_t i = 0; i <= hlen - nlen; i++) {
        int match = 1;
        for (size_t j = 0; j < nlen; j++) {
            if (tolower((unsigned char)haystack[i+j]) != tolower((unsigned char)needle[j])) {
                match = 0;
                break;
            }
        }
        if (match) return 1;
    }
    return 0;
}

// Detect SQL injection patterns
static int looks_like_sql_injection(const char *s) {
    if (!s || *s == '\0') return 0;

    const char *patterns[] = {
        "' or '1'='1",
        "\" or \"1\"=\"1",
        " or 1=1",
        " union select",
        " drop table",
        " insert into",
        " delete from",
        ";--",
        "--",
        "/*",
        "*/",
        NULL
    };

    for (int i = 0; patterns[i]; i++) {
        if (contains_ci(s, patterns[i])) {
            return 1;
        }
    }
    return 0;
}

// Central SQL defense handler
// Returns 1 if request was blocked and response sent
// Returns 0 if caller should continue normally
static int sql_defense_handle_request(
    int client_fd,
    const char *username,
    const char *password,
    const char *ip
) {
    int suspicious = looks_like_sql_injection(username) ||
                     looks_like_sql_injection(password);

    if (!suspicious) {
        return 0;  // No attack detected
    }

    time_t now = time(NULL);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));

    if (sql_defense_enabled) {
        // DEFENSE ON: Block injection attempt
        logAttackEvent(ts,
                       ip,
                       "SQL Injection attempt blocked",
                       "Detected suspicious SQL patterns in form input");
        write_log(ip, "POST", "/add-user", "SQLI_BLOCKED");

        char resp[4096];
        snprintf(resp, sizeof(resp),
            "HTTP/1.1 400 Bad Request\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "Connection: close\r\n"
            "\r\n"
            "<!doctype html>"
            "<html><head><title>SafeByte - Attack Blocked</title>"
            "<style>"
            "body{font-family: 'Segoe UI', Arial, sans-serif; background: linear-gradient(135deg, #0a0a0a 0%%, #1a1a2e 100%%); color:#eee; padding:40px; min-height:100vh; display:flex; align-items:center; justify-content:center;}"
            ".logo{position:absolute; top:20px; right:30px; width:150px; background:rgba(255,255,255,0.05); padding:8px; border-radius:8px; text-align:center; color:#00d4ff; font-weight:bold; font-size:14px;}"
            ".container{background:rgba(25, 25, 40, 0.9); border:1px solid #ff4444; border-radius:12px; padding:40px; max-width:550px; box-shadow:0 8px 32px rgba(0,0,0,0.5);}"
            "h1{font-size:36px; color:#ff4444; margin-bottom:20px;}"
            "p{color:#ccc; line-height:1.6; margin:15px 0;}"
            ".warning{background:rgba(255,68,68,0.1); padding:15px; border-left:4px solid #ff4444; margin:20px 0; border-radius:4px;}"
            "a{color:#00d4ff; text-decoration:none; margin:0 10px;}"
            "a:hover{text-decoration:underline;}"
            "</style></head>"
            "<body>"
            "<div class='logo'>SafeByte</div>"
            "<div class='container'>"
            "<h1>Attack Blocked</h1>"
            "<div class='warning'>"
            "<strong>SQL Injection Detected</strong><br>"
            "Your input contained patterns that look like a SQL injection attack."
            "</div>"
            "<p>The SafeByte defense system has blocked this request to protect the database.</p>"
            "<p><strong>Attack logged:</strong> %s</p>"
            "<p style='margin-top:30px;'>"
            "<a href='/add-user'>Go Back</a> | "
            "<a href='/attack-history'>View Attack History</a> | "
            "<a href='/'>Home</a>"
            "</p>"
            "</div>"
            "</body></html>",
            ts);

        send(client_fd, resp, strlen(resp), 0);
        return 1;  // Request handled
    } else {
        // DEFENSE OFF: Attack runs, but we log it
        logAttackEvent(ts,
                       ip,
                       "SQL Injection (defense OFF)",
                       "Suspicious SQL patterns detected but defense is disabled");
        write_log(ip, "POST", "/add-user", "SQLI_DETECTED_NOT_BLOCKED");
        return 0;  // Continue normally
    }
}

// ============================================================================

// helper: URL-decode + and %xx
static void url_decode(char *s) {
    char *o = s;
    for (; *s; s++, o++) {
        if (*s == '+') {
            *o = ' ';
        } else if (*s == '%' && s[1] && s[2]) {
            char hex[3] = { s[1], s[2], '\0' };
            *o = (char) strtol(hex, NULL, 16);
            s += 2;
        } else {
            *o = *s;
        }
    }
    *o = '\0';
}

// helper: pull field value from x-www-form-urlencoded body
static void get_form_field(const char *body, const char *name, char *out, size_t out_sz) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "%s=", name);

    const char *p = strstr(body, pattern);
    if (!p) {
        out[0] = '\0';
        return;
    }
    p += strlen(pattern);

    size_t i = 0;
    while (*p && *p != '&' && i + 1 < out_sz) {
        out[i++] = *p++;
    }
    out[i] = '\0';
    url_decode(out);
}


void handle_add_user_post(int client_fd, const char *body, const char *ip) {
    char username[64] = {0};
    char password[64] = {0};

    if (body) {
        get_form_field(body, "username", username, sizeof(username));
        get_form_field(body, "password", password, sizeof(password));
    }

    /* block suspicious payloads only when defense logic says to */
    if (sql_defense_handle_request(client_fd, username, password, ip)) {
        return;
    }

    if (username[0] != '\0' && password[0] != '\0') {
        int ok = 0;

        if (sql_defense_enabled) {
            ok = db_create_user_safe(username, password);
            write_log(ip, "POST", "/add-user", ok ? "ADD_USER_SAFE" : "ADD_USER_SAFE_FAIL");
        } else {
            ok = db_add_user(username, password);   /* intentionally vulnerable */
            write_log(ip, "POST", "/add-user", ok ? "ADD_USER" : "ADD_USER_FAIL");
        }
    } else {
        write_log(ip, "POST", "/add-user", "ADD_USER_BAD_FORM");
    }

    const char *resp =
        "HTTP/1.1 302 Found\r\n"
        "Location: /users\r\n"
        "Connection: close\r\n"
        "\r\n";

    send(client_fd, resp, strlen(resp), 0);
}

// -----------------------------------------
// /login POST handler
// -----------------------------------------

void handle_login_post(int client_fd, const char *body, const char *ip) {
    char username[64] = {0};
    char password[64] = {0};

    if (body) {
        get_form_field(body, "username", username, sizeof(username));
        get_form_field(body, "password", password, sizeof(password));
    }

    if (sql_defense_handle_request(client_fd, username, password, ip)) {
        logged_in = 0;
        return;
    }

    int success = 0;

    if (sql_defense_enabled) {
        success = db_verify_login_safe(username, password);
    } else {
        success = db_verify_login(username, password);   /* intentionally vulnerable */
    }

    logged_in = success ? 1 : 0;

    write_log(ip, "POST", "/login", success ? "LOGIN_OK" : "LOGIN_FAIL");

    char response[RESP_SIZE];
    int n = snprintf(response, sizeof(response),
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Type: text/html; charset=utf-8\r\n"
                     "Connection: close\r\n"
                     "\r\n"
                     "<!doctype html>"
                     "<html><head><title>Login result</title></head>"
                     "<body style='font-family: Arial; background:#111; color:#eee;'>"
                     "<h1>Login %s</h1>"
                     "<p>%s</p>"
                     "<p><a href='/dashboard' style='color:#4ea3ff;'>Go to dashboard</a></p>"
                     "<p><a href='/' style='color:#4ea3ff;'>Back to home</a></p>"
                     "</body></html>",
                     success ? "successful" : "failed",
                     success
                        ? "Credentials accepted."
                        : "Wrong username or password.");

    if (n > 0) {
        send(client_fd, response, (size_t)n, 0);
    }
}

// -----------------------------------------
// SQL Injection attack trigger (/attack-sql)
// -----------------------------------------

void run_sql_attack(int client_fd, const char *ip) {
    // timestamp
    if (sql_defense_enabled) {
        time_t now = time(NULL);
        char ts[64];
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));

        logAttackEvent(ts, ip, "SQL Injection attempt blocked",
                       "Blocked /attack-sql because SQL defense is enabled");

        write_log(ip, "GET", "/attack-sql", "SQL_ATTACK_BLOCKED");

        const char *resp =
            "HTTP/1.1 403 Forbidden\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "Connection: close\r\n"
            "\r\n"
            "<h1>SQL Injection Blocked</h1>"
            "<p>Defense is ON</p>";

        send(client_fd, resp, strlen(resp), 0);
        return;
    }
    time_t now = time(NULL);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));

    // log to attack-history-db.txt
    logAttackEvent(ts, ip, "SQL Injection", "Triggered SQL injection attack via /attack-sql");
    write_log(ip, "GET", "/attack-sql", "SQL_ATTACK_TRIGGERED");

    char script_path[1100];
    snprintf(script_path, sizeof(script_path), "python3 -u \"%s/SQL_Injection.py\" 2>&1", BASE_DIR);
    FILE *fp = popen(script_path, "r");
    if (!fp) {
        const char *err =
            "HTTP/1.1 500 Internal Server Error\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "Connection: close\r\n"
            "\r\n"
            "<h1>Error running SQL injection</h1>";
        return;
    }

    // buffer to accumulate attack output
    char attack_output[8192];
    attack_output[0] = '\0';

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        // append to big output string
        strncat(attack_output, line, sizeof(attack_output) - strlen(attack_output) - 1);

        // also print to terminal
        printf("[SQL_INJECTION] %s", line);
        fflush(stdout);

        // log each line as before
        write_log(ip, "SQL_INJECTION", "/attack-sql", line);
    }

    pclose(fp);

    // Build HTML page including attack output
    char response[16384];
    int n = snprintf(response, sizeof(response),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Connection: close\r\n"
        "\r\n"
        "<!doctype html>"
        "<html><head><title>SafeByte - SQL Injection</title>"
        "<style>"
        "body{font-family: 'Segoe UI', Arial, sans-serif; background: linear-gradient(135deg, #0a0a0a 0%%, #1a1a2e 100%%); color:#eee; padding:40px; min-height:100vh;}"
        ".logo{position:absolute; top:20px; right:30px; width:150px; background:rgba(255,255,255,0.05); padding:8px; border-radius:8px; text-align:center; color:#00d4ff; font-weight:bold; font-size:14px;}"
        "h1{font-size:48px; background:linear-gradient(45deg, #00d4ff, #ff6600); -webkit-background-clip:text; -webkit-text-fill-color:transparent; margin-bottom:10px;}"
        ".subtitle{color:#888; font-size:18px; margin-bottom:30px;}"
        ".card{background:rgba(25, 25, 40, 0.9); border:1px solid #333; border-radius:12px; padding:25px; box-shadow:0 8px 32px rgba(0,0,0,0.5);}"
        ".card h2{color:#00d4ff; font-size:22px; margin-bottom:20px;}"
        "pre{background:rgba(0,0,0,0.5); padding:20px; color:#00d4ff; border-radius:8px; border-left:3px solid #00d4ff; font-family:'Courier New', monospace; font-size:13px; line-height:1.6; overflow-x:auto;}"
        ".back-link{display:inline-block; margin-top:30px; color:#00d4ff; text-decoration:none; font-size:14px;}"
        ".back-link:hover{text-decoration:underline;}"
        "</style></head>"
        "<body>"
        "<div class='logo'>SafeByte</div>"
        "<h1>SQL Injection Attack</h1>"
        "<div class='subtitle'>Attack Execution Results</div>"
        "<div class='card'>"
        "<h2>💉 Output</h2>"
        "<pre>%s</pre>"
        "</div>"
        "<a href='/' class='back-link'>← Back to Home</a>"
        "</body></html>",
        attack_output
    );

    if (n > 0) {
        send(client_fd, response, (size_t)n, 0);
    }
}

// -----------------------------------------
// Attack history page
// -----------------------------------------

void send_attack_history_page(int client_fd) {
    struct AttackEvent events[256];
    int count = readAttackHistory(events, 256);

    char response[20000];
    int offset = snprintf(response, sizeof(response),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Connection: close\r\n\r\n"
        "<!doctype html>"
        "<html><head><title>SafeByte - Attack History</title>"
        "<style>"
        "body{font-family: 'Segoe UI', Arial, sans-serif; background: linear-gradient(135deg, #0a0a0a 0%%, #1a1a2e 100%%); color:#eee; padding:40px; min-height:100vh;}"
        ".logo{position:absolute; top:20px; right:30px; width:150px; background:rgba(255,255,255,0.05); padding:8px; border-radius:8px; text-align:center; color:#00d4ff; font-weight:bold; font-size:14px;}"
        "h1{font-size:48px; background:linear-gradient(45deg, #00d4ff, #ff6600); -webkit-background-clip:text; -webkit-text-fill-color:transparent; margin-bottom:10px;}"
        ".subtitle{color:#888; font-size:18px; margin-bottom:30px;}"
        ".card{background:rgba(25, 25, 40, 0.9); border:1px solid #333; border-radius:12px; padding:25px; box-shadow:0 8px 32px rgba(0,0,0,0.5);}"
        ".card h2{color:#00d4ff; font-size:22px; margin-bottom:20px;}"
        "table{width:100%%; border-collapse:collapse; background:rgba(0,0,0,0.3); border-radius:8px; overflow:hidden;}"
        "th{background:rgba(0,212,255,0.1); color:#00d4ff; padding:15px; text-align:left; font-weight:600; text-transform:uppercase; font-size:12px; letter-spacing:1px;}"
        "td{padding:15px; border-top:1px solid rgba(255,255,255,0.05); color:#ccc; font-size:14px;}"
        "tr:hover td{background:rgba(0,212,255,0.05);}"
        ".attack-count{margin-top:20px; padding:15px; background:rgba(0,212,255,0.1); border-radius:8px; color:#00d4ff; text-align:center; font-weight:bold;}"
        ".back-link{display:inline-block; margin-top:30px; color:#00d4ff; text-decoration:none; font-size:14px;}"
        ".back-link:hover{text-decoration:underline;}"
        "</style></head>"
        "<body>"
        "<div class='logo'>SafeByte</div>"
        "<h1>Attack History</h1>"
        "<div class='subtitle'>Logged Security Tests</div>"
        "<div class='card'>"
        "<h2>🎯 Attack Log</h2>"
        "<table>"
        "<tr><th>Timestamp</th><th>Actor</th><th>Type</th><th>Description</th></tr>"
    );

    for (int i = 0; i < count; i++) {
        offset += snprintf(response + offset, sizeof(response) - offset,
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
            events[i].timestamp,
            events[i].actor,
            events[i].type,
            events[i].description);
    }

    offset += snprintf(response + offset, sizeof(response) - offset,
        "</table>"
        "<div class='attack-count'>Total Attacks Logged: %d</div>"
        "</div>"
        "<a href='/' class='back-link'>← Back to Home</a>"
        "</body></html>",
        count
    );

    send(client_fd, response, (size_t)offset, 0);
}

// -----------------------------------------
// POST /log-attack  (called by XSS page JS)
// -----------------------------------------

void handle_log_attack_post(int client_fd, const char *body, const char *ip) {
    char actor[128] = "unknown";
    char type[128]  = "Unknown";
    char desc[256]  = "No description";

    if (body) {
        const char *p;

        p = strstr(body, "\"actor\"");
        if (p) { p = strchr(p, ':'); if (p) sscanf(p + 1, " \"%127[^\"]\"", actor); }

        p = strstr(body, "\"type\"");
        if (p) { p = strchr(p, ':'); if (p) sscanf(p + 1, " \"%127[^\"]\"", type); }

        p = strstr(body, "\"description\"");
        if (p) { p = strchr(p, ':'); if (p) sscanf(p + 1, " \"%255[^\"]\"", desc); }
    }

    time_t now = time(NULL);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));

    logAttackEvent(ts, actor, type, desc);
    write_log(ip, "POST", "/log-attack", "XSS_ATTACK_LOGGED");

    const char *resp =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n"
        "\r\n"
        "logged";
    send(client_fd, resp, strlen(resp), 0);
}

// -----------------------------------------
// Per-connection handler (runs in its own thread)
// -----------------------------------------

typedef struct { int client_fd; char ip[INET_ADDRSTRLEN]; } ConnArgs;

static void *handle_connection(void *arg) {
    ConnArgs *ca = (ConnArgs *)arg;
    int client_fd = ca->client_fd;
    char ip_str[INET_ADDRSTRLEN];
    strncpy(ip_str, ca->ip, sizeof(ip_str));
    free(ca);

    check_ddos(ip_str);

    // If defense is ON and this IP is blocked, return 429 immediately
    if (ddos_defense_enabled && is_blocked(ip_str)) {
        const char *blocked_resp =
            "HTTP/1.1 429 Too Many Requests\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "Retry-After: 10\r\n"
            "Connection: close\r\n"
            "\r\n"
            "<!doctype html>"
            "<html><head><title>429 - Rate Limited</title></head>"
            "<body style='font-family:Arial; background:#111; color:#eee; padding:40px;'>"
            "<h1 style='color:#ff4444;'>429 - Too Many Requests</h1>"
            "<p>Your IP has been rate-limited by the DDoS defense system.</p>"
            "<p><a href='/' style='color:#00d4ff;'>Back to Home</a></p>"
            "</body></html>";
        send(client_fd, blocked_resp, strlen(blocked_resp), 0);
        close(client_fd);
        return NULL;
    }

    // Read full request (headers + body)
    char buffer[BUF_SIZE];
    memset(buffer, 0, sizeof(buffer));
    int total = 0, bytes;
    while (total < (int)sizeof(buffer) - 1) {
        bytes = recv(client_fd, buffer + total, sizeof(buffer) - 1 - total, 0);
        if (bytes <= 0) break;
        total += bytes;
        // Stop once we have the full headers + body
        if (strstr(buffer, "\r\n\r\n")) {
            // Check Content-Length to see if we need to read more body
            char *cl = strstr(buffer, "Content-Length:");
            if (cl) {
                int content_len = atoi(cl + 15);
                char *body_start = strstr(buffer, "\r\n\r\n");
                if (body_start) {
                    int header_len = (int)(body_start - buffer) + 4;
                    int body_received = total - header_len;
                    if (body_received >= content_len) break;
                }
            } else {
                break; // no body expected
            }
        }
    }

    char method[8] = {0};
    char path[256] = {0};
    sscanf(buffer, "%7s %255s", method, path);

    char *body = strstr(buffer, "\r\n\r\n");
    if (body) body += 4;

    printf("DEBUG: method='%s' path='%s'\n", method, path);
    fflush(stdout);

    char debug_msg[300];
    snprintf(debug_msg, sizeof(debug_msg), "DEBUG: method='%s' path='%s'", method, path);
    write_log(ip_str, method, path, debug_msg);

    if (strcmp(method, "GET") == 0 && strcmp(path, "/") == 0) {
        write_log(ip_str, method, path, "200");
        send(client_fd, index_page, strlen(index_page), 0);
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/login") == 0) {
        write_log(ip_str, method, path, "200");
        send(client_fd, login_page, strlen(login_page), 0);
    } else if (strcmp(method, "POST") == 0 && strcmp(path, "/login") == 0) {
        handle_login_post(client_fd, body, ip_str);
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/dashboard") == 0) {
        write_log(ip_str, method, path, "200");
        send_dashboard_page(client_fd);
    } else if (strcmp(method, "GET") == 0 && strncmp(path, "/logs", 5) == 0) {
        write_log(ip_str, method, path, "200");
        send_logs_page(client_fd);
    } else if (strcmp(method, "GET") == 0 && strncmp(path, "/stats", 6) == 0) {
        write_log(ip_str, method, path, "200");
        send_stats_json(client_fd);
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/vulnerable") == 0) {
        write_log(ip_str, method, path, "200");
        send_vulnerable_page(client_fd);
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/xss-defense-status") == 0) {
    send_xss_defense_status(client_fd);
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/users") == 0) {
        write_log(ip_str, method, path, "200");
        send_users_page(client_fd);
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/add-user") == 0) {
        write_log(ip_str, method, path, "200");
        send_add_user_form(client_fd);
    } else if (strcmp(method, "POST") == 0 && strcmp(path, "/add-user") == 0) {
        handle_add_user_post(client_fd, body, ip_str);
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/attack-sql") == 0) {
        write_log(ip_str, method, path, "200");
        run_sql_attack(client_fd, ip_str);
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/ddos-dashboard") == 0) {
        write_log(ip_str, method, path, "200");
        send_ddos_dashboard(client_fd);
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/logo") == 0) {
        write_log(ip_str, method, path, "200");
        send_logo(client_fd);
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/attack-history") == 0) {
        write_log(ip_str, method, path, "200");
        send_attack_history_page(client_fd);
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/enable-sql-defense") == 0) {
        write_log(ip_str, method, path, "200");
        send_enable_sql_defense_page(client_fd, ip_str);
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/disable-sql-defense") == 0) {
        write_log(ip_str, method, path, "200");
        send_disable_sql_defense_page(client_fd, ip_str);
    }else if (strcmp(method, "GET") == 0 && strcmp(path, "/enable-xss-defense") == 0) {
    write_log(ip_str, method, path, "200");
    send_enable_xss_defense_page(client_fd, ip_str);
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/disable-xss-defense") == 0) {
    write_log(ip_str, method, path, "200");
    send_disable_xss_defense_page(client_fd, ip_str);    
    } else if (strcmp(method, "POST") == 0 && strcmp(path, "/log-attack") == 0) {
        handle_log_attack_post(client_fd, body, ip_str);
    } else if (strcmp(method, "POST") == 0 && strcmp(path, "/attack") == 0) {
        handle_ddos_attack_post(client_fd, body, ip_str);
    } else if (strcmp(method, "POST") == 0 && strcmp(path, "/stop") == 0) {
        handle_ddos_stop_post(client_fd);
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/status") == 0) {
        handle_ddos_status_get(client_fd);
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/ddos-defense") == 0) {
        write_log(ip_str, method, path, "200");
        send_ddos_defense_page(client_fd, ip_str);
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/defense-status") == 0) {
        handle_ddos_defense_status(client_fd);
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/enable-ddos-defense") == 0) {
        send_enable_ddos_defense_page(client_fd, ip_str);
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/disable-ddos-defense") == 0) {
        send_disable_ddos_defense_page(client_fd, ip_str);
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/clear-ddos-blocklist") == 0) {
        handle_clear_ddos_blocklist(client_fd, ip_str);
    } else {
        write_log(ip_str, method, path, "404");
        send(client_fd, not_found_page, strlen(not_found_page), 0);
    }

    close(client_fd);
    return NULL;
}

static void *ddos_worker(void *arg) {
    (void)arg;

    pthread_mutex_lock(&ddos_mutex);
    char target[512];
    strncpy(target, ddos_state.target_url, sizeof(target) - 1);
    int reqs = ddos_state.requests_per_thread;
    pthread_mutex_unlock(&ddos_mutex);

    // Parse host and port from target URL (http://host:port/path)
    char host[256] = "127.0.0.1";
    int  port      = 8080;
    char path[256] = "/";

    const char *p = target;
    if (strncmp(p, "http://", 7) == 0) p += 7;
    else if (strncmp(p, "https://", 8) == 0) p += 8;

    char hostport[256] = {0};
    const char *slash = strchr(p, '/');
    if (slash) {
        size_t hplen = (size_t)(slash - p);
        if (hplen >= sizeof(hostport)) hplen = sizeof(hostport) - 1;
        strncpy(hostport, p, hplen);
        hostport[hplen] = '\0';
        strncpy(path, slash, sizeof(path) - 1);
    } else {
        strncpy(hostport, p, sizeof(hostport) - 1);
    }

    char *colon = strchr(hostport, ':');
    if (colon) {
        *colon = '\0';
        port = atoi(colon + 1);
    }
    strncpy(host, hostport, sizeof(host) - 1);

    for (int i = 0; i < reqs; i++) {
        pthread_mutex_lock(&ddos_mutex);
        int should_stop = ddos_state.stop_flag;
        pthread_mutex_unlock(&ddos_mutex);
        if (should_stop) break;

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            pthread_mutex_lock(&ddos_mutex);
            ddos_state.failed++;
            ddos_state.total_requests++;
            pthread_mutex_unlock(&ddos_mutex);
            continue;
        }

        struct timeval tv = {1, 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        struct sockaddr_in saddr = {0};
        saddr.sin_family = AF_INET;
        saddr.sin_port   = htons((uint16_t)port);

        // Use getaddrinfo so "localhost" resolves correctly, not just numeric IPs
        struct addrinfo hints = {0}, *res = NULL;
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", port);
        if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) {
            close(sock);
            pthread_mutex_lock(&ddos_mutex);
            ddos_state.failed++;
            ddos_state.total_requests++;
            pthread_mutex_unlock(&ddos_mutex);
            continue;
        }
        memcpy(&saddr, res->ai_addr, res->ai_addrlen);
        freeaddrinfo(res);

        int ok = 0;
        if (connect(sock, (struct sockaddr *)&saddr, sizeof(saddr)) == 0) {
            char req[512];
            snprintf(req, sizeof(req),
                "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n",
                path, host);
            if (send(sock, req, strlen(req), 0) > 0) {
                char buf[256];
                if (recv(sock, buf, sizeof(buf) - 1, 0) > 0) ok = 1;
            }
        }
        close(sock);

        pthread_mutex_lock(&ddos_mutex);
        ddos_state.total_requests++;
        if (ok) ddos_state.successful++;
        else    ddos_state.failed++;

        time_t now = time(NULL);
        ddos_state.elapsed = difftime(now, ddos_state.start_time);
        if (ddos_state.elapsed > 0)
            ddos_state.current_rps = ddos_state.total_requests / ddos_state.elapsed;
        pthread_mutex_unlock(&ddos_mutex);
    }

    pthread_mutex_lock(&ddos_mutex);
    ddos_state.threads_active--;
    if (ddos_state.threads_active <= 0) {
        ddos_state.running        = 0;
        ddos_state.threads_active = 0;
    }
    pthread_mutex_unlock(&ddos_mutex);

    return NULL;
}

// POST /attack
void handle_ddos_attack_post(int client_fd, const char *body, const char *ip) {
    char target[512] = "http://127.0.0.1:8080/";
    int  threads     = 5;
    int  requests    = 50;

    if (body) {
        const char *p;
        p = strstr(body, "\"target_url\"");
        if (p) { p = strchr(p, ':'); if (p) sscanf(p + 1, " \"%511[^\"]\"", target); }
        p = strstr(body, "\"threads\"");
        if (p) { p = strchr(p, ':'); if (p) sscanf(p + 1, " %d", &threads); }
        p = strstr(body, "\"requests\"");
        if (p) { p = strchr(p, ':'); if (p) sscanf(p + 1, " %d", &requests); }
    }

    if (threads < 1)  threads  = 1;
    if (threads > 50) threads  = 50;
    if (requests < 1) requests = 1;
    if (requests > 500) requests = 500;

    // Log the attack event
    time_t now = time(NULL);
    char ts[64], desc[256];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
    snprintf(desc, sizeof(desc), "DDoS launched – %d threads x %d requests → %s",
             threads, requests, target);
    logAttackEvent(ts, ip, "DDoS", desc);

    pthread_mutex_lock(&ddos_mutex);
    ddos_state.running          = 1;
    ddos_state.stop_flag        = 0;
    ddos_state.total_requests   = 0;
    ddos_state.successful       = 0;
    ddos_state.failed           = 0;
    ddos_state.threads_active   = threads;
    ddos_state.elapsed          = 0;
    ddos_state.current_rps      = 0;
    ddos_state.requests_per_thread = requests;
    strncpy(ddos_state.target_url, target, sizeof(ddos_state.target_url) - 1);
    ddos_state.start_time       = now;
    pthread_mutex_unlock(&ddos_mutex);

    for (int i = 0; i < threads; i++) {
        pthread_t tid;
        pthread_create(&tid, NULL, ddos_worker, NULL);
        pthread_detach(tid);
    }

    const char *resp =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n"
        "\r\n"
        "{\"status\":\"started\"}";
    send(client_fd, resp, strlen(resp), 0);
}

// POST /stop
void handle_ddos_stop_post(int client_fd) {
    pthread_mutex_lock(&ddos_mutex);
    ddos_state.stop_flag = 1;
    ddos_state.running   = 0;
    pthread_mutex_unlock(&ddos_mutex);

    const char *resp =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n"
        "\r\n"
        "{\"status\":\"stopped\"}";
    send(client_fd, resp, strlen(resp), 0);
}

// GET /status
void handle_ddos_status_get(int client_fd) {
    pthread_mutex_lock(&ddos_mutex);
    int    running  = ddos_state.running;
    int    total    = ddos_state.total_requests;
    int    succ     = ddos_state.successful;
    int    fail     = ddos_state.failed;
    int    tactive  = ddos_state.threads_active;
    double elapsed  = ddos_state.elapsed;
    double rps      = ddos_state.current_rps;
    pthread_mutex_unlock(&ddos_mutex);

    char body[512];
    int  blen = snprintf(body, sizeof(body),
        "{\"running\":%s,\"total_requests\":%d,\"successful\":%d,"
        "\"failed\":%d,\"threads_active\":%d,\"elapsed\":%.1f,\"current_rps\":%.1f}",
        running ? "true" : "false", total, succ, fail, tactive, elapsed, rps);

    char resp[768];
    snprintf(resp, sizeof(resp),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s", blen, body);
    send(client_fd, resp, strlen(resp), 0);
}
// ============================================================================

void send_enable_sql_defense_page(int client_fd, const char *ip) {
    sql_defense_enabled = 1;

    time_t now = time(NULL);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    logAttackEvent(ts, ip, "SQL Defense Enabled", "Administrator enabled SQL injection protection");
    write_log(ip, "GET", "/enable-sql-defense", "DEFENSE_ENABLED");

    const char *resp =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Connection: close\r\n"
        "\r\n"
        "<!doctype html>"
        "<html><head><title>SafeByte - SQL Defense</title>"
        "<style>"
        "body{font-family: 'Segoe UI', Arial, sans-serif; background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%); color:#eee; padding:40px; min-height:100vh; display:flex; align-items:center; justify-content:center;}"
        ".logo{position:absolute; top:20px; right:30px; width:150px; background:rgba(255,255,255,0.05); padding:8px; border-radius:8px; text-align:center; color:#00d4ff; font-weight:bold; font-size:14px;}"
        ".container{background:rgba(25, 25, 40, 0.9); border:1px solid #00ff88; border-radius:12px; padding:40px; max-width:550px; box-shadow:0 8px 32px rgba(0,0,0,0.5); text-align:center;}"
        "h1{font-size:36px; color:#00ff88; margin-bottom:20px;}"
        "p{color:#ccc; line-height:1.6; margin:15px 0;}"
        ".status{background:rgba(0,255,136,0.1); padding:20px; border-left:4px solid #00ff88; margin:20px 0; border-radius:4px;}"
        "a{color:#00d4ff; text-decoration:none; margin:0 10px;}"
        "a:hover{text-decoration:underline;}"
        "</style></head>"
        "<body>"
        "<div class='logo'>SafeByte</div>"
        "<div class='container'>"
        "<h1>🛡️ SQL Defense Enabled</h1>"
        "<div class='status'>"
        "<strong>Protection Active</strong><br>"
        "SQL injection attempts will now be blocked."
        "</div>"
        "<p>The system will detect and prevent SQL injection attacks in real-time.</p>"
        "<p style='margin-top:30px;'>"
        "<a href='/add-user'>Try Adding User</a> | "
        "<a href='/disable-sql-defense'>Disable Defense</a> | "
        "<a href='/'>Home</a>"
        "</p>"
        "</div>"
        "</body></html>";

    send(client_fd, resp, strlen(resp), 0);
}

void send_disable_sql_defense_page(int client_fd, const char *ip) {
    sql_defense_enabled = 0;

    time_t now = time(NULL);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    logAttackEvent(ts, ip, "SQL Defense Disabled", "Administrator disabled SQL injection protection");
    write_log(ip, "GET", "/disable-sql-defense", "DEFENSE_DISABLED");

    const char *resp =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Connection: close\r\n"
        "\r\n"
        "<!doctype html>"
        "<html><head><title>SafeByte - SQL Defense</title>"
        "<style>"
        "body{font-family: 'Segoe UI', Arial, sans-serif; background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%); color:#eee; padding:40px; min-height:100vh; display:flex; align-items:center; justify-content:center;}"
        ".logo{position:absolute; top:20px; right:30px; width:150px; background:rgba(255,255,255,0.05); padding:8px; border-radius:8px; text-align:center; color:#00d4ff; font-weight:bold; font-size:14px;}"
        ".container{background:rgba(25, 25, 40, 0.9); border:1px solid #ff9900; border-radius:12px; padding:40px; max-width:550px; box-shadow:0 8px 32px rgba(0,0,0,0.5); text-align:center;}"
        "h1{font-size:36px; color:#ff9900; margin-bottom:20px;}"
        "p{color:#ccc; line-height:1.6; margin:15px 0;}"
        ".warning{background:rgba(255,153,0,0.1); padding:20px; border-left:4px solid #ff9900; margin:20px 0; border-radius:4px;}"
        "a{color:#00d4ff; text-decoration:none; margin:0 10px;}"
        "a:hover{text-decoration:underline;}"
        "</style></head>"
        "<body>"
        "<div class='logo'>SafeByte</div>"
        "<div class='container'>"
        "<h1>⚠️ SQL Defense Disabled</h1>"
        "<div class='warning'>"
        "<strong>Vulnerable Mode</strong><br>"
        "SQL injection attacks will NOT be blocked."
        "</div>"
        "<p>The system is now vulnerable to SQL injection for training purposes.</p>"
        "<p style='margin-top:30px;'>"
        "<a href='/add-user'>Try Adding User</a> | "
        "<a href='/enable-sql-defense'>Enable Defense</a> | "
        "<a href='/'>Home</a>"
        "</p>"
        "</div>"
        "</body></html>";

    send(client_fd, resp, strlen(resp), 0);
}

// xss defense stuff

void send_enable_xss_defense_page(int client_fd, const char *ip) {
    xss_defense_enabled = 1;
    write_log(ip, "GET", "/enable-xss-defense", "XSS_DEFENSE_ENABLED");

    const char *resp =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Connection: close\r\n"
        "\r\n"
        "<!doctype html>"
        "<html><head><title>SafeByte - XSS Defense Enabled</title>"
        "<style>"
        "body{font-family:'Segoe UI',Arial,sans-serif;background:linear-gradient(135deg,#0a0a0a 0%,#1a1a2e 100%);color:#eee;padding:40px;min-height:100vh;display:flex;align-items:center;justify-content:center;}"
        ".container{background:rgba(25,25,40,0.92);border:1px solid #00ff88;border-radius:18px;padding:52px;max-width:760px;width:100%;box-shadow:0 10px 38px rgba(0,0,0,0.55);text-align:center;}"
        "h1{font-size:60px;color:#00ff88;margin-bottom:26px;}"
        ".status{background:rgba(0,255,136,0.12);border-left:5px solid #00ff88;border-radius:8px;padding:22px;margin-bottom:26px;font-size:20px;color:#dfffe8;}"
        "p{font-size:18px;color:#ccc;margin-bottom:30px;}"
        ".links a{color:#00d4ff;text-decoration:none;font-size:18px;margin:0 14px;}"
        ".links a:hover{text-decoration:underline;}"
        "</style></head>"
        "<body>"
        "<div class='container'>"
        "<h1>🛡️ XSS Defense Enabled</h1>"
        "<div class='status'><strong>Protection Active</strong><br>Stored XSS payloads will now be shown safely instead of executing.</div>"
        "<p>The system is now sanitizing comment content for the XSS demo.</p>"
        "<div class='links'>"
        "<a href='/vulnerable'>Try XSS Demo</a> | "
        "<a href='/disable-xss-defense'>Disable Defense</a> | "
        "<a href='/'>Home</a>"
        "</div>"
        "</div>"
        "</body></html>";

    send(client_fd, resp, strlen(resp), 0);
}

void send_disable_xss_defense_page(int client_fd, const char *ip) {
    xss_defense_enabled = 0;
    write_log(ip, "GET", "/disable-xss-defense", "XSS_DEFENSE_DISABLED");

    const char *resp =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Connection: close\r\n"
        "\r\n"
        "<!doctype html>"
        "<html><head><title>SafeByte - XSS Defense Disabled</title>"
        "<style>"
        "body{font-family:'Segoe UI',Arial,sans-serif;background:linear-gradient(135deg,#0a0a0a 0%,#1a1a2e 100%);color:#eee;padding:40px;min-height:100vh;display:flex;align-items:center;justify-content:center;}"
        ".container{background:rgba(25,25,40,0.92);border:1px solid #ff9900;border-radius:18px;padding:52px;max-width:760px;width:100%;box-shadow:0 10px 38px rgba(0,0,0,0.55);text-align:center;}"
        "h1{font-size:60px;color:#ff9900;margin-bottom:26px;}"
        ".status{background:rgba(255,153,0,0.12);border-left:5px solid #ff9900;border-radius:8px;padding:22px;margin-bottom:26px;font-size:20px;color:#ffe7c2;}"
        "p{font-size:18px;color:#ccc;margin-bottom:30px;}"
        ".links a{color:#00d4ff;text-decoration:none;font-size:18px;margin:0 14px;}"
        ".links a:hover{text-decoration:underline;}"
        "</style></head>"
        "<body>"
        "<div class='container'>"
        "<h1>⚠️ XSS Defense Disabled</h1>"
        "<div class='status'><strong>Vulnerable Mode</strong><br>Stored XSS payloads will execute when comments are rendered.</div>"
        "<p>The system is now intentionally vulnerable to stored XSS for training purposes.</p>"
        "<div class='links'>"
        "<a href='/vulnerable'>Try XSS Demo</a> | "
        "<a href='/enable-xss-defense'>Enable Defense</a> | "
        "<a href='/'>Home</a>"
        "</div>"
        "</div>"
        "</body></html>";

    send(client_fd, resp, strlen(resp), 0);
}


// ============================================================================
// DDoS Defense Pages
// ============================================================================

void send_ddos_defense_page(int client_fd, const char *ip) {
    (void)ip;

    // Build blocked IP rows
    char ip_rows[4096] = "";
    if (blocked_ip_count == 0) {
        strcat(ip_rows, "<tr><td colspan='3' style='color:#666;text-align:center;padding:20px;'>No IPs currently blocked</td></tr>");
    } else {
        for (int i = 0; i < blocked_ip_count; i++) {
            char row[256];
            snprintf(row, sizeof(row),
                "<tr><td>%d</td><td>%s</td><td><span style='color:#ff4444;font-weight:bold;'>BLOCKED</span></td></tr>",
                i + 1, blocked_ips[i]);
            strncat(ip_rows, row, sizeof(ip_rows) - strlen(ip_rows) - 1);
        }
    }

    char resp[10240];
    snprintf(resp, sizeof(resp),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Connection: close\r\n"
        "\r\n"
        "<!doctype html>"
        "<html><head><title>SafeByte - DDoS Defense</title>"
        "<meta http-equiv='refresh' content='3'>"
        "<style>"
        "body{font-family:'Segoe UI',Arial,sans-serif;background:linear-gradient(135deg,#0a0a0a 0%%,#1a1a2e 100%%);color:#eee;padding:40px;min-height:100vh;}"
        ".logo{position:absolute;top:20px;right:30px;width:150px;background:rgba(255,255,255,0.05);padding:8px;border-radius:8px;text-align:center;color:#00d4ff;font-weight:bold;font-size:14px;}"
        "h1{font-size:48px;background:linear-gradient(45deg,#00d4ff,#ff6600);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:10px;}"
        ".subtitle{color:#888;font-size:18px;margin-bottom:30px;}"
        ".card{background:rgba(25,25,40,0.9);border:1px solid #333;border-radius:12px;padding:25px;margin-bottom:20px;box-shadow:0 8px 32px rgba(0,0,0,0.5);}"
        ".card h2{color:#00d4ff;font-size:22px;margin-bottom:20px;}"
        ".toggle-row{display:flex;align-items:center;gap:20px;margin-bottom:20px;}"
        ".toggle-label{font-size:18px;font-weight:bold;}"
        ".toggle{position:relative;width:70px;height:36px;cursor:pointer;}"
        ".toggle input{opacity:0;width:0;height:0;}"
        ".slider{position:absolute;top:0;left:0;right:0;bottom:0;background:#333;border-radius:36px;transition:0.3s;}"
        ".slider:before{position:absolute;content:'';height:28px;width:28px;left:4px;bottom:4px;background:#fff;border-radius:50%%;transition:0.3s;}"
        "input:checked + .slider{background:linear-gradient(45deg,#00ff88,#00cc66);}"
        "input:checked + .slider:before{transform:translateX(34px);}"
        ".status-banner{padding:15px 20px;border-radius:8px;margin-bottom:20px;font-weight:bold;font-size:16px;}"
        ".banner-on{background:rgba(0,255,136,0.15);border:1px solid #00ff88;color:#00ff88;}"
        ".banner-off{background:rgba(255,68,68,0.15);border:1px solid #ff4444;color:#ff4444;}"
        ".info{background:rgba(0,212,255,0.05);border-left:4px solid #00d4ff;padding:15px;border-radius:4px;margin-bottom:20px;font-size:14px;color:#aaa;line-height:1.7;}"
        ".btn{display:inline-block;padding:11px 24px;border-radius:8px;text-decoration:none;font-weight:bold;font-size:14px;margin-right:10px;margin-top:8px;transition:all 0.3s;cursor:pointer;border:none;}"
        ".btn-gray{background:linear-gradient(45deg,#555,#777);color:#fff;}"
        ".btn-home{background:linear-gradient(45deg,#00d4ff,#0099cc);color:#fff;}"
        ".btn:hover{transform:translateY(-2px);opacity:0.9;}"
        "table{width:100%%;border-collapse:collapse;background:rgba(0,0,0,0.3);border-radius:8px;overflow:hidden;}"
        "th{background:rgba(0,212,255,0.1);color:#00d4ff;padding:12px 15px;text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:1px;}"
        "td{padding:12px 15px;border-top:1px solid rgba(255,255,255,0.05);color:#ccc;}"
        "tr:hover td{background:rgba(0,212,255,0.04);}"
        ".count-badge{display:inline-block;background:rgba(255,68,68,0.2);color:#ff4444;border-radius:20px;padding:2px 12px;font-size:13px;margin-left:8px;}"
        ".back-link{display:inline-block;margin-top:30px;color:#00d4ff;text-decoration:none;font-size:14px;}"
        ".refresh-note{color:#555;font-size:12px;margin-top:8px;}"
        "</style></head>"
        "<body>"
        "<div class='logo'>SafeByte</div>"
        "<h1>DDoS Defense</h1>"
        "<div class='subtitle'>Rate Limiting &amp; IP Blocking</div>"

        "<div class='card'>"
        "<h2>🛡️ Defense Toggle</h2>"
        "<div class='status-banner %s'>%s</div>"
        "<div class='toggle-row'>"
        "  <span class='toggle-label'>Defense is %s</span>"
        "  <a href='/%s-ddos-defense'>"
        "    <label class='toggle'>"
        "      <input type='checkbox' %s disabled>"
        "      <span class='slider'></span>"
        "    </label>"
        "  </a>"
        "  <a href='/%s-ddos-defense' class='btn %s'>%s</a>"
        "</div>"
        "<div class='info'>"
        "When <strong>ON</strong>, any IP sending <strong>%d or more requests within %d seconds</strong> "
        "is automatically blocked and receives a <code style='background:rgba(0,0,0,0.4);padding:2px 6px;border-radius:3px;'>429 Too Many Requests</code>. "
        "The <strong>DDoS Attack Dashboard</strong> will show requests failing once the attacking IP is blocked — "
        "open both tabs to observe the defense in action."
        "</div>"
        "</div>"

        "<div class='card'>"
        "<h2>🚫 Blocked IPs <span class='count-badge'>%d blocked</span></h2>"
        "<table>"
        "<tr><th>#</th><th>IP Address</th><th>Status</th></tr>"
        "%s"
        "</table>"
        "<div style='margin-top:15px;'>"
        "<a href='/clear-ddos-blocklist' class='btn btn-gray'>Clear Blocklist</a>"
        "</div>"
        "<div class='refresh-note'>⟳ Page auto-refreshes every 3 seconds to show new blocks</div>"
        "</div>"

        "<a href='/' class='btn btn-home' style='margin-top:10px;'>← Back to Home</a>"
        "</body></html>",

        // banner class + text
        ddos_defense_enabled ? "banner-on" : "banner-off",
        ddos_defense_enabled
            ? "✅ Defense is ON — attacking IPs will be rate-limited and blocked"
            : "❌ Defense is OFF — all requests pass through unrestricted",
        // toggle label
        ddos_defense_enabled ? "ON" : "OFF",
        // toggle href action
        ddos_defense_enabled ? "disable" : "enable",
        // checkbox checked state
        ddos_defense_enabled ? "checked" : "",
        // button href + style + text
        ddos_defense_enabled ? "disable" : "enable",
        ddos_defense_enabled ? "btn-gray" : "btn-home",
        ddos_defense_enabled ? "Turn OFF" : "Turn ON",
        // info thresholds
        DDOS_THRESHOLD, DDOS_WINDOW_SECS,
        // blocked count + rows
        blocked_ip_count,
        ip_rows
    );

    send(client_fd, resp, strlen(resp), 0);
}

void send_enable_ddos_defense_page(int client_fd, const char *ip) {
    ddos_defense_enabled = 1;

    time_t now = time(NULL);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
    logAttackEvent(ts, ip, "DDoS Defense Enabled", "Administrator enabled DDoS rate-limit protection");
    write_log(ip, "GET", "/enable-ddos-defense", "DDOS_DEFENSE_ENABLED");

    const char *resp =
        "HTTP/1.1 302 Found\r\n"
        "Location: /ddos-defense\r\n"
        "Connection: close\r\n"
        "\r\n";
    send(client_fd, resp, strlen(resp), 0);
}

void send_disable_ddos_defense_page(int client_fd, const char *ip) {
    ddos_defense_enabled = 0;

    time_t now = time(NULL);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
    logAttackEvent(ts, ip, "DDoS Defense Disabled", "Administrator disabled DDoS rate-limit protection");
    write_log(ip, "GET", "/disable-ddos-defense", "DDOS_DEFENSE_DISABLED");

    const char *resp =
        "HTTP/1.1 302 Found\r\n"
        "Location: /ddos-defense\r\n"
        "Connection: close\r\n"
        "\r\n";
    send(client_fd, resp, strlen(resp), 0);
}

void handle_clear_ddos_blocklist(int client_fd, const char *ip) {
    clear_blocklist();

    time_t now = time(NULL);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
    logAttackEvent(ts, ip, "DDoS Blocklist Cleared", "Administrator cleared the IP blocklist");
    write_log(ip, "GET", "/clear-ddos-blocklist", "DDOS_BLOCKLIST_CLEARED");

    const char *resp =
        "HTTP/1.1 302 Found\r\n"
        "Location: /ddos-defense\r\n"
        "Connection: close\r\n"
        "\r\n";
    send(client_fd, resp, strlen(resp), 0);
}

void handle_ddos_defense_status(int client_fd) {
    char body[64];
    int blen = snprintf(body, sizeof(body),
        "{\"enabled\":%s}", ddos_defense_enabled ? "true" : "false");
    char resp[256];
    snprintf(resp, sizeof(resp),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s", blen, body);
    send(client_fd, resp, strlen(resp), 0);
}

// ============================================================================
// If running locally, Attack Agent will be at http://127.0.0.1:9000
// If using VMs, edit the JavaScript in send_ddos_dashboard() to use your VM's IP

void send_ddos_dashboard(int client_fd) {
    const char *dashboard = 
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Connection: close\r\n"
        "\r\n"
        "<!doctype html>\n"
        "<html><head>\n"
        "<title>SafeByte - DDoS Attack Dashboard</title>\n"
        "<meta charset='UTF-8'>\n"
        "<style>\n"
        "  * { margin: 0; padding: 0; box-sizing: border-box; }\n"
        "  body {\n"
        "    font-family: 'Segoe UI', Arial, sans-serif;\n"
        "    background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%);\n"
        "    color: #eee;\n"
        "    padding: 20px;\n"
        "    min-height: 100vh;\n"
        "  }\n"
        "  .logo {\n"
        "    position: absolute;\n"
        "    top: 20px;\n"
        "    right: 30px;\n"
        "    width: 180px;\n"
        "    height: auto;\n"
        "  }\n"
        "  .header {\n"
        "    text-align: center;\n"
        "    margin-bottom: 30px;\n"
        "    padding-top: 10px;\n"
        "  }\n"
        "  h1 {\n"
        "    font-size: 42px;\n"
        "    background: linear-gradient(45deg, #00d4ff, #ff6600);\n"
        "    -webkit-background-clip: text;\n"
        "    -webkit-text-fill-color: transparent;\n"
        "    margin-bottom: 10px;\n"
        "  }\n"
        "  .subtitle { color: #888; font-size: 16px; }\n"
        "  .container {\n"
        "    max-width: 1400px;\n"
        "    margin: 0 auto;\n"
        "  }\n"
        "  .control-panel {\n"
        "    background: rgba(25, 25, 40, 0.9);\n"
        "    border: 1px solid #333;\n"
        "    border-radius: 12px;\n"
        "    padding: 25px;\n"
        "    margin-bottom: 20px;\n"
        "    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);\n"
        "  }\n"
        "  .form-grid {\n"
        "    display: grid;\n"
        "    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));\n"
        "    gap: 20px;\n"
        "    margin-bottom: 20px;\n"
        "  }\n"
        "  .form-group {\n"
        "    display: flex;\n"
        "    flex-direction: column;\n"
        "  }\n"
        "  label {\n"
        "    color: #aaa;\n"
        "    font-size: 13px;\n"
        "    margin-bottom: 8px;\n"
        "    text-transform: uppercase;\n"
        "    letter-spacing: 0.5px;\n"
        "  }\n"
        "  input[type='text'], input[type='number'] {\n"
        "    background: rgba(10, 10, 20, 0.8);\n"
        "    border: 1px solid #444;\n"
        "    border-radius: 6px;\n"
        "    padding: 12px;\n"
        "    color: #fff;\n"
        "    font-size: 16px;\n"
        "    transition: all 0.3s;\n"
        "  }\n"
        "  input:focus {\n"
        "    outline: none;\n"
        "    border-color: #00d4ff;\n"
        "    box-shadow: 0 0 10px rgba(0, 212, 255, 0.3);\n"
        "  }\n"
        "  .btn-group {\n"
        "    display: flex;\n"
        "    gap: 15px;\n"
        "    justify-content: center;\n"
        "  }\n"
        "  button {\n"
        "    padding: 15px 40px;\n"
        "    font-size: 16px;\n"
        "    font-weight: bold;\n"
        "    border: none;\n"
        "    border-radius: 8px;\n"
        "    cursor: pointer;\n"
        "    transition: all 0.3s;\n"
        "    text-transform: uppercase;\n"
        "    letter-spacing: 1px;\n"
        "  }\n"
        "  .btn-attack {\n"
        "    background: linear-gradient(45deg, #00d4ff, #0099cc);\n"
        "    color: white;\n"
        "    box-shadow: 0 4px 15px rgba(0, 212, 255, 0.4);\n"
        "  }\n"
        "  .btn-attack:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(0, 212, 255, 0.6); }\n"
        "  .btn-stop {\n"
        "    background: linear-gradient(45deg, #666, #888);\n"
        "    color: white;\n"
        "  }\n"
        "  .btn-stop:hover { background: linear-gradient(45deg, #888, #aaa); }\n"
        "  .stats-grid {\n"
        "    display: grid;\n"
        "    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));\n"
        "    gap: 20px;\n"
        "    margin-bottom: 20px;\n"
        "  }\n"
        "  .stat-card {\n"
        "    background: rgba(25, 25, 40, 0.9);\n"
        "    border: 1px solid #333;\n"
        "    border-radius: 12px;\n"
        "    padding: 20px;\n"
        "    text-align: center;\n"
        "    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);\n"
        "  }\n"
        "  .stat-label {\n"
        "    color: #888;\n"
        "    font-size: 12px;\n"
        "    text-transform: uppercase;\n"
        "    margin-bottom: 10px;\n"
        "    letter-spacing: 1px;\n"
        "  }\n"
        "  .stat-value {\n"
        "    font-size: 32px;\n"
        "    font-weight: bold;\n"
        "    color: #00d4ff;\n"
        "  }\n"
        "  .stat-value.success { color: #00ff88; }\n"
        "  .stat-value.failed { color: #ff4444; }\n"
        "  .stat-value.rps { color: #ffaa00; }\n"
        "  .visual-area {\n"
        "    background: rgba(25, 25, 40, 0.9);\n"
        "    border: 1px solid #333;\n"
        "    border-radius: 12px;\n"
        "    padding: 25px;\n"
        "    min-height: 300px;\n"
        "    position: relative;\n"
        "    overflow: hidden;\n"
        "  }\n"
        "  .visual-title {\n"
        "    font-size: 18px;\n"
        "    color: #00d4ff;\n"
        "    margin-bottom: 20px;\n"
        "    text-align: center;\n"
        "  }\n"
        "  #attackCanvas {\n"
        "    width: 100%%;\n"
        "    height: 250px;\n"
        "    background: rgba(0, 0, 0, 0.3);\n"
        "    border-radius: 8px;\n"
        "  }\n"
        "  .status-badge {\n"
        "    display: inline-block;\n"
        "    padding: 6px 16px;\n"
        "    border-radius: 20px;\n"
        "    font-size: 12px;\n"
        "    font-weight: bold;\n"
        "    text-transform: uppercase;\n"
        "    letter-spacing: 1px;\n"
        "  }\n"
        "  .status-idle { background: #444; color: #aaa; }\n"
        "  .status-running { background: #ff3300; color: #fff; animation: pulse 1.5s infinite; }\n"
        "  @keyframes pulse {\n"
        "    0%, 100%% { opacity: 1; }\n"
        "    50%% { opacity: 0.7; }\n"
        "  }\n"
        "  .back-link {\n"
        "    display: inline-block;\n"
        "    margin-top: 20px;\n"
        "    color: #00d4ff;\n"
        "    text-decoration: none;\n"
        "    font-size: 14px;\n"
        "  }\n"
        "  .back-link:hover { text-decoration: underline; }\n"
        "</style>\n"
        "</head>\n"
        "<body>\n"
        "<img src='/logo' class='logo' alt='SafeByte Logo'>\n"
        "<div class='container'>\n"
        "  <div class='header'>\n"
        "    <h1>DDoS Attack Dashboard</h1>\n"
        "    <div class='subtitle'>Real-Time Attack Monitoring & Control</div>\n"
        "  </div>\n"
        "  \n"
        "  <div class='control-panel'>\n"
        "    <h3 style='margin-bottom:20px; color:#00d4ff;'>Attack Configuration</h3>\n"
        "    <div class='form-grid'>\n"
        "      <div class='form-group'>\n"
        "        <label>Target URL</label>\n"
        "        <input type='text' id='targetUrl' value='http://192.168.1.100:8080' placeholder='http://target:port'>\n"
        "      </div>\n"
        "      <div class='form-group'>\n"
        "        <label>Threads</label>\n"
        "        <input type='number' id='threads' value='30' min='1' max='100'>\n"
        "      </div>\n"
        "      <div class='form-group'>\n"
        "        <label>Requests per Thread</label>\n"
        "        <input type='number' id='requests' value='100' min='1' max='1000'>\n"
        "      </div>\n"
        "    </div>\n"
        "    <div class='btn-group'>\n"
        "      <button class='btn-attack' onclick='startAttack()'>Launch Attack</button>\n"
        "      <button class='btn-stop' onclick='stopAttack()'>Stop Attack</button>\n"
        "    </div>\n"
        "  </div>\n"
        "  \n"
        "  <div style='text-align:center; margin-bottom:20px;'>\n"
        "    <span class='status-badge' id='statusBadge'>Idle</span>\n"
        "  </div>\n"
        "  <div id='defenseBanner' style='display:none;background:rgba(0,255,136,0.1);border:1px solid #00ff88;border-radius:8px;padding:14px 20px;margin-bottom:20px;color:#00ff88;font-weight:bold;text-align:center;'>\n"
        "    🛡️ DDoS Defense is ON — attacking IPs will be blocked after 15 requests in 5s. "
        "Watch the Failed counter increase as blocks take effect. "
        "    <a href='/ddos-defense' style='color:#00d4ff;margin-left:10px;'>View Defense Tab →</a>\n"
        "  </div>\n"
        "  \n"
        "  <div class='stats-grid'>\n"
        "    <div class='stat-card'>\n"
        "      <div class='stat-label'>Total Requests</div>\n"
        "      <div class='stat-value' id='totalReqs'>0</div>\n"
        "    </div>\n"
        "    <div class='stat-card'>\n"
        "      <div class='stat-label'>Successful</div>\n"
        "      <div class='stat-value success' id='successReqs'>0</div>\n"
        "    </div>\n"
        "    <div class='stat-card'>\n"
        "      <div class='stat-label'>Failed</div>\n"
        "      <div class='stat-value failed' id='failedReqs'>0</div>\n"
        "    </div>\n"
        "    <div class='stat-card'>\n"
        "      <div class='stat-label'>Active Threads</div>\n"
        "      <div class='stat-value' id='activeThreads'>0</div>\n"
        "    </div>\n"
        "    <div class='stat-card'>\n"
        "      <div class='stat-label'>Requests/sec</div>\n"
        "      <div class='stat-value rps' id='rps'>0</div>\n"
        "    </div>\n"
        "    <div class='stat-card'>\n"
        "      <div class='stat-label'>Elapsed Time</div>\n"
        "      <div class='stat-value' id='elapsed'>0s</div>\n"
        "    </div>\n"
        "  </div>\n"
        "  \n"
        "  <div class='visual-area'>\n"
        "    <div class='visual-title'>📊 Attack Visualization</div>\n"
        "    <canvas id='attackCanvas'></canvas>\n"
        "  </div>\n"
        "  \n"
        "  <a href='/' class='back-link'>← Back to Home</a>\n"
        "</div>\n"
        "<script>\n"
        "const ATTACK_VM = '';\n"
        "let updateInterval = null;\n"
        "let canvas = document.getElementById('attackCanvas');\n"
        "let ctx = canvas.getContext('2d');\n"
        "let particles = [];\n"
        "let canvasSized = false;\n"
        "\n"
        "function sizeCanvas() {\n"
        "  if (!canvasSized && canvas.offsetWidth > 0) {\n"
        "    canvas.width = canvas.offsetWidth;\n"
        "    canvas.height = canvas.offsetHeight || 250;\n"
        "    canvasSized = true;\n"
        "  }\n"
        "}\n"
        "\n"
        "function checkDefenseStatus() {\n"
        "  fetch('/defense-status')\n"
        "  .then(r => r.json())\n"
        "  .then(data => {\n"
        "    const banner = document.getElementById('defenseBanner');\n"
        "    if (data.enabled) {\n"
        "      banner.style.display = 'block';\n"
        "    } else {\n"
        "      banner.style.display = 'none';\n"
        "    }\n"
        "  })\n"
        "  .catch(() => {});\n"
        "}\n"
        "\n"
        "function startAttack() {\n"
        "  const target = document.getElementById('targetUrl').value;\n"
        "  const threads = document.getElementById('threads').value;\n"
        "  const requests = document.getElementById('requests').value;\n"
        "  \n"
        "  fetch(ATTACK_VM + '/attack', {\n"
        "    method: 'POST',\n"
        "    headers: {'Content-Type': 'application/json'},\n"
        "    body: JSON.stringify({target_url: target, threads: parseInt(threads), requests: parseInt(requests)})\n"
        "  })\n"
        "  .then(r => r.json())\n"
        "  .then(data => {\n"
        "    console.log('Attack started:', data);\n"
        "    document.getElementById('statusBadge').className = 'status-badge status-running';\n"
        "    document.getElementById('statusBadge').textContent = 'ATTACKING';\n"
        "    if (!updateInterval) updateInterval = setInterval(updateStats, 500);\n"
        "  })\n"
        "  .catch(e => alert('Failed to start attack: ' + e));\n"
        "}\n"
        "\n"
        "function stopAttack() {\n"
        "  fetch(ATTACK_VM + '/stop', {method: 'POST'})\n"
        "  .then(r => r.json())\n"
        "  .then(data => {\n"
        "    console.log('Attack stopped:', data);\n"
        "    document.getElementById('statusBadge').className = 'status-badge status-idle';\n"
        "    document.getElementById('statusBadge').textContent = 'IDLE';\n"
        "  });\n"
        "}\n"
        "\n"
        "function updateStats() {\n"
        "  fetch(ATTACK_VM + '/status')\n"
        "  .then(r => r.json())\n"
        "  .then(data => {\n"
        "    document.getElementById('totalReqs').textContent = data.total_requests || 0;\n"
        "    document.getElementById('successReqs').textContent = data.successful || 0;\n"
        "    document.getElementById('failedReqs').textContent = data.failed || 0;\n"
        "    document.getElementById('activeThreads').textContent = data.threads_active || 0;\n"
        "    document.getElementById('rps').textContent = data.current_rps || 0;\n"
        "    document.getElementById('elapsed').textContent = (data.elapsed || 0).toFixed(1) + 's';\n"
        "    if (data.running) {\n"
        "      for(let i = 0; i < (data.current_rps / 10); i++) addParticle();\n"
        "    }\n"
        "    if (!data.running && updateInterval) {\n"
        "      document.getElementById('statusBadge').className = 'status-badge status-idle';\n"
        "      document.getElementById('statusBadge').textContent = 'COMPLETED';\n"
        "    }\n"
        "  })\n"
        "  .catch(e => console.error('Status update failed:', e));\n"
        "}\n"
        "\n"
        "function addParticle() {\n"
        "  particles.push({\n"
        "    x: Math.random() * canvas.width,\n"
        "    y: 0,\n"
        "    speed: 2 + Math.random() * 3,\n"
        "    size: 2 + Math.random() * 3,\n"
        "    color: Math.random() > 0.5 ? '#00d4ff' : '#ff6600'\n"
        "  });\n"
        "}\n"
        "\n"
        "function animate() {\n"
        "  sizeCanvas();\n"
        "  ctx.fillStyle = 'rgba(0, 0, 0, 0.1)';\n"
        "  ctx.fillRect(0, 0, canvas.width, canvas.height);\n"
        "  particles = particles.filter(p => p.y < canvas.height);\n"
        "  particles.forEach(p => {\n"
        "    ctx.fillStyle = p.color;\n"
        "    ctx.beginPath();\n"
        "    ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);\n"
        "    ctx.fill();\n"
        "    p.y += p.speed;\n"
        "  });\n"
        "  requestAnimationFrame(animate);\n"
        "}\n"
        "animate();\n"
        "checkDefenseStatus();\n"
        "setInterval(checkDefenseStatus, 3000);\n"
        "</script>\n"
        "</body></html>";
    
    send(client_fd, dashboard, strlen(dashboard), 0);
}

// Serve the SafeByte logo
void send_logo(int client_fd) {
    char logo_path[1100];
    snprintf(logo_path, sizeof(logo_path), "%s/safebyte_logo.png", BASE_DIR);
    FILE *f = fopen(logo_path, "rb");
    if (!f) {
        const char *not_found = "HTTP/1.1 404 Not Found\r\n\r\n";
        send(client_fd, not_found, strlen(not_found), 0);
        return;
    }
    
    // Get file size
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    // Send headers
    char header[256];
    snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: image/png\r\n"
        "Content-Length: %ld\r\n"
        "Connection: close\r\n\r\n", fsize);
    send(client_fd, header, strlen(header), 0);
    
    // Send file
    char buffer[4096];
    size_t n;
    while ((n = fread(buffer, 1, sizeof(buffer), f)) > 0) {
        send(client_fd, buffer, n, 0);
    }
    
    fclose(f);
}



// -----------------------------------------
// main server loop
// -----------------------------------------

int main() {
    int server_fd, client_fd;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);

    // Resolve base directory from binary location
    char binary_path[1024] = {0};
#ifdef __APPLE__
    uint32_t size = sizeof(binary_path);
    if (_NSGetExecutablePath(binary_path, &size) != 0)
        strncpy(binary_path, "./server", sizeof(binary_path) - 1);
#else
    if (realpath("/proc/self/exe", binary_path) == NULL)
        strncpy(binary_path, "./server", sizeof(binary_path) - 1);
#endif
    char *last_slash = strrchr(binary_path, '/');
    if (last_slash) {
        *last_slash = '\0';
        strncpy(BASE_DIR, binary_path, sizeof(BASE_DIR) - 1);
    }
    printf("[+] Base directory: %s\n", BASE_DIR);
    snprintf(LOG_FILE, sizeof(LOG_FILE), "%s/access.log", BASE_DIR);

    // 1. create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&opt, sizeof(opt));

    // 2. bind to 0.0.0.0:8080
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    char *port_env = getenv("PORT");
    int port = port_env ? atoi(port_env) : 8080;
    addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // 3. listen
    if (listen(server_fd, 128) < 0) {
        perror("listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("C web server running on http://0.0.0.0:%d\n", port);
    printf("Try opening it in a browser.\n");

    // initialize SQLite database
    if (!db_init()) {
        fprintf(stderr, "[-] Database init failed.\n");
        close(server_fd);
        return 1;
    }

    // 4. accept + spawn a thread per connection
    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&addr, &addrlen);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        char ip_str[INET_ADDRSTRLEN] = "unknown";
        inet_ntop(AF_INET, &addr.sin_addr, ip_str, sizeof(ip_str));

        ConnArgs *ca = malloc(sizeof(ConnArgs));
        if (!ca) { close(client_fd); continue; }
        ca->client_fd = client_fd;
        strncpy(ca->ip, ip_str, sizeof(ca->ip) - 1);

        pthread_t tid;
        if (pthread_create(&tid, NULL, handle_connection, ca) != 0) {
            free(ca);
            close(client_fd);
        } else {
            pthread_detach(tid);
        }
    }

    close(server_fd);
    return 0;
}
