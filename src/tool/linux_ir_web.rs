//! Linux IR — Web Threats (M07, M11, M38, M39, M40)
//! Detects webshells, Java memory shells, dark links, config backdoors, access log attacks.

use super::linux_ir_common::*;

pub struct WebCategory;

static MODULES: &[ModuleDef] = &[
    ModuleDef {
        id: 7,
        name: "web_shell",
        description: "Detect webshells in web directories",
        commands: &[
            "find /var/www /usr/share/nginx /home/www -type f \\( -name '*.php' -o -name '*.jsp' -o -name '*.asp' \\) -mtime -30 2>/dev/null | head -50",
            "grep -rlE '(eval|base64_decode|system|exec|passthru|shell_exec)' /var/www /usr/share/nginx 2>/dev/null | head -30",
        ],
    },
    ModuleDef {
        id: 11,
        name: "web_memory_shell",
        description: "Detect Java memory shells",
        commands: &[
            "ps aux | grep -E '(java|tomcat|weblogic|jboss)' | grep -v grep",
            "find / -name '*.class' -mtime -7 2>/dev/null | grep -vE '/(usr|opt)/' | head -20",
        ],
    },
    ModuleDef {
        id: 38,
        name: "web_dark_link",
        description: "Detect dark links and hidden iframes",
        commands: &[
            "grep -rlE '(display:\\s*none|visibility:\\s*hidden|position:\\s*absolute.*left:\\s*-)' /var/www 2>/dev/null | head -20",
        ],
    },
    ModuleDef {
        id: 39,
        name: "web_config",
        description: "Check web server configs for backdoors",
        commands: &[
            "cat /etc/nginx/nginx.conf /etc/httpd/conf/httpd.conf 2>/dev/null | grep -E '(proxy_pass|rewrite|include)' | head -30",
        ],
    },
    ModuleDef {
        id: 40,
        name: "web_access_log",
        description: "Analyze web access logs for attacks",
        commands: &[
            "tail -1000 /var/log/nginx/access.log /var/log/httpd/access_log 2>/dev/null | grep -iE '(union.*select|<script|eval\\(|base64|/etc/passwd)' | tail -30",
        ],
    },
];

const WEBSHELL_PATTERNS: &[&str] = &[
    "eval(", "base64_decode", "system(", "exec(", "passthru", "shell_exec",
    "assert(", "preg_replace", "call_user_func", "create_function",
];

impl LinuxIrCategory for WebCategory {
    fn category(&self) -> &'static str { "web" }
    fn modules(&self) -> &'static [ModuleDef] { MODULES }

    fn parse(&self, module_id: u32, output: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let output_lower = output.to_lowercase();

        match module_id {
            7 => {
                for pattern in WEBSHELL_PATTERNS {
                    if output_lower.contains(pattern) {
                        findings.push(
                            Finding::new(7, "web_shell", Severity::Critical,
                                "Possible webshell detected")
                                .with_description(&format!("Found '{}' pattern", pattern))
                                .with_evidence(&extract_line(output, pattern))
                        );
                    }
                }
            }
            11 => {
                // Suspicious .class files
                for line in output.lines() {
                    if line.contains(".class") && !line.contains("/usr/") && !line.contains("/opt/") {
                        findings.push(
                            Finding::new(11, "web_memory_shell", Severity::High,
                                "Suspicious Java class file")
                                .with_evidence(line)
                        );
                    }
                }
            }
            38 => {
                // Dark links / hidden elements
                let file_count = output.lines().filter(|l| !l.trim().is_empty()).count();
                if file_count > 0 {
                    findings.push(
                        Finding::new(38, "web_dark_link", Severity::Medium,
                            &format!("Hidden elements found in {} files", file_count))
                            .with_description("Possible dark links or hidden iframes (SEO spam)")
                            .with_evidence(&truncate(output, 500))
                    );
                }
            }
            39 => {
                // Suspicious proxy/rewrite rules
                for line in output.lines() {
                    let ll = line.to_lowercase();
                    if ll.contains("proxy_pass") && (ll.contains(".cn") || ll.contains(".ru") || ll.contains("ip=")) {
                        findings.push(
                            Finding::new(39, "web_config", Severity::High,
                                "Suspicious proxy_pass in web config")
                                .with_evidence(line)
                        );
                    }
                }
            }
            40 => {
                // Web attacks in logs
                let attack_patterns = ["union", "select", "<script", "eval(", "/etc/passwd", "cmd="];
                for pattern in &attack_patterns {
                    if output_lower.contains(pattern) {
                        findings.push(
                            Finding::new(40, "web_access_log", Severity::Medium,
                                &format!("Web attack pattern: {}", pattern))
                                .with_evidence(&extract_line(output, pattern))
                        );
                    }
                }
            }
            _ => {}
        }
        findings
    }
}
