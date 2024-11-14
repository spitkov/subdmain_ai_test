use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::proto::rr::RecordType;
use std::collections::HashSet;
use reqwest;

pub struct SubdomainFinder {
    resolver: TokioAsyncResolver,
    client: reqwest::Client,
    deep_scan: bool,
}

#[derive(serde::Deserialize)]
struct CrtShEntry {
    name_value: String,
}

impl SubdomainFinder {
    pub async fn new(deep_scan: bool) -> Self {
        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .expect("Failed to create resolver from system config");

        Self {
            resolver,
            client: reqwest::Client::builder()
                .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                .build()
                .unwrap(),
            deep_scan,
        }
    }

    pub async fn find_subdomains(&self, domain: &str) -> Vec<String> {
        let mut subdomains = HashSet::new();

        // Basic techniques (always included)
        self.dns_records(domain, &mut subdomains).await;
        self.check_ssl_certificates(domain, &mut subdomains).await;
        self.check_crt_sh(domain, &mut subdomains).await;
        self.bruteforce_subdomains(domain, &mut subdomains).await;

        if self.deep_scan {
            self.search_engines(domain, &mut subdomains).await;
            self.web_crawl(domain, &mut subdomains).await;
            self.reverse_dns(domain, &mut subdomains).await;
            self.generate_permutations(domain, &mut subdomains).await;
            self.check_cname_records(domain, &mut subdomains).await;
        }

        let mut result: Vec<String> = subdomains.into_iter().collect();
        result.sort();
        result
    }

    async fn bruteforce_subdomains(&self, domain: &str, subdomains: &mut HashSet<String>) {
        for &subdomain in COMMON_SUBDOMAINS {
            let full_domain = format!("{}.{}", subdomain, domain);
            if let Ok(_) = self.resolver.lookup_ip(&full_domain).await {
                subdomains.insert(full_domain);
            }
        }
    }

    async fn dns_records(&self, domain: &str, subdomains: &mut HashSet<String>) {
        let record_types = [
            RecordType::NS,
            RecordType::MX,
            RecordType::TXT,
            RecordType::CNAME,
        ];

        for &record_type in &record_types {
            if let Ok(response) = self.resolver.lookup(domain, record_type).await {
                for record in response.records() {
                    if let Some(name) = record.name().to_ascii().strip_suffix(domain) {
                        if !name.is_empty() {
                            subdomains.insert(format!("{}.{}", name.trim_end_matches('.'), domain));
                        }
                    }
                }
            }
        }
    }

    async fn check_ssl_certificates(&self, domain: &str, subdomains: &mut HashSet<String>) {
        let urls = [
            format!("https://{}", domain),
            format!("https://www.{}", domain),
        ];

        for url in urls {
            if let Ok(_) = self.client.get(&url).send().await {
                subdomains.insert(domain.to_string());
            }
        }
    }

    async fn search_engines(&self, domain: &str, result_subdomains: &mut HashSet<String>) {
        let dorks = [
            format!("site:*.{}", domain),
            format!("site:{} -www", domain),
        ];

        for dork in dorks {
            let url = format!(
                "https://www.google.com/search?q={}&num=100",
                urlencoding::encode(&dork)
            );
            if let Ok(response) = self.client.get(&url).send().await {
                if let Ok(text) = response.text().await {
                    for line in text.lines() {
                        if line.contains(domain) {
                            // Extract potential subdomains from the line
                            if let Some(subdomain) = extract_subdomain(line, domain) {
                                result_subdomains.insert(subdomain);
                            }
                        }
                    }
                }
            }
        }
    }

    async fn web_crawl(&self, domain: &str, result_subdomains: &mut HashSet<String>) {
        let url = format!("https://{}", domain);
        if let Ok(response) = self.client.get(&url).send().await {
            if let Ok(text) = response.text().await {
                // Extract links from HTML and look for subdomains
                for line in text.lines() {
                    if line.contains(domain) {
                        if let Some(subdomain) = extract_subdomain(line, domain) {
                            result_subdomains.insert(subdomain);
                        }
                    }
                }
            }
        }
    }

    async fn reverse_dns(&self, domain: &str, subdomains: &mut HashSet<String>) {
        if let Ok(ips) = self.resolver.lookup_ip(domain).await {
            for ip in ips.iter() {
                if let Ok(names) = self.resolver.reverse_lookup(ip).await {
                    for name in names.iter() {
                        if name.to_string().ends_with(domain) {
                            subdomains.insert(name.to_string());
                        }
                    }
                }
            }
        }
    }

    async fn generate_permutations(&self, _domain: &str, subdomains: &mut HashSet<String>) {
        let current_subs: Vec<String> = subdomains.iter().cloned().collect();
        let prefixes = ["dev", "staging", "test", "prod", "api", "v1", "v2"];
        let suffixes = ["-api", "-app", "-test", "-dev", "-prod"];

        for sub in current_subs {
            for prefix in prefixes.iter() {
                subdomains.insert(format!("{}-{}", prefix, sub));
            }
            for suffix in suffixes.iter() {
                subdomains.insert(format!("{}{}", sub, suffix));
            }
        }
    }

    async fn check_cname_records(&self, domain: &str, subdomains: &mut HashSet<String>) {
        for subdomain in subdomains.clone() {
            if let Ok(response) = self.resolver.lookup(subdomain.as_str(), RecordType::CNAME).await {
                for record in response.records() {
                    if let Some(cname) = record.data() {
                        if cname.to_string().contains(domain) {
                            subdomains.insert(cname.to_string());
                        }
                    }
                }
            }
        }
    }

    async fn check_crt_sh(&self, domain: &str, subdomains: &mut HashSet<String>) {
        let url = format!("https://crt.sh/?q=%.{}&output=json", domain);
        
        if let Ok(response) = self.client.get(&url).send().await {
            if let Ok(text) = response.text().await {
                if let Ok(certs) = serde_json::from_str::<Vec<CrtShEntry>>(&text) {
                    for cert in certs {
                        for name in cert.name_value.split(['\n', '*'].as_ref()) {
                            let name = name.trim();
                            if name.ends_with(domain) {
                                subdomains.insert(name.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
}

// Helper function to extract subdomains from text
fn extract_subdomain(text: &str, domain: &str) -> Option<String> {
    let domain_with_dot = format!(".{}", domain);
    if let Some(start) = text.find(&domain_with_dot) {
        if start > 0 {
            let potential_subdomain = &text[..start + domain_with_dot.len()];
            if let Some(subdomain_start) = potential_subdomain.rfind("//") {
                return Some(potential_subdomain[subdomain_start + 2..].to_string());
            } else if let Some(subdomain_start) = potential_subdomain.rfind(' ') {
                return Some(potential_subdomain[subdomain_start + 1..].to_string());
            }
        }
    }
    None
}

const COMMON_SUBDOMAINS: &[&str] = &[
    "www", "mail", "ftp", "smtp", "pop", "m", "webmail", "api",
    "dev", "staging", "test", "admin", "blog", "shop", "store",
    "vpn", "dns", "ns1", "ns2", "cdn", "cloud", "app", "remote",
    "support", "portal", "beta", "gateway", "secure", "admin",
    "services", "internal", "api-dev", "staging-api", "dev-api",
];