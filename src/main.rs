use std::collections::HashSet;
use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write}; // Read dihapus karena AsyncReadExt akan digunakan
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod, Runtime};
use futures::StreamExt;
use ipnetwork::IpNetwork;
use maxminddb::{geoip2, Reader};
use native_tls::TlsConnector as NativeTlsConnector; // Renamed to avoid conflict
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt}; // Untuk read_exact, write_all async
use tokio::net::TcpStream; // TcpStream async dari Tokio
use tokio_native_tls::TlsConnector as TokioTlsConnector; // Konektor TLS async
use tokio_postgres::NoTls;

const IP_RESOLVER: &str = "speed.cloudflare.com";
const PATH_RESOLVER: &str = "/meta";
const PROXY_FILE: &str = "Data/emeliaProxyIP15AGS.txt"; //input
const OUTPUT_FILE: &str = "Data/alive.txt";
const COUNTRY_DB: &str = "Data/GeoLite2-Country.mmdb";
const CITY_DB: &str = "Data/GeoLite2-City.mmdb";
const ASN_DB: &str = "Data/GeoLite2-ASN.mmdb";
const ABUSE_IP_FILE: &str = "Data/abuseips.txt";
const FIREHOL_CIDR_FILE: &str = "Data/firehol_cidr.txt";
const MAX_CONCURRENT: usize = 175;
const TIMEOUT_SECONDS: u64 = 9;

// Define a custom error type that implements Send + Sync
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

// 代理数据结构
#[derive(Debug, Clone)]
struct ProxyData {
    ip: String,
    port: u16,
    country_code: String,
    country_name: String,
    city_code: String,
    city_name: String,
    asn_number: String,
    org_name: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("Starting proxy scanner...");

    // Create output directory if it doesn't exist
    if let Some(parent) = Path::new(OUTPUT_FILE).parent() {
        fs::create_dir_all(parent)?;
    }

    // Initialize GeoIP database readers
    let country_reader = Arc::new(Reader::open_readfile(COUNTRY_DB)?);
    println!("Loaded Country database: {}", COUNTRY_DB);

    let city_reader = match Reader::open_readfile(CITY_DB) {
        Ok(reader) => {
            println!("Loaded City database: {}", CITY_DB);
            Some(Arc::new(reader))
        }
        Err(e) => {
            eprintln!("Warning: Could not load City database ({}): {}. City info will show as '未知'.", CITY_DB, e);
            None
        }
    };

    // Initialize ASN database reader (optional)
    let asn_reader = match Reader::open_readfile(ASN_DB) {
        Ok(reader) => {
            println!("Loaded ASN database: {}", ASN_DB);
            Some(Arc::new(reader))
        }
        Err(e) => {
            eprintln!("Warning: Could not load ASN database ({}): {}. ASN info will show as empty.", ASN_DB, e);
            None
        }
    };


    // Load AbuseIPDB blacklist
    let abuse_ips = Arc::new(load_abuse_ips(ABUSE_IP_FILE));

    // Load FireHOL CIDR blocklist
    let firehol_cidrs = Arc::new(load_firehol_cidrs(FIREHOL_CIDR_FILE));

    // Clear output file before starting
    // File::create akan mengosongkan file jika sudah ada atau membuatnya jika belum
    File::create(OUTPUT_FILE)?;
    println!("File {} has been cleared or created before scanning process started.", OUTPUT_FILE);

    // Read proxy list from file
    let proxies = match read_proxy_file(PROXY_FILE) {
        Ok(proxies) => proxies,
        Err(e) => {
            eprintln!("Error reading proxy file: {}", e);
            return Err(e.into());
        }
    };

    println!("Loaded {} proxies from file", proxies.len());

    // Get original IP (without proxy)
    let original_ip_data = match check_connection(IP_RESOLVER, PATH_RESOLVER, None).await {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to get original IP info: {}", e);
            // Consider if you want to exit here. If speed.cloudflare.com is down, no checks can be done.
            return Err(e.into());
        }
    };

    let original_ip = match original_ip_data.get("clientIp") {
        Some(Value::String(ip)) => ip.clone(),
        _ => {
            eprintln!("Failed to extract original client IP from response: {:?}", original_ip_data);
            return Err("Failed to extract original client IP".into());
        }
    };

    println!("Original IP: {}", original_ip);

    // Store active proxies and proxy data for batch writing
    let active_proxies = Arc::new(Mutex::new(Vec::new()));
    let proxy_data_batch = Arc::new(Mutex::new(Vec::<ProxyData>::new()));
    let batch_counter = Arc::new(Mutex::new(0usize));
    // Batch size for incremental PostgreSQL writes
    // Note: Used as literal value (50) in line 832 condition check

    // Initialize PostgreSQL connection pool (REQUIRED)
    println!("🔌 Initializing PostgreSQL connection...");
    let pg_pool = match create_pg_pool() {
        Ok(pool) => pool,
        Err(e) => {
            eprintln!("❌ Failed to create PostgreSQL connection pool: {}", e);
            eprintln!("💡 Please configure DATABASE_URL and ensure database is accessible");
            std::process::exit(1);
        }
    };

    // Test database connection (REQUIRED)
    if let Err(e) = test_database_connection(&pg_pool).await {
        eprintln!("❌ Database connection test failed: {}", e);
        eprintln!("💡 Please check: DATABASE_URL, network connectivity, and run schema.sql");
        std::process::exit(1);
    }
    println!("✅ Database ready for sync");

    // Generate batch timestamp for this run
    let batch_time = chrono::Utc::now();

    // Share pool across tasks
    let pg_pool_shared = Arc::new(pg_pool);

    // Process proxies concurrently
    let tasks = futures::stream::iter(
        proxies.into_iter().map(|proxy_line| {
            let original_ip = original_ip.clone();
            let active_proxies = Arc::clone(&active_proxies);
            let proxy_data_batch = Arc::clone(&proxy_data_batch);
            let batch_counter = Arc::clone(&batch_counter);
            let pg_pool_clone = Arc::clone(&pg_pool_shared);
            let country_reader = Arc::clone(&country_reader);
            let city_reader = city_reader.clone();
            let asn_reader = asn_reader.clone();
            let anonymous_reader = anonymous_reader.clone();
            let abuse_ips = Arc::clone(&abuse_ips);
            let firehol_cidrs = Arc::clone(&firehol_cidrs);

            // tokio::spawn akan menjalankan setiap future process_proxy secara independen
            // Ini adalah cara yang lebih idiomatik untuk menjalankan banyak tugas async di Tokio
            // daripada hanya mengandalkan buffer_unordered pada stream dari async blok.
            // Namun, karena buffer_unordered sudah menangani konkurensi,
            // tokio::spawn di sini mungkin redundan jika process_proxy itu sendiri tidak
            // melakukan spawn lebih lanjut atau operasi berat CPU yang panjang.
            // Untuk I/O bound seperti ini, buffer_unordered sudah cukup.
            // Mari kita tetap dengan struktur asli untuk kesederhanaan, karena buffer_unordered sudah menangani konkurensi.
            async move {
                process_proxy(
                    proxy_line,
                    &original_ip,
                    &active_proxies,
                    &proxy_data_batch,
                    &batch_counter,
                    &pg_pool_clone,
                    batch_time,
                    &country_reader,
                    city_reader.as_deref(),
                    asn_reader.as_deref(),
                    anonymous_reader.as_deref(),
                    &abuse_ips,
                    &firehol_cidrs,
                ).await;
            }
        })
    ).buffer_unordered(MAX_CONCURRENT).collect::<Vec<()>>();

    tasks.await;

    // Write final batch if any remaining proxies
    {
        let batch = proxy_data_batch.lock().unwrap();
        if !batch.is_empty() {
            println!("📤 Writing final batch of {} proxies to PostgreSQL...", batch.len());
            match batch_insert_proxies(&pg_pool_shared, &batch, batch_time).await {
                Ok(_) => println!("✅ Final batch written successfully"),
                Err(e) => eprintln!("❌ Failed to write final batch: {}", e),
            }
        }
    }

    // Clean up old records
    match cleanup_old_proxies(&pg_pool_shared, batch_time).await {
        Ok(_) => println!("✅ Database cleanup completed"),
        Err(e) => eprintln!("❌ Failed to cleanup old proxies: {}", e),
    }

    // Save active proxies to file
    let active_proxies_locked = active_proxies.lock().unwrap();
    if !active_proxies_locked.is_empty() {
        let mut file = File::create(OUTPUT_FILE)?;
        for proxy_csv in active_proxies_locked.iter() {
            writeln!(file, "{}", proxy_csv)?;
        }
        println!("✅ All active proxies saved to {}", OUTPUT_FILE);
    } else {
        println!("No active proxies found");
    }

    println!("Proxy checking completed.");
    Ok(())
}

fn read_proxy_file(file_path: &str) -> io::Result<Vec<String>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut proxies = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if !line.trim().is_empty() {
            proxies.push(line);
        }
    }

    Ok(proxies)
}

// 读取 AbuseIPDB 黑名单 IP 列表
fn load_abuse_ips(file_path: &str) -> HashSet<IpAddr> {
    let mut abuse_ips = HashSet::new();

    match File::open(file_path) {
        Ok(file) => {
            let reader = BufReader::new(file);
            for line in reader.lines() {
                if let Ok(line) = line {
                    // 格式: ip,country_code,abuse_confidence_score
                    let parts: Vec<&str> = line.split(',').collect();
                    if !parts.is_empty() {
                        if let Ok(ip) = parts[0].trim().parse::<IpAddr>() {
                            abuse_ips.insert(ip);
                        }
                    }
                }
            }
            println!("Loaded {} abuse IPs from {}", abuse_ips.len(), file_path);
        }
        Err(e) => {
            eprintln!("Warning: Could not load abuse IP list ({}): {}. Abuse IP filtering will be disabled.", file_path, e);
        }
    }

    abuse_ips
}

// 读取 FireHOL CIDR 网段列表
fn load_firehol_cidrs(file_path: &str) -> Vec<IpNetwork> {
    let mut cidrs = Vec::new();

    match File::open(file_path) {
        Ok(file) => {
            let reader = BufReader::new(file);
            for line in reader.lines() {
                if let Ok(line) = line {
                    let line = line.trim();
                    if !line.is_empty() {
                        if let Ok(network) = line.parse::<IpNetwork>() {
                            cidrs.push(network);
                        }
                    }
                }
            }
            println!("Loaded {} CIDR ranges from {}", cidrs.len(), file_path);
        }
        Err(e) => {
            eprintln!("Warning: Could not load FireHOL CIDR list ({}): {}. CIDR filtering will be disabled.", file_path, e);
        }
    }

    cidrs
}

// 检查 IP 是否在 CIDR 网段内
fn is_ip_in_cidr_list(ip: IpAddr, cidrs: &[IpNetwork]) -> bool {
    cidrs.iter().any(|network| network.contains(ip))
}

// 初始化 PostgreSQL 连接池（必需）
fn create_pg_pool() -> Result<Pool> {
    let database_url = match env::var("DATABASE_URL") {
        Ok(url) => {
            if url.is_empty() {
                return Err("DATABASE_URL is empty. PostgreSQL connection is required.".into());
            }
            println!("✅ DATABASE_URL configured: {}...", &url.chars().take(20).collect::<String>());
            url
        }
        Err(_) => {
            return Err("DATABASE_URL not set. PostgreSQL connection is required.".into());
        }
    };

    let mut cfg = Config::new();
    cfg.url = Some(database_url);
    cfg.manager = Some(ManagerConfig {
        recycling_method: RecyclingMethod::Fast,
    });

    match cfg.create_pool(Some(Runtime::Tokio1), NoTls) {
        Ok(pool) => {
            println!("✅ PostgreSQL connection pool created successfully");
            Ok(pool)
        }
        Err(e) => {
            Err(format!("Failed to create PostgreSQL connection pool: {}", e).into())
        }
    }
}

// 测试数据库连接并验证表结构
async fn test_database_connection(pool: &Pool) -> Result<()> {
    println!("🔍 Testing database connection...");

    let client = pool.get().await.map_err(|e| {
        eprintln!("❌ Failed to get database client: {}", e);
        e
    })?;

    println!("✅ Database connection successful");

    // Check if proxies table exists
    let table_check = client.query(
        "SELECT EXISTS (
            SELECT FROM information_schema.tables
            WHERE table_name = 'proxies'
        )",
        &[]
    ).await?;

    if let Some(row) = table_check.first() {
        let exists: bool = row.get(0);
        if exists {
            println!("✅ Table 'proxies' exists");

            // Get row count
            let count_result = client.query("SELECT COUNT(*) FROM proxies", &[]).await?;
            if let Some(row) = count_result.first() {
                let count: i64 = row.get(0);
                println!("📊 Current proxy count in database: {}", count);
            }
        } else {
            eprintln!("❌ Table 'proxies' does not exist! Please run schema.sql first.");
            return Err("Table 'proxies' not found".into());
        }
    }

    Ok(())
}

// 批量写入代理数据到 PostgreSQL
async fn batch_insert_proxies(pool: &Pool, proxies: &[ProxyData], batch_time: chrono::DateTime<chrono::Utc>) -> Result<()> {
    if proxies.is_empty() {
        return Ok(());
    }

    let mut client = pool.get().await?;

    // 开始事务
    let transaction = client.transaction().await?;

    // 批量插入（使用 UPSERT 策略）
    let stmt = transaction.prepare(
        "INSERT INTO proxies (ip, port, country_code, country_name, city_code, city_name, asn_number, org_name, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (ip, port)
         DO UPDATE SET
            country_code = EXCLUDED.country_code,
            country_name = EXCLUDED.country_name,
            city_code = EXCLUDED.city_code,
            city_name = EXCLUDED.city_name,
            asn_number = EXCLUDED.asn_number,
            org_name = EXCLUDED.org_name,
            updated_at = EXCLUDED.updated_at"
    ).await?;

    let mut inserted = 0;
    for proxy in proxies {
        transaction.execute(
            &stmt,
            &[
                &proxy.ip,
                &(proxy.port as i32),
                &proxy.country_code,
                &proxy.country_name,
                &proxy.city_code,
                &proxy.city_name,
                &proxy.asn_number,
                &proxy.org_name,
                &batch_time,
            ],
        ).await?;
        inserted += 1;
    }

    // 提交事务
    transaction.commit().await?;

    println!("✅ Inserted/Updated {} proxies to PostgreSQL", inserted);
    Ok(())
}

// 清理旧数据（保留本次更新的数据）
async fn cleanup_old_proxies(pool: &Pool, batch_time: chrono::DateTime<chrono::Utc>) -> Result<()> {
    let client = pool.get().await?;

    let rows_deleted = client.execute(
        "DELETE FROM proxies WHERE updated_at < $1",
        &[&batch_time],
    ).await?;

    println!("✅ Cleaned up {} old proxy records from PostgreSQL", rows_deleted);
    Ok(())
}

async fn check_connection(
    host: &str,
    path: &str,
    proxy: Option<(&str, u16)>,
) -> Result<Value> {
    let timeout_duration = Duration::from_secs(TIMEOUT_SECONDS);

    // Bungkus seluruh operasi koneksi dalam tokio::time::timeout
    match tokio::time::timeout(timeout_duration, async {
        // Build HTTP request payload
        let payload = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10240\r\n\
             Connection: close\r\n\r\n",
            path, host
        );

        // Create TCP connection
        let stream = if let Some((proxy_ip, proxy_port)) = proxy {
            // *** PERUBAHAN UTAMA DI SINI ***
            // Menangani alamat IPv6 dengan benar dengan membungkusnya dalam kurung siku.
            let connect_addr = if proxy_ip.contains(':') {
                // Ini adalah alamat IPv6, formatnya menjadi "[ipv6]:port"
                format!("[{}]:{}", proxy_ip, proxy_port)
            } else {
                // Ini adalah alamat IPv4, formatnya tetap "ipv4:port"
                format!("{}:{}", proxy_ip, proxy_port)
            };
            TcpStream::connect(connect_addr).await?
        } else {
            // Connect directly to host (Tokio's connect can resolve hostnames)
            TcpStream::connect(format!("{}:443", host)).await?
        };

        // Create TLS connection
        // NativeTlsConnector dikonfigurasi terlebih dahulu
        let native_connector = NativeTlsConnector::builder().build()?;
        // Kemudian dibungkus dengan TokioTlsConnector untuk penggunaan async
        let tokio_connector = TokioTlsConnector::from(native_connector);

        let mut tls_stream = tokio_connector.connect(host, stream).await?;

        // Send HTTP request
        tls_stream.write_all(payload.as_bytes()).await?;

        // Read response
        let mut response = Vec::new();
        // Menggunakan buffer yang sama ukurannya
        let mut buffer = [0; 4096];

        // Loop untuk membaca data dari stream
        // AsyncReadExt::read akan mengembalikan Ok(0) saat EOF.
        loop {
            match tls_stream.read(&mut buffer).await {
                Ok(0) => break, // End of stream
                Ok(n) => response.extend_from_slice(&buffer[..n]),
                Err(e) => {
                    // Jika jenis error adalah WouldBlock, dalam konteks async,
                    // ini biasanya ditangani oleh runtime (tidak akan sampai ke sini jika .await digunakan dengan benar).
                    // Namun, jika ada error I/O lain, kita return.
                    return Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>);
                }
            }
        }

        // Parse response
        let response_str = String::from_utf8_lossy(&response);

        // Split headers and body
        if let Some(body_start) = response_str.find("\r\n\r\n") {
            let body = &response_str[body_start + 4..];

            // Try to parse the JSON body
            match serde_json::from_str::<Value>(body.trim()) {
                Ok(json_data) => Ok(json_data),
                Err(e) => {
                    eprintln!("Failed to parse JSON: {}", e);
                    eprintln!("Response body for {}:{}: {}", host, proxy.map_or_else(|| "direct".to_string(), |(ip,p)| format!("{}:{}",ip,p)), body);
                    Err("Invalid JSON response".into())
                }
            }
        } else {
            Err("Invalid HTTP response: No separator found".into())
        }
    }).await {
        Ok(inner_result) => inner_result, // Hasil dari blok async (bisa Ok atau Err)
        Err(_) => Err(Box::new(io::Error::new(io::ErrorKind::TimedOut, "Connection attempt timed out")) as Box<dyn std::error::Error + Send + Sync>), // Error karena timeout
    }
}


#[allow(dead_code)]
fn clean_org_name(org_name: &str) -> String {
    org_name.chars()
        .filter(|c| c.is_alphanumeric() || c.is_whitespace())
        .collect()
}

// 查询 IP 地理位置信息
// 返回: (国家代码, 国家名, 城市代码, 城市名)
fn get_geo_info(
    country_reader: &Reader<Vec<u8>>,
    city_reader: Option<&Reader<Vec<u8>>>,
    ip_str: &str,
) -> (String, String, String, String) {
    let ip: IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => return (String::new(), String::new(), String::new(), String::new()),
    };

    // 查询国家信息
    let (country_code, country_name) = match country_reader.lookup::<geoip2::Country>(ip) {
        Ok(country_data) => {
            let code = country_data
                .country
                .as_ref()
                .and_then(|c| c.iso_code)
                .unwrap_or("")
                .to_string();

            let name = country_data
                .country
                .as_ref()
                .and_then(|c| c.names.as_ref())
                .and_then(|names| {
                    names.get("zh-CN")
                        .or_else(|| names.get("en"))
                        .map(|s| s.to_string())
                })
                .unwrap_or_default();

            (code, name)
        }
        Err(_) => (String::new(), String::new()),
    };

    // 查询城市信息（如果有城市数据库）
    let (city_code, city_name) = if let Some(reader) = city_reader {
        match reader.lookup::<geoip2::City>(ip) {
            Ok(city_data) => {
                // GeoLite2 没有城市代码，使用城市名的英文作为代码
                let code = city_data
                    .city
                    .as_ref()
                    .and_then(|c| c.names.as_ref())
                    .and_then(|names| names.get("en").map(|s| s.to_string()))
                    .unwrap_or_default();

                let name = city_data
                    .city
                    .as_ref()
                    .and_then(|c| c.names.as_ref())
                    .and_then(|names| {
                        names.get("zh-CN")
                            .or_else(|| names.get("en"))
                            .map(|s| s.to_string())
                    })
                    .unwrap_or_default();

                (code, name)
            }
            Err(_) => (String::new(), String::new()),
        }
    } else {
        (String::new(), String::new())
    };

    (country_code, country_name, city_code, city_name)
}

// 查询 ASN 信息
// 返回: (ASN 编号, 组织名)
fn get_asn_info(
    asn_reader: &Reader<Vec<u8>>,
    ip_str: &str,
) -> (String, String) {
    let ip: IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => return (String::new(), String::new()),
    };

    match asn_reader.lookup::<geoip2::Asn>(ip) {
        Ok(asn_data) => {
            let asn_number = asn_data
                .autonomous_system_number
                .map(|n| n.to_string())
                .unwrap_or_default();

            let org_name = asn_data
                .autonomous_system_organization
                .unwrap_or("")
                .to_string();

            (asn_number, org_name)
        }
        Err(_) => (String::new(), String::new()),
    }
}


async fn process_proxy(
    proxy_line: String,
    original_ip: &str,
    active_proxies: &Arc<Mutex<Vec<String>>>,
    proxy_data_batch: &Arc<Mutex<Vec<ProxyData>>>,
    batch_counter: &Arc<Mutex<usize>>,
    pg_pool: &Arc<Pool>,
    batch_time: chrono::DateTime<chrono::Utc>,
    country_reader: &Reader<Vec<u8>>,
    city_reader: Option<&Reader<Vec<u8>>>,
    asn_reader: Option<&Reader<Vec<u8>>>,
    anonymous_reader: Option<&Reader<Vec<u8>>>,
    abuse_ips: &HashSet<IpAddr>,
    firehol_cidrs: &[IpNetwork],
) {
    let parts: Vec<&str> = proxy_line.split(',').collect();
    if parts.len() < 4 {
        println!("Invalid proxy line format: {}. Expected ip,port,country,org", proxy_line);
        return;
    }

    let ip = parts[0];
    let port_str = parts[1]; // Renamed to avoid conflict with port_num
    let _country = parts[2]; // 保留以备将来使用
    let _org = parts[3]; // 保留以备将来使用

    let port_num = match port_str.parse::<u16>() {
        Ok(p) => p,
        Err(_) => {
            println!("Invalid port number: {} in line: {}", port_str, proxy_line);
            return;
        }
    };

    match check_connection(IP_RESOLVER, PATH_RESOLVER, Some((ip, port_num))).await {
        Ok(proxy_data) => {
            if let Some(Value::String(proxy_ip)) = proxy_data.get("clientIp") {
                if proxy_ip != original_ip {
                    // 解析 IP 地址用于过滤检查
                    let ip_addr = match ip.parse::<IpAddr>() {
                        Ok(addr) => addr,
                        Err(_) => {
                            //println!("CF PROXY FILTERED 🚫 (Invalid IP format): {}:{}", ip, port_num);
                            return;
                        }
                    };

                    // 检查是否在 AbuseIPDB 黑名单中
                    if !abuse_ips.is_empty() && abuse_ips.contains(&ip_addr) {
                        //println!("CF PROXY FILTERED 🚫 (AbuseIPDB 黑名单): {}:{}", ip, port_num);
                        return;
                    }

                    // 检查是否在 FireHOL CIDR 黑名单中
                    if !firehol_cidrs.is_empty() && is_ip_in_cidr_list(ip_addr, firehol_cidrs) {
                       // println!("CF PROXY FILTERED 🚫 (FireHOL CIDR 黑名单): {}:{}", ip, port_num);
                        return;
                    }

                    // 获取地理位置信息
                    let (country_code, country_name, city_code, city_name) =
                        get_geo_info(country_reader, city_reader, ip);

                    // 获取 ASN 信息
                    let (asn_number, org_name) = if let Some(reader) = asn_reader {
                        get_asn_info(reader, ip)
                    } else {
                        (String::new(), String::new())
                    };

                    // CSV 格式: ip,port,国家代码,国家名,城市代码,城市名,ASN编号,组织名
                    let proxy_entry = format!("{},{},{},{},{},{},{},{}",
                        ip, port_num,
                        country_code, country_name,
                        city_code, city_name,
                        asn_number, org_name
                    );
                    println!("CF PROXY LIVE ✅: {}", proxy_entry);

                    // Add to active proxies for file output
                    {
                        let mut active_proxies_locked = active_proxies.lock().unwrap();
                        active_proxies_locked.push(proxy_entry);
                    }

                    // Add to batch for PostgreSQL
                    let proxy_data = ProxyData {
                        ip: ip.to_string(),
                        port: port_num,
                        country_code: country_code.clone(),
                        country_name: country_name.clone(),
                        city_code: city_code.clone(),
                        city_name: city_name.clone(),
                        asn_number: asn_number.clone(),
                        org_name: org_name.clone(),
                    };

                    {
                        let mut batch = proxy_data_batch.lock().unwrap();
                        batch.push(proxy_data);

                        let mut counter = batch_counter.lock().unwrap();
                        *counter += 1;

                        // Trigger batch write when reaching BATCH_SIZE (50)
                        if *counter >= 50 {
                            println!("📤 Writing batch of {} proxies to PostgreSQL...", batch.len());

                            // Clone data for async write
                            let batch_to_write = batch.clone();
                            let pool_clone = Arc::clone(pg_pool);

                            // Clear batch and reset counter
                            batch.clear();
                            *counter = 0;

                            // Spawn async task to write batch
                            tokio::spawn(async move {
                                if let Err(e) = batch_insert_proxies(&pool_clone, &batch_to_write, batch_time).await {
                                    eprintln!("❌ Failed to write batch to PostgreSQL: {}", e);
                                } else {
                                    println!("✅ Batch write completed successfully");
                                }
                            });
                        }
                    }
                } else {
                   // println!("CF PROXY DEAD ❌ (Same IP as original): {}:{}", ip, port_num);
                }
            } else {
               // println!("CF PROXY DEAD ❌ (No clientIp field in response): {}:{} - Response: {:?}", ip, port_num, proxy_data);
            }
        },
        Err(_e) => {
           // println!("CF PROXY DEAD ⏱️ (Error connecting): {}:{} - {}", ip, port_num, _e);
        }
    }
}
