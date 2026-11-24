//! Integration tests for end-to-end DNS functionality

use rdnsx_core::{client::DnsxClient, config::DnsxOptions, types::RecordType};

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "needs public DNS; CI runs it with --include-ignored"]
    async fn test_google_dns_resolution() {
        let client = DnsxClient::with_options(DnsxOptions {
            resolvers: vec!["8.8.8.8:53".to_string()],
            ..Default::default()
        })
        .unwrap();

        let records = client.query("google.com", RecordType::A).await.unwrap();
        assert!(!records.is_empty());
        assert!(records[0].domain == "google.com");
        assert_eq!(records[0].record_type, RecordType::A);
    }

    #[tokio::test]
    #[ignore = "needs public DNS; CI runs it with --include-ignored"]
    async fn test_cloudflare_dns_resolution() {
        let client = DnsxClient::with_options(DnsxOptions {
            resolvers: vec!["1.1.1.1:53".to_string()],
            ..Default::default()
        })
        .unwrap();

        let records = client.query("cloudflare.com", RecordType::A).await.unwrap();
        assert!(!records.is_empty());
    }

    #[tokio::test]
    #[ignore = "needs public DNS; CI runs it with --include-ignored"]
    async fn test_ipv4_lookup() {
        let client = DnsxClient::new().unwrap();
        let ips = client.lookup_ipv4("github.com").await.unwrap();
        assert!(!ips.is_empty());
        // Verify all returned values are valid IPv4 addresses
        for ip in ips {
            assert!(!ip.is_unspecified());
        }
    }

    #[tokio::test]
    #[ignore = "needs public DNS; CI runs it with --include-ignored"]
    async fn test_multiple_record_types() {
        let client = DnsxClient::new().unwrap();

        // Test A records
        let a_records = client.query("google.com", RecordType::A).await.unwrap();
        assert!(!a_records.is_empty());

        // Test CNAME records (may not exist for root domain)
        let cname_result = client.query("www.google.com", RecordType::Cname).await;
        // CNAME query should not fail, even if no records exist
        assert!(cname_result.is_ok());
    }

    #[tokio::test]
    #[ignore = "needs public DNS; CI runs it with --include-ignored"]
    async fn test_txt_record_parsing() {
        let client = DnsxClient::new().unwrap();
        let records = client.query("google.com", RecordType::Txt).await.unwrap();

        // TXT records may or may not exist, but parsing should work
        for record in records {
            if let rdnsx_core::types::RecordValue::Text(_) = &record.value {
                // Successfully parsed TXT record
            }
        }
    }

    #[tokio::test]
    #[ignore = "needs public DNS; CI runs it with --include-ignored"]
    async fn test_mx_record_parsing() {
        let client = DnsxClient::new().unwrap();
        let records = client.query("google.com", RecordType::Mx).await.unwrap();
        assert!(!records.is_empty());

        // Verify MX records have priority and exchange
        for record in records {
            if let rdnsx_core::types::RecordValue::Mx { exchange, .. } = &record.value {
                assert!(!exchange.is_empty());
            }
        }
    }

    #[tokio::test]
    #[ignore = "needs public DNS; CI runs it with --include-ignored"]
    async fn test_custom_timeout() {
        let client = DnsxClient::with_options(DnsxOptions {
            timeout: std::time::Duration::from_secs(1),
            ..Default::default()
        })
        .unwrap();

        // This should work within the timeout
        let records = client.query("google.com", RecordType::A).await.unwrap();
        assert!(!records.is_empty());
    }

    #[tokio::test]
    #[ignore = "needs public DNS; CI runs it with --include-ignored"]
    async fn test_nonexistent_domain() {
        let client = DnsxClient::new().unwrap();

        // Query for a domain that definitely doesn't exist
        let response = client
            .query_response("definitely-not-a-real-domain-12345.com", RecordType::A)
            .await
            .unwrap();

        assert_eq!(response.response_code, rdnsx_core::ResponseCode::NxDomain);
        assert!(response.records.is_empty());
    }

    #[tokio::test]
    #[ignore = "needs public DNS; CI runs it with --include-ignored"]
    async fn test_concurrent_queries() {
        let client = std::sync::Arc::new(DnsxClient::new().unwrap());

        let domains = vec!["google.com", "github.com", "stackoverflow.com"];
        let mut handles = Vec::new();

        for domain in domains {
            let client = std::sync::Arc::clone(&client);
            let domain = domain.to_string();
            let handle = tokio::spawn(async move { client.query(&domain, RecordType::A).await });
            handles.push(handle);
        }

        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok());
            assert!(!result.unwrap().is_empty());
        }
    }

    #[tokio::test]
    #[ignore = "needs public DNS; CI runs it with --include-ignored"]
    async fn test_resolver_fallback() {
        // Test with multiple resolvers to ensure fallback works
        let client = DnsxClient::with_options(DnsxOptions {
            resolvers: vec![
                "8.8.8.8:53".to_string(),
                "1.1.1.1:53".to_string(),
                "9.9.9.9:53".to_string(),
            ],
            ..Default::default()
        })
        .unwrap();

        let records = client.query("google.com", RecordType::A).await.unwrap();
        assert!(!records.is_empty());
    }
}
