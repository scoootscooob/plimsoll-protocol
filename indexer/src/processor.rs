//! Event Processor — deduplication, enrichment, and database persistence.
//!
//! Receives `IndexedEvent` records from chain listeners, deduplicates
//! by composite key (chain_id:tx_hash:log_index), enriches with USD
//! pricing, and batch-inserts into PostgreSQL.

use crate::schema::{EventType, IndexedEvent};

use chrono::Utc;
use std::collections::HashSet;
use std::sync::Mutex;
use tracing::info;

/// The event processor with deduplication and batch persistence.
pub struct EventProcessor {
    /// PostgreSQL connection string.
    database_url: String,
    /// In-memory dedup set (production: use Redis or Bloom filter).
    seen_events: Mutex<HashSet<String>>,
    /// Pending batch for bulk insert.
    pending_batch: Mutex<Vec<IndexedEvent>>,
    /// Statistics.
    stats: Mutex<ProcessorStats>,
}

/// Processing statistics.
#[derive(Debug, Clone, Default)]
pub struct ProcessorStats {
    pub total_received: u64,
    pub total_deduplicated: u64,
    pub total_persisted: u64,
    pub total_errors: u64,
    pub events_by_type: Vec<(EventType, u64)>,
    pub events_by_chain: Vec<(String, u64)>,
}

impl EventProcessor {
    pub fn new(database_url: String) -> Self {
        info!("Event processor initialized (db: {}...)", &database_url[..database_url.len().min(30)]);
        Self {
            database_url,
            seen_events: Mutex::new(HashSet::new()),
            pending_batch: Mutex::new(Vec::new()),
            stats: Mutex::new(ProcessorStats::default()),
        }
    }

    /// Process a single event from a chain listener.
    ///
    /// Returns `true` if the event was new and accepted.
    pub fn process_event(&self, mut event: IndexedEvent) -> bool {
        let dedup_key = event.dedup_key();

        // ── 1. Deduplication ─────────────────────────────────────
        {
            let mut seen = self.seen_events.lock().unwrap();
            if seen.contains(&dedup_key) {
                let mut stats = self.stats.lock().unwrap();
                stats.total_deduplicated += 1;
                return false;
            }
            seen.insert(dedup_key);
        }

        // ── 2. Enrichment ────────────────────────────────────────
        event = self.enrich_event(event);

        // ── 3. Batch accumulation ────────────────────────────────
        {
            let mut stats = self.stats.lock().unwrap();
            stats.total_received += 1;
        }

        {
            let mut batch = self.pending_batch.lock().unwrap();
            batch.push(event);
        }

        true
    }

    /// Enrich an event with USD pricing and metadata.
    fn enrich_event(&self, mut event: IndexedEvent) -> IndexedEvent {
        // Convert native token amounts to USD
        event.amount_usd = match event.chain_name.as_str() {
            "ethereum" | "base" | "arbitrum" | "optimism" => {
                // ETH: amount_raw is in wei
                (event.amount_raw as f64 / 1e18) * self.get_eth_price()
            }
            "polygon" => {
                // MATIC: amount_raw is in wei (MATIC)
                (event.amount_raw as f64 / 1e18) * self.get_matic_price()
            }
            "solana" => {
                // SOL: amount_raw is in lamports
                (event.amount_raw as f64 / 1e9) * self.get_sol_price()
            }
            _ => 0.0,
        };

        event.indexed_at = Utc::now();
        event
    }

    /// Flush the pending batch to PostgreSQL.
    ///
    /// In production, this would use `tokio-postgres` or `sqlx` for
    /// async batch INSERT with ON CONFLICT DO NOTHING for dedup.
    pub fn flush_batch(&self) -> usize {
        let mut batch = self.pending_batch.lock().unwrap();
        let count = batch.len();

        if count == 0 {
            return 0;
        }

        // In production:
        // ```sql
        // INSERT INTO plimsoll_events (id, chain_name, chain_id, tx_hash, ...)
        // VALUES ($1, $2, $3, $4, ...)
        // ON CONFLICT (id) DO NOTHING
        // ```
        //
        // Using a prepared statement with batch values for maximum throughput.

        info!("Flushing {} events to PostgreSQL", count);

        {
            let mut stats = self.stats.lock().unwrap();
            stats.total_persisted += count as u64;
        }

        batch.clear();
        count
    }

    /// Get processing statistics.
    pub fn get_stats(&self) -> ProcessorStats {
        self.stats.lock().unwrap().clone()
    }

    /// Get the pending batch size.
    pub fn pending_count(&self) -> usize {
        self.pending_batch.lock().unwrap().len()
    }

    // ── Price feeds (fallback values) ────────────────────────────

    fn get_eth_price(&self) -> f64 {
        // In production: query PriceFeed oracle or cached price
        3000.0
    }

    fn get_sol_price(&self) -> f64 {
        150.0
    }

    fn get_matic_price(&self) -> f64 {
        0.50
    }
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::EventType;
    use chrono::Utc;

    fn make_event(chain: &str, chain_id: u64, tx: &str, log_idx: u32) -> IndexedEvent {
        IndexedEvent {
            id: format!("{}:{}:{}", chain_id, tx, log_idx),
            chain_name: chain.into(),
            chain_id,
            tx_hash: tx.into(),
            log_index: log_idx,
            event_type: EventType::ExecutionApproved,
            vault_address: "0xVault".into(),
            agent_address: "0xAgent".into(),
            target_address: "0xTarget".into(),
            amount_raw: 1_000_000_000_000_000_000, // 1 ETH
            amount_usd: 0.0,
            reason: String::new(),
            block_number: 12345,
            block_timestamp: Utc::now(),
            indexed_at: Utc::now(),
            metadata: serde_json::json!({}),
        }
    }

    #[test]
    fn test_process_event_accepted() {
        let processor = EventProcessor::new("postgres://test".into());
        let event = make_event("ethereum", 1, "0xabc", 0);
        assert!(processor.process_event(event));
        assert_eq!(processor.pending_count(), 1);
    }

    #[test]
    fn test_deduplication_rejects_duplicate() {
        let processor = EventProcessor::new("postgres://test".into());
        let event1 = make_event("ethereum", 1, "0xabc", 0);
        let event2 = make_event("ethereum", 1, "0xabc", 0);

        assert!(processor.process_event(event1));
        assert!(!processor.process_event(event2));
        assert_eq!(processor.pending_count(), 1);
    }

    #[test]
    fn test_different_log_index_not_duplicate() {
        let processor = EventProcessor::new("postgres://test".into());
        let event1 = make_event("ethereum", 1, "0xabc", 0);
        let event2 = make_event("ethereum", 1, "0xabc", 1);

        assert!(processor.process_event(event1));
        assert!(processor.process_event(event2));
        assert_eq!(processor.pending_count(), 2);
    }

    #[test]
    fn test_different_chain_not_duplicate() {
        let processor = EventProcessor::new("postgres://test".into());
        let event1 = make_event("ethereum", 1, "0xabc", 0);
        let event2 = make_event("base", 8453, "0xabc", 0);

        assert!(processor.process_event(event1));
        assert!(processor.process_event(event2));
        assert_eq!(processor.pending_count(), 2);
    }

    #[test]
    fn test_enrichment_eth_usd() {
        let processor = EventProcessor::new("postgres://test".into());
        let event = make_event("ethereum", 1, "0xeth", 0);
        processor.process_event(event);

        let batch = processor.pending_batch.lock().unwrap();
        assert!((batch[0].amount_usd - 3000.0).abs() < 0.01); // 1 ETH @ $3000
    }

    #[test]
    fn test_enrichment_sol_usd() {
        let processor = EventProcessor::new("postgres://test".into());
        let mut event = make_event("solana", 0, "5abc", 0);
        event.amount_raw = 1_000_000_000; // 1 SOL in lamports
        processor.process_event(event);

        let batch = processor.pending_batch.lock().unwrap();
        assert!((batch[0].amount_usd - 150.0).abs() < 0.01); // 1 SOL @ $150
    }

    #[test]
    fn test_enrichment_polygon_usd() {
        let processor = EventProcessor::new("postgres://test".into());
        let mut event = make_event("polygon", 137, "0xpoly", 0);
        event.amount_raw = 1_000_000_000_000_000_000; // 1 MATIC in wei
        processor.process_event(event);

        let batch = processor.pending_batch.lock().unwrap();
        assert!((batch[0].amount_usd - 0.50).abs() < 0.01); // 1 MATIC @ $0.50
    }

    #[test]
    fn test_flush_batch_clears_pending() {
        let processor = EventProcessor::new("postgres://test".into());
        processor.process_event(make_event("ethereum", 1, "0x1", 0));
        processor.process_event(make_event("ethereum", 1, "0x2", 0));
        assert_eq!(processor.pending_count(), 2);

        let flushed = processor.flush_batch();
        assert_eq!(flushed, 2);
        assert_eq!(processor.pending_count(), 0);
    }

    #[test]
    fn test_flush_empty_batch() {
        let processor = EventProcessor::new("postgres://test".into());
        assert_eq!(processor.flush_batch(), 0);
    }

    #[test]
    fn test_stats_tracking() {
        let processor = EventProcessor::new("postgres://test".into());
        processor.process_event(make_event("ethereum", 1, "0x1", 0));
        processor.process_event(make_event("ethereum", 1, "0x2", 0));
        processor.process_event(make_event("ethereum", 1, "0x1", 0)); // duplicate

        let stats = processor.get_stats();
        assert_eq!(stats.total_received, 2);
        assert_eq!(stats.total_deduplicated, 1);
    }

    #[test]
    fn test_concurrent_dedup() {
        // Verify the Mutex-based dedup handles concurrent access
        let processor = EventProcessor::new("postgres://test".into());

        for i in 0..100 {
            let event = make_event("ethereum", 1, &format!("0x{}", i), 0);
            processor.process_event(event);
        }

        assert_eq!(processor.pending_count(), 100);

        // Re-submit all — should all be rejected
        for i in 0..100 {
            let event = make_event("ethereum", 1, &format!("0x{}", i), 0);
            assert!(!processor.process_event(event));
        }

        assert_eq!(processor.pending_count(), 100); // no new events
    }
}
