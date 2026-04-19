use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct DnsCacheKey {
    pub query_name: String,
    pub query_type: u16,
    pub selection_scope: String,
}

impl DnsCacheKey {
    pub fn new(query_name: String, query_type: u16, candidate_server_tags: &[String]) -> Self {
        Self {
            query_name,
            query_type,
            selection_scope: candidate_server_tags.join(","),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DnsCacheValue {
    pub raw_message: Vec<u8>,
    pub stored_server_tag: String,
    pub ttl: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DnsCacheLookup {
    Hit(DnsCacheValue),
    Miss,
    Expired,
}

#[derive(Clone, Debug)]
struct DnsCacheEntry {
    value: DnsCacheValue,
    expires_at: Instant,
    lru_tick: u64,
}

#[derive(Debug)]
pub(crate) struct DnsCache {
    capacity: usize,
    next_tick: u64,
    entries: HashMap<DnsCacheKey, DnsCacheEntry>,
    lru: VecDeque<(DnsCacheKey, u64)>,
}

impl DnsCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            next_tick: 1,
            entries: HashMap::new(),
            lru: VecDeque::new(),
        }
    }

    pub fn lookup(&mut self, key: &DnsCacheKey) -> DnsCacheLookup {
        self.lookup_at(key, Instant::now())
    }

    pub fn lookup_at(&mut self, key: &DnsCacheKey, now: Instant) -> DnsCacheLookup {
        let Some(entry) = self.entries.get(key) else {
            return DnsCacheLookup::Miss;
        };

        if entry.expires_at <= now {
            self.entries.remove(key);
            return DnsCacheLookup::Expired;
        }

        let tick = self.bump_tick();
        let entry = self
            .entries
            .get_mut(key)
            .expect("dns cache entry should still exist");
        entry.lru_tick = tick;
        self.lru.push_back((key.clone(), tick));
        DnsCacheLookup::Hit(entry.value.clone())
    }

    pub fn store(
        &mut self,
        key: DnsCacheKey,
        raw_message: Vec<u8>,
        ttl: Duration,
        stored_server_tag: String,
    ) {
        self.store_at(key, raw_message, ttl, stored_server_tag, Instant::now());
    }

    pub fn store_at(
        &mut self,
        key: DnsCacheKey,
        raw_message: Vec<u8>,
        ttl: Duration,
        stored_server_tag: String,
        now: Instant,
    ) {
        if ttl.is_zero() {
            return;
        }

        let tick = self.bump_tick();
        let entry = DnsCacheEntry {
            value: DnsCacheValue {
                raw_message,
                stored_server_tag,
                ttl,
            },
            expires_at: now + ttl,
            lru_tick: tick,
        };
        self.entries.insert(key.clone(), entry);
        self.lru.push_back((key, tick));
        self.evict_if_needed();
    }

    fn bump_tick(&mut self) -> u64 {
        let tick = self.next_tick;
        self.next_tick = self.next_tick.saturating_add(1);
        tick
    }

    fn evict_if_needed(&mut self) {
        while self.entries.len() > self.capacity {
            let Some((candidate, tick)) = self.lru.pop_front() else {
                break;
            };
            let should_remove = self
                .entries
                .get(&candidate)
                .is_some_and(|entry| entry.lru_tick == tick);
            if should_remove {
                self.entries.remove(&candidate);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{DnsCache, DnsCacheKey, DnsCacheLookup};

    #[test]
    fn cache_hit_and_expiry_follow_ttl() {
        let now = Instant::now();
        let mut cache = DnsCache::new(4);
        let key = DnsCacheKey::new("example.com".into(), 1, &["remote".into()]);

        assert_eq!(cache.lookup_at(&key, now), DnsCacheLookup::Miss);

        cache.store_at(
            key.clone(),
            vec![1, 2, 3],
            Duration::from_secs(30),
            "remote".into(),
            now,
        );

        assert!(matches!(cache.lookup_at(&key, now), DnsCacheLookup::Hit(_)));
        assert_eq!(
            cache.lookup_at(&key, now + Duration::from_secs(30)),
            DnsCacheLookup::Expired
        );
    }

    #[test]
    fn cache_evicts_least_recently_used_entry() {
        let now = Instant::now();
        let mut cache = DnsCache::new(1);
        let first = DnsCacheKey::new("one.example".into(), 1, &["remote".into()]);
        let second = DnsCacheKey::new("two.example".into(), 1, &["remote".into()]);

        cache.store_at(
            first.clone(),
            vec![1],
            Duration::from_secs(30),
            "remote".into(),
            now,
        );
        cache.store_at(
            second.clone(),
            vec![2],
            Duration::from_secs(30),
            "remote".into(),
            now + Duration::from_secs(1),
        );

        assert_eq!(
            cache.lookup_at(&first, now + Duration::from_secs(2)),
            DnsCacheLookup::Miss
        );
        assert!(matches!(
            cache.lookup_at(&second, now + Duration::from_secs(2)),
            DnsCacheLookup::Hit(_)
        ));
    }
}
