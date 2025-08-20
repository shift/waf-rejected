# Phase 2: Performance & Caching - Storage Engine & I/O Optimization

## Current Status: Implementation Phase - P2-03 Follower Reads
**Priority**: High  
**Assigned**: @shift  
**Project**: [Phase 2: Performance & Caching](https://github.com/users/shift/projects/4)

## Objective
Implement high-performance storage engine with I/O optimization and caching capabilities to support enterprise-scale WAF deployment with sub-millisecond latency requirements.

## ✅ Completed Tasks (P2-01 & P2-02)
- **Storage Engine Integration**: Complete StorageAdapter trait with redb, sled, and memory backends
- **I/O Optimization**: io_uring integration with high-performance file and network I/O 
- **Performance Infrastructure**: Benchmarking tools and statistics tracking
- **Branch**: `feat/io-uring-optimization` (commit: cdf8e17)

## Context & Requirements

### Performance Targets
- **Latency**: <100μs for cache hits, <1ms for storage operations
- **Throughput**: >100,000 requests/second sustained
- **Storage**: Support for TTL-based key expiration and follower reads
- **I/O**: Linux io_uring integration for zero-copy operations

### Architecture Goals
- Replace current sled-based storage with redb for better performance
- Implement storage adapter trait for pluggable backends
- Add follower read capabilities for eventual consistency scenarios
- Background TTL expiration with efficient cleanup

## Implementation Plan

### Phase 2 Task Breakdown

#### ✅ Completed Tasks
- **WASM Optimization**: Instance pooling and performance improvements committed
- **Project Infrastructure**: GitHub project board and documentation established
- **P2-01: Storage Engine Integration**: ✅ **COMPLETED**
  - [x] Add redb crate dependency to Cargo.toml
  - [x] Implement StorageAdapter trait for pluggable backends
  - [x] Create redb-based storage implementation
  - [x] Migrate existing sled usage to new adapter pattern
  - [x] Validate data compatibility and migration path

#### 🚧 Current Tasks

**P2-01: Storage Engine Integration**
- [ ] Add redb crate dependency to Cargo.toml
- [ ] Implement StorageAdapter trait for pluggable backends
- [ ] Create redb-based storage implementation
- [ ] Migrate existing sled usage to new adapter pattern
- [ ] Validate data compatibility and migration path

**P2-02: I/O Optimization** 
- [ ] Add tokio-uring dependency for io_uring support
- [ ] Implement io_uring backend for file operations
- [ ] Optimize network I/O with zero-copy operations
- [ ] Benchmark I/O performance improvements

**P2-03: Follower Reads**
- [ ] Add ReadConsistency enum (Strong, Eventual)
- [ ] Implement follower read logic in storage adapter
- [ ] Add configuration options for read consistency
- [ ] Test eventual consistency scenarios

**P2-04: TTL Storage**
- [ ] Design key_expirations table schema in redb
- [ ] Implement TTL setting and tracking functionality
- [ ] Add TTL metadata to storage operations
- [ ] Validate TTL accuracy and performance

**P2-05/P2-06: TTL Expiration & Deletion**
- [ ] Implement background expiration task
- [ ] Add configurable expiration interval
- [ ] Optimize bulk deletion operations
- [ ] Monitor expiration performance impact

**P2-07: Performance Testing**
- [ ] Create Tier 1 workload tests (cache-heavy)
- [ ] Create Tier 2 workload tests (storage-heavy)
- [ ] Implement P99 latency validation
- [ ] Establish performance regression testing

## Technical Specifications

### Storage Architecture
```rust
// New storage adapter trait
pub trait StorageAdapter: Send + Sync {
    async fn get(&self, key: &[u8], consistency: ReadConsistency) -> Result<Option<Vec<u8>>>;
    async fn set(&self, key: &[u8], value: &[u8], ttl: Option<Duration>) -> Result<()>;
    async fn delete(&self, key: &[u8]) -> Result<bool>;
    async fn exists(&self, key: &[u8]) -> Result<bool>;
    async fn expire_keys(&self) -> Result<u64>; // Returns count of expired keys
}

pub enum ReadConsistency {
    Strong,    // Read from primary
    Eventual,  // Allow follower reads
}
```

### Database Schema (redb)
```rust
// Main data table
const DATA_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("data");

// TTL expiration tracking
const EXPIRATION_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("expirations");
// Key: expiration_timestamp_ms, Value: key
```

### Configuration Updates
```toml
[storage]
backend = "redb"  # "sled", "redb", "memory"
path = "./data/waf.redb"
enable_follower_reads = true
ttl_cleanup_interval = "60s"

[io]
backend = "io_uring"  # "standard", "io_uring"
enable_zero_copy = true
```

## Acceptance Criteria

### Performance Requirements
- [ ] P99 latency <1ms for storage operations
- [ ] P99 latency <100μs for cache hits
- [ ] Sustained throughput >100k requests/second
- [ ] Memory usage stable under load
- [ ] TTL expiration accuracy within 1 second

### Functional Requirements
- [ ] All existing storage functionality preserved
- [ ] Seamless migration from sled to redb
- [ ] Follower reads configurable per operation
- [ ] TTL functionality with background cleanup
- [ ] Zero data loss during migrations

### Quality Requirements
- [ ] Comprehensive unit test coverage (>90%)
- [ ] Integration tests for all storage adapters
- [ ] Performance regression test suite
- [ ] Documentation for new storage architecture
- [ ] Migration guide from existing deployments

## Dependencies & Blockers

### Dependencies
- **redb crate**: Latest stable version for storage backend
- **tokio-uring**: For Linux io_uring integration
- **Performance baseline**: Current metrics from WASM optimization

### Potential Blockers
- **io_uring compatibility**: Linux kernel version requirements
- **Data migration**: Large existing sled databases
- **Performance validation**: Hardware-specific optimizations needed

## Timeline & Milestones

### Week 1: Storage Foundation
- P2-01: Storage adapter implementation
- P2-02: Basic I/O optimization

### Week 2: Advanced Features  
- P2-03: Follower reads implementation
- P2-04: TTL storage functionality

### Week 3: Cleanup & Testing
- P2-05/P2-06: TTL expiration system
- P2-07: Comprehensive performance testing

### Week 4: Integration & Validation
- End-to-end testing
- Performance validation
- Documentation completion

## Next Actions

1. **Start P2-01**: Begin storage adapter trait implementation
2. **Research redb**: Study optimal configuration and usage patterns  
3. **Baseline metrics**: Establish current performance benchmarks
4. **Test environment**: Set up isolated testing for storage migration

## Notes & Decisions

- **Storage choice**: redb selected over alternatives for better performance characteristics
- **I/O strategy**: io_uring provides significant performance benefits on Linux
- **Migration strategy**: Implement both backends temporarily for safe migration
- **Testing approach**: Separate performance and functional testing phases

---

**Last Updated**: 2025-08-20  
**Next Review**: Daily during implementation phase