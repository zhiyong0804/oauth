/// redis with redis
#[cfg(feature = "with-redis")]
pub mod redis;

#[cfg(feature = "with-redis")]
use crate::db_service::redis::RedisDataSource;

#[cfg(feature = "with-redis")]
pub type DataSource = RedisDataSource;



/// redis with redis cluster
#[cfg(feature = "with-redis-cluster")]
pub mod redis_cluster;

#[cfg(feature = "with-redis-cluster")]
use redis_cluster::RedisClusterDataSource;

#[cfg(feature = "with-redis-cluster")]
pub type DataSource = RedisClusterDataSource;

/// redis with scylla
#[cfg(feature = "with-scylla")]
pub mod scylla;

#[cfg(feature = "with-scylla")]
use scylla::ScyllaDataSource;

#[cfg(feature = "with-scylla")]
pub type DataSource = ScyllaDataSource;

/// redis with scylla as persistence
#[cfg(feature = "with-redis-scylla")]
pub mod redis_scylla;

#[cfg(feature = "with-redis-scylla")]
use redis_scylla::DBDataSource;

#[cfg(feature = "with-redis-scylla")]
pub type DataSource = DBDataSource;

