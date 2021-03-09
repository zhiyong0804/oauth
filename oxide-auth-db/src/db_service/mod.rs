/// redis with redis
#[cfg(feature = "with-redis")]
pub mod redis;
#[cfg(feature = "with-redis")]
use redis::DBDataSource;



/// redis with redis cluster
#[cfg(feature = "with-redis-cluster")]
pub mod redis_cluster;
#[cfg(feature = "with-redis-cluster")]
use redis_cluster::DBDataSource;

/// redis with scylla
#[cfg(feature = "with-scylla")]
pub mod scylla;
#[cfg(feature = "with-scylla")]
use scylla::DBDataSource;

/// redis with scylla as persistence
#[cfg(feature = "with-redis-scylla")]
pub mod redis_scylla;
#[cfg(feature = "with-redis-scylla")]
use redis_scylla::DBDataSource;


#[cfg(feature = "with-cluster-redis-scylla")]
pub mod redis_scylla_cluster;
#[cfg(feature = "with-cluster-redis-scylla")]
use redis_scylla_cluster::DBDataSource;


pub type DataSource = DBDataSource;

