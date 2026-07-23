//! DNS resolution via the [hickory-resolver](https://github.com/hickory-dns/hickory-dns) crate
//!
//! ## Fork workaround
//!
//! **Tokio does not support `fork(2)` after the runtime has been used**
//! ([docs](https://docs.rs/tokio/latest/tokio/runtime/#unix-fork)). This
//! module provides a *best-effort* workaround for the specific pattern where
//! a new runtime is built in the child (e.g. the wreq-php extension's
//! PID-tagged runtime hook): the DNS resolver is rebuilt alongside it.
//!
//! A plain `static LazyLock` would survive `fork(2)` already initialized,
//! but its `TokioResolver` would still reference the parent's dead runtime —
//! every lookup would hang until the connect timeout.
//!
//! We cache the resolver in a `thread_local!` tagged with the PID that built
//! it. On PID mismatch (forked child) the inherited resolver is
//! `mem::forget`-ed — its sockets belong to the parent's I/O driver and its
//! `Drop` could panic or hang — and a fresh one is built on the current
//! runtime.
//!
//! `thread_local!` (rather than a process-global `Mutex`) avoids the classic
//! fork-with-held-lock deadlock: if another thread held a global mutex at the
//! moment of `fork`, the child would inherit it locked with no thread to
//! release it. Thread-local storage has no cross-thread contention.

use std::{
    cell::RefCell,
    mem,
    net::SocketAddr,
    sync::Arc,
};

use hickory_resolver::{
    TokioResolver,
    config::{self, LookupIpStrategy, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
};

use super::{Addrs, Name, Resolve, Resolving};

thread_local! {
    /// Per-thread DNS resolver cache, tagged with the PID that built it.
    /// See the module-level "Fork workaround" note.
    static RESOLVER: RefCell<Option<(u32, Arc<TokioResolver>)>> = const { RefCell::new(None) };
}

/// Returns a shared reference to a `TokioResolver` for the current thread,
/// building it on first use and rebuilding after a `fork` (PID mismatch).
///
/// Must be called from within a Tokio runtime context (inside `block_on`),
/// because `TokioResolver::builder_tokio()` captures the current runtime
/// handle.
fn shared_resolver() -> Arc<TokioResolver> {
    let pid = std::process::id();

    RESOLVER.with(|cell| {
        let mut guard = cell.borrow_mut();

        match guard.as_ref() {
            Some((owner, resolver)) if *owner == pid => return Arc::clone(resolver),
            // Inherited across a fork: the resolver's sockets are registered
            // in the parent's I/O driver, which is dead here. Abandon it
            // without running Drop.
            Some(_) => {
                if let Some((_, stale)) = guard.take() {
                    mem::forget(stale);
                }
            }
            None => {}
        }

        let resolver = Arc::new(build());
        *guard = Some((pid, Arc::clone(&resolver)));
        resolver
    })
}

fn build() -> TokioResolver {
    let mut builder = match TokioResolver::builder_tokio() {
        Ok(resolver) => {
            debug!("using system DNS configuration");
            resolver
        }
        Err(_err) => {
            debug!("error reading DNS system conf: {}, using defaults", _err);
            TokioResolver::builder_with_config(
                ResolverConfig::udp_and_tcp(&config::GOOGLE),
                TokioRuntimeProvider::default(),
            )
        }
    };
    builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    builder.build().expect("failed to create DNS resolver")
}

/// Wrapper around a per-thread [`TokioResolver`], which implements the [`Resolve`] trait.
///
/// Stateless handle — the actual resolver is cached per-thread (see
/// [`shared_resolver`]) and rebuilt automatically after `fork`.
#[derive(Debug, Clone)]
pub struct HickoryDnsResolver {
    _priv: (),
}

impl HickoryDnsResolver {
    /// Create a new resolver with the default configuration,
    /// which reads from `/etc/resolv.conf`. The options are
    /// overridden to look up both IPv4 and IPv6 addresses
    /// to support the "happy eyeballs" algorithm.
    ///
    /// SAFETY: `build` only fails if DNS-over-TLS is enabled and default TLS config creation fails.
    pub fn new() -> HickoryDnsResolver {
        HickoryDnsResolver { _priv: () }
    }
}

impl Resolve for HickoryDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let resolver = shared_resolver();
            let lookup = resolver.lookup_ip(name.as_str()).await?;
            let addrs: Addrs = Box::new(
                lookup
                    .iter()
                    .map(|ip_addr| SocketAddr::new(ip_addr, 0))
                    .collect::<Vec<_>>()
                    .into_iter(),
            );
            Ok(addrs)
        })
    }
}
