mod db;

pub use db::{Db, Meta};

use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::env;
use std::time::Duration;

pub fn init() -> anyhow::Result<()> {
    let config = HashMap::new();

    #[cfg(target_os = "linux")]
    {
        // Keyutils keys live in kernel memory, so every cache entry is lost on
        // reboot. Secret Service is disk-backed and matches what the macOS and
        // BSD builds give. Keyutils stays reachable for sessions without a
        // Secret Service provider, such as a headless box with no D-Bus.
        let backend = env::var("OP_FAST_KEYRING").unwrap_or_else(|_| "secret-service".into());
        match backend.as_str() {
            "secret-service" => {
                match dbus_secret_service_keyring_store::Store::new_with_configuration(&config) {
                    Ok(store) => {
                        keyring_core::set_default_store(store);
                        Ok(())
                    }
                    Err(e) => {
                        log::warn!(
                            "Secret Service unavailable ({}), falling back to keyutils",
                            e
                        );
                        let store =
                            linux_keyutils_keyring_store::Store::new_with_configuration(&config)
                                .map_err(|e| {
                                    anyhow::anyhow!(
                                        "Failed to initialize Linux keyutils store: {}",
                                        e
                                    )
                                })?;
                        keyring_core::set_default_store(store);
                        Ok(())
                    }
                }
            }
            "keyutils" => {
                let store = linux_keyutils_keyring_store::Store::new_with_configuration(&config)
                    .map_err(|e| {
                        anyhow::anyhow!("Failed to initialize Linux keyutils store: {}", e)
                    })?;
                keyring_core::set_default_store(store);
                Ok(())
            }
            other => anyhow::bail!(
                "Unknown OP_FAST_KEYRING value: {} (expected \"secret-service\" or \"keyutils\")",
                other
            ),
        }
    }

    #[cfg(target_os = "macos")]
    {
        let store = apple_native_keyring_store::keychain::Store::new_with_configuration(&config)
            .map_err(|e| anyhow::anyhow!("Failed to initialize macOS keychain store: {}", e))?;
        keyring_core::set_default_store(store);
        Ok(())
    }

    #[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
    {
        let store = dbus_secret_service_keyring_store::Store::new_with_configuration(&config)
            .map_err(|e| anyhow::anyhow!("Failed to initialize Secret Service store: {}", e))?;
        keyring_core::set_default_store(store);
        Ok(())
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
    )))]
    {
        anyhow::bail!("No supported keyring backend is configured for this platform");
    }
}

pub struct Store {
    db: Db,
}

impl Store {
    pub fn open() -> anyhow::Result<Self> {
        let db = Db::open()?;
        let store = Self { db };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now.is_multiple_of(10)
            && let Err(e) = store.db.gc()
        {
            log::warn!("Background GC failed: {}", e);
        }

        Ok(store)
    }

    pub fn get(&self, reference: &str) -> anyhow::Result<Option<String>> {
        match self.db.get(reference)? {
            Some(value) => {
                log::debug!("Store hit for: {}", reference);
                Ok(Some(value))
            }
            None => {
                log::debug!("Store miss for: {}", reference);
                Ok(None)
            }
        }
    }

    pub fn put(&self, reference: &str, value: &str, ttl: Duration) -> anyhow::Result<()> {
        self.db.put(reference, value, ttl)?;
        log::debug!("Stored {} with TTL {:?}", reference, ttl);
        Ok(())
    }

    pub fn delete(&self, reference: &str) -> anyhow::Result<bool> {
        self.db.delete(reference)
    }

    pub fn list(&self) -> anyhow::Result<Vec<(String, Meta)>> {
        self.db.list()
    }

    pub fn clear(&self) -> anyhow::Result<()> {
        self.db.clear()
    }
}
