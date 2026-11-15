#[cfg(feature = "encryption")]
use crate::error::Result;

#[cfg(feature = "encryption")]
use crate::crypto::{rar30::Rar30Cipher, rar50::Rar50Keys};

/// Keys per password and salt, each derived once without serializing distinct keys.
// Held by one opened archive or read session, never shared process-wide.
#[derive(Default)]
pub(crate) struct KeyCache {
    #[cfg(feature = "encryption")]
    rar50: Slots<([u8; 16], u8), Rar50Keys>,
    #[cfg(feature = "encryption")]
    rar30: Slots<Option<[u8; 8]>, Rar30Cipher>,
}

impl std::fmt::Debug for KeyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyCache").finish_non_exhaustive()
    }
}

#[cfg(feature = "encryption")]
impl KeyCache {
    pub(crate) fn rar50(
        &self,
        password: &[u8],
        salt: [u8; 16],
        kdf_count: u8,
    ) -> Result<Rar50Keys> {
        self.rar50.get_or_derive(password, (salt, kdf_count), || {
            Rar50Keys::derive(password, salt, kdf_count)
                .map_err(crate::rar50::map_rar50_crypto_error)
        })
    }

    /// A clone, so callers never share a CBC chain.
    pub(crate) fn rar30(&self, password: &[u8], salt: Option<[u8; 8]>) -> Result<Rar30Cipher> {
        self.rar30.get_or_derive(password, salt, || {
            Rar30Cipher::new(password, salt).map_err(crate::Error::from)
        })
    }
}

#[cfg(feature = "encryption")]
type Slot<V> = std::sync::Arc<std::sync::OnceLock<Result<V>>>;

#[cfg(feature = "encryption")]
type PasswordSlots<V> = Vec<(zeroize::Zeroizing<Vec<u8>>, Slot<V>)>;

#[cfg(feature = "encryption")]
struct Slots<K, V> {
    entries: std::sync::Mutex<std::collections::HashMap<K, PasswordSlots<V>>>,
}

#[cfg(feature = "encryption")]
impl<K, V> Default for Slots<K, V> {
    fn default() -> Self {
        Self {
            entries: std::sync::Mutex::default(),
        }
    }
}

#[cfg(feature = "encryption")]
impl<K: std::hash::Hash + Eq, V: Clone> Slots<K, V> {
    fn get_or_derive(
        &self,
        password: &[u8],
        key: K,
        derive: impl FnOnce() -> Result<V>,
    ) -> Result<V> {
        // Only lookup is serialized. Slots stay at fixed addresses, so growing
        // the map moves pointers rather than leaving key copies in old storage.
        let slot = {
            let mut entries = self
                .entries
                .lock()
                .map_err(|_| std::io::Error::other("key cache lock poisoned"))?;
            let passwords = entries.entry(key).or_default();
            match passwords
                .iter()
                .find(|(known, _)| known.as_slice() == password)
            {
                Some((_, slot)) => slot.clone(),
                None => {
                    let slot = Slot::default();
                    passwords.push((zeroize::Zeroizing::new(password.to_vec()), slot.clone()));
                    slot
                }
            }
        };
        slot.get_or_init(derive).clone()
    }
}
