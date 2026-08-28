//! Subscriptions to what the chain changes.
//!
//! A subscriber registers a [`ChangeFilter`] with the core and is woken
//! whenever the canonical head moves in a way that filter selects. What
//! arrives is a [`ChangeNotification`] — where the head was, where it is,
//! and the [`ChangeSet`] between the two — never the values themselves:
//! the answer to a notification is to go and read.
//!
//! Two properties shape the machinery. Publishing happens on the mainloop
//! task that owns the core, so nothing here may block or await: a slow
//! subscriber must never hold up the chain. And a subscriber that stops
//! reading must cost a bounded amount, so notifications merge into one
//! pending change set per subscription rather than queueing — falling
//! behind loses the shape of the movements, never the fact of them.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use lotusd_rpc as rpc;
use state::{Change, Movement};
use thunderdome::{Arena, Index};
use tokio::sync::mpsc;
use wire::{EnvelopeDigest, msg::NamespaceKey, subkey::SubkeyPath};

/// One thing a subscriber wants to hear about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeSelector {
    /// Every movement of the canonical head, whatever it changed.
    Head,
    /// Any change anywhere under a namespace.
    Namespace(NamespaceKey),
    /// A change to what a path addresses in a namespace. Matches in both
    /// directions: a write below the path, and a write above it that
    /// carries the path along with it.
    Path {
        /// The namespace the path is walked from.
        key: NamespaceKey,
        /// The path within it.
        path: SubkeyPath,
    },
    /// One envelope leaving the canonical chain — a reorg taking the chain
    /// down a branch that does not pass through it.
    ///
    /// Fires once and for all: an orphaned envelope never returns to the
    /// chain, so a subscriber watching one has heard everything there is to
    /// hear and can drop its handle. Compaction pruning an envelope is not
    /// this: a pruned envelope is still an ancestor of the head, it is
    /// merely no longer held.
    Orphaned(EnvelopeDigest),
}

impl ChangeSelector {
    /// Whether `movement` selects this — asked only of a movement that
    /// actually happened, which is why [`ChangeSelector::Head`] needs to
    /// look no further.
    fn selects(&self, movement: &Movement) -> bool {
        match self {
            ChangeSelector::Head => true,
            ChangeSelector::Namespace(key) => movement.changes.touches(key, None),
            ChangeSelector::Path { key, path } => movement.changes.touches(key, Some(path)),
            ChangeSelector::Orphaned(digest) => movement.orphaned.contains(digest),
        }
    }
}

/// What one subscription watches.
///
/// Never empty: a filter that can select nothing is a subscription that can
/// never fire, so the constructors each start from one selector and the
/// `and_` builders widen from there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeFilter {
    first: ChangeSelector,
    rest: Vec<ChangeSelector>,
}

impl ChangeFilter {
    /// Every movement of the canonical head.
    pub fn head() -> Self {
        Self::of(ChangeSelector::Head)
    }

    /// Any change under `key`.
    pub fn namespace(key: NamespaceKey) -> Self {
        Self::of(ChangeSelector::Namespace(key))
    }

    /// Changes to what `path` addresses in `key`.
    pub fn path(key: NamespaceKey, path: SubkeyPath) -> Self {
        Self::of(ChangeSelector::Path { key, path })
    }

    /// The envelope `digest` leaving the canonical chain.
    pub fn orphaned(digest: EnvelopeDigest) -> Self {
        Self::of(ChangeSelector::Orphaned(digest))
    }

    /// Also any change under `key`.
    pub fn and_namespace(self, key: NamespaceKey) -> Self {
        self.and(ChangeSelector::Namespace(key))
    }

    /// Also changes to what `path` addresses in `key`.
    pub fn and_path(self, key: NamespaceKey, path: SubkeyPath) -> Self {
        self.and(ChangeSelector::Path { key, path })
    }

    /// Also the envelope `digest` leaving the canonical chain.
    pub fn and_orphaned(self, digest: EnvelopeDigest) -> Self {
        self.and(ChangeSelector::Orphaned(digest))
    }

    /// Every selector this filter watches.
    pub fn selectors(&self) -> impl Iterator<Item = &ChangeSelector> {
        core::iter::once(&self.first).chain(&self.rest)
    }

    /// The selectors `movement` matched — what a woken subscriber asks to
    /// find out which of its interests fired.
    pub fn matched<'a>(
        &'a self,
        movement: &'a Movement,
    ) -> impl Iterator<Item = &'a ChangeSelector> {
        self.selectors()
            .filter(|selector| selector.selects(movement))
    }

    /// Whether any selector matched.
    pub fn matches(&self, movement: &Movement) -> bool {
        self.selectors().any(|selector| selector.selects(movement))
    }

    fn of(selector: ChangeSelector) -> Self {
        Self {
            first: selector,
            rest: Vec::new(),
        }
    }

    fn and(mut self, selector: ChangeSelector) -> Self {
        self.rest.push(selector);
        self
    }
}

impl From<rpc::WatchSelector> for ChangeSelector {
    fn from(selector: rpc::WatchSelector) -> Self {
        match selector {
            rpc::WatchSelector::Head => ChangeSelector::Head,
            rpc::WatchSelector::Namespace(key) => ChangeSelector::Namespace(key),
            rpc::WatchSelector::Path(rpc::WatchPath { key, path }) => {
                ChangeSelector::Path { key, path }
            }
            rpc::WatchSelector::Orphaned(digest) => ChangeSelector::Orphaned(digest),
        }
    }
}

impl From<ChangeSelector> for ChangeFilter {
    fn from(selector: ChangeSelector) -> Self {
        Self::of(selector)
    }
}

/// What a subscriber is woken with.
///
/// One notification can cover several movements of the head: a subscriber
/// that was not reading when the chain moved finds them merged rather than
/// queued, so `from` is where it was last told the head stood and `changes`
/// is everything that has happened since.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeNotification {
    /// The head the chain stood at before these changes.
    pub from: EnvelopeDigest,
    /// The head it stands at now.
    pub head: EnvelopeDigest,
    /// Everything that happened, not only what the filter selected — ask
    /// [`ChangeFilter::matched`] which interests fired.
    pub movement: Movement,
}

impl ChangeNotification {
    /// The notification in the shape the control protocol carries.
    ///
    /// The protocol keeps its own types rather than encoding the daemon's:
    /// what a [`ChangeSet`] is made of is an internal matter, and a client
    /// should not have to be rebuilt because it changed shape.
    ///
    /// [`ChangeSet`]: state::ChangeSet
    pub fn to_wire(&self) -> rpc::Changed {
        rpc::Changed {
            from: self.from,
            head: self.head,
            changes: self
                .movement
                .changes
                .iter()
                .map(|(key, change)| {
                    let change = match change {
                        Change::Whole => rpc::NamespaceChange::Whole,
                        Change::Paths(paths) => rpc::NamespaceChange::Paths(paths.clone()),
                    };
                    (key.clone(), change)
                })
                .collect(),
            orphaned: self.movement.orphaned.clone(),
        }
    }
}

/// A registered interest in what the chain changes.
///
/// Dropping it deregisters: the core stops matching against its filter and
/// stops accumulating for it, so a subscriber that goes away — a control
/// connection that hung up, a task that was cancelled — costs nothing from
/// the moment it does. Not `Clone`, since the notifications have one
/// reader; share one by putting it behind an `Arc` and the deregistration
/// still waits for the last owner.
#[derive(Debug)]
pub struct SubscriptionHandle {
    id: Index,
    opened_at: EnvelopeDigest,
    inner: Arc<SubscriptionInner>,
    wake: mpsc::Receiver<()>,
    registry: Weak<Mutex<Registry>>,
}

impl SubscriptionHandle {
    /// The head the chain stood at when this subscription was registered.
    ///
    /// Nothing moved between reading it and registering, so a subscriber
    /// that reads the state here is certain every later change reaches it
    /// as a notification.
    pub fn opened_at(&self) -> EnvelopeDigest {
        self.opened_at
    }

    /// What this subscription watches.
    pub fn filter(&self) -> &ChangeFilter {
        &self.inner.filter
    }

    /// The next notification, or `None` once the core is gone.
    ///
    /// Cancel-safe: what is pending is checked before waiting, so a wake
    /// dropped by a cancelled `next` is not a notification lost.
    pub async fn next(&mut self) -> Option<ChangeNotification> {
        loop {
            if let Some(notification) = self.inner.take() {
                return Some(notification);
            }
            // A wake with nothing behind it is ordinary: the publisher
            // merges before it wakes, so an earlier wake may already have
            // carried this one's changes away.
            self.wake.recv().await?;
        }
    }
}

impl Drop for SubscriptionHandle {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            lock(&registry).subscribers.remove(self.id);
        }
    }
}

/// The subscriptions a core publishes to.
///
/// Shared with every subscription it hands out, so one can deregister
/// itself when it is dropped without a round trip through the mainloop.
#[derive(Debug, Default)]
pub struct Subscriptions(Arc<Mutex<Registry>>);

impl Subscriptions {
    /// Registers `filter`, standing at the head `opened_at`.
    pub fn register(&self, filter: ChangeFilter, opened_at: EnvelopeDigest) -> SubscriptionHandle {
        // One wake is as good as ten: it says only that something is
        // pending, and the pending change set is where the detail lives.
        let (wake, rx) = mpsc::channel(1);
        let inner = Arc::new(SubscriptionInner {
            filter,
            pending: Mutex::new(None),
        });

        let id = lock(&self.0).subscribers.insert(Subscriber {
            inner: Arc::clone(&inner),
            wake,
        });

        SubscriptionHandle {
            id,
            opened_at,
            inner,
            wake: rx,
            registry: Arc::downgrade(&self.0),
        }
    }

    /// Wakes every subscription whose filter selects `changes`.
    ///
    /// Called only when the head actually moved, from `from` to `head`.
    /// Never blocks and never awaits: the mainloop publishes, and a
    /// subscriber that is not reading merely accumulates.
    pub fn publish(&self, from: EnvelopeDigest, head: EnvelopeDigest, movement: &Movement) {
        lock(&self.0)
            .subscribers
            .iter()
            .map(|(_, subscriber)| subscriber)
            .filter(|subscriber| subscriber.inner.filter.matches(movement))
            .for_each(|subscriber| subscriber.push(from, head, movement));
    }

    /// How many subscriptions are registered.
    pub fn count(&self) -> usize {
        lock(&self.0).subscribers.len()
    }
}

/// Every registered subscription.
///
/// An arena rather than a map: registering and deregistering are the only
/// things that ever happen to it, and its indices are generational, so a
/// slot reused by a later subscription cannot be removed by an earlier
/// one's index.
#[derive(Debug, Default)]
struct Registry {
    subscribers: Arena<Subscriber>,
}

/// One subscription as the publisher holds it.
///
/// The waking end lives here rather than in the shared
/// [`SubscriptionInner`] so that a core going away closes it: the handle is
/// left holding a receiver whose senders are gone, which is how
/// [`SubscriptionHandle::next`] comes to a stop instead of waiting for a
/// chain nothing will advance.
#[derive(Debug)]
struct Subscriber {
    inner: Arc<SubscriptionInner>,
    wake: mpsc::Sender<()>,
}

/// What a [`SubscriptionHandle`] and its publisher share.
#[derive(Debug)]
struct SubscriptionInner {
    filter: ChangeFilter,
    /// What has accumulated since the subscriber last drained. Merged
    /// rather than queued, so a subscriber that stops reading costs one
    /// change set however long it stops for.
    pending: Mutex<Option<ChangeNotification>>,
}

impl SubscriptionInner {
    fn take(&self) -> Option<ChangeNotification> {
        lock(&self.pending).take()
    }
}

impl Subscriber {
    /// Merges a movement into what is pending and wakes the subscriber.
    fn push(&self, from: EnvelopeDigest, head: EnvelopeDigest, movement: &Movement) {
        // Merged before the wake, so a subscriber woken by it never finds
        // less than it was woken for.
        {
            let mut pending = lock(&self.inner.pending);
            if let Some(accumulated) = pending.as_mut() {
                // `from` stays where the oldest undrained movement started.
                accumulated.head = head;
                accumulated.movement.merge(movement);
            } else {
                *pending = Some(ChangeNotification {
                    from,
                    head,
                    movement: movement.clone(),
                });
            }
        }

        // A full channel already holds a wake, which says the same thing;
        // a closed one is a subscriber mid-drop, about to deregister.
        let _ = self.wake.try_send(());
    }
}

/// Locks `mutex`, taking the guard back from a poisoned lock.
///
/// Nothing here holds a lock across an await or leaves half-updated data
/// behind, so a panic elsewhere cannot have left anything inconsistent to
/// be protected from.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use wire::{
        Msg,
        msg::{SetNamespace, SetNamespaceKey, Value},
        subkey::Subkey,
    };

    use super::*;

    fn digest(byte: u8) -> EnvelopeDigest {
        EnvelopeDigest::from_bytes([byte; 32])
    }

    fn key(k: &str) -> NamespaceKey {
        NamespaceKey::try_new(k).unwrap()
    }

    fn keys(segments: &[&str]) -> SubkeyPath {
        SubkeyPath::try_new(
            segments
                .iter()
                .map(|k| Subkey::Key((*k).to_string()))
                .collect(),
        )
        .unwrap()
    }

    /// The movement a whole-namespace write to `k` produces.
    fn wrote_namespace(k: &str) -> Movement {
        let mut movement = Movement::default();
        movement.changes.record(&Msg::SetNamespace(SetNamespace {
            prev: digest(0),
            key: key(k),
            namespace: wire::msg::Namespace {
                value: Value::Int(1),
            },
        }));
        movement
    }

    /// The movement a write to `path` in `k` produces.
    fn wrote_path(k: &str, path: SubkeyPath) -> Movement {
        let mut movement = Movement::default();
        movement
            .changes
            .record(&Msg::SetNamespaceKey(SetNamespaceKey {
                prev: digest(0),
                key: key(k),
                path,
                value: Some(Value::Int(1)),
            }));
        movement
    }

    /// The movement a reorg past the envelope at `byte` produces.
    fn orphaned(byte: u8) -> Movement {
        Movement {
            orphaned: [digest(byte)].into(),
            ..Movement::default()
        }
    }

    #[tokio::test]
    async fn a_namespace_subscription_is_woken_by_a_change_under_it() {
        let subscriptions = Subscriptions::default();
        let mut subscription = subscriptions.register(ChangeFilter::namespace(key("a")), digest(1));

        subscriptions.publish(digest(1), digest(2), &wrote_path("a", keys(&["host"])));

        let notification = subscription.next().await.unwrap();
        assert_eq!(notification.from, digest(1));
        assert_eq!(notification.head, digest(2));
        assert!(notification.movement.changes.touches(&key("a"), None));
    }

    /// The point of path selectors: a write elsewhere in the same namespace
    /// is not this subscriber's business.
    #[tokio::test]
    async fn a_path_subscription_sleeps_through_a_sibling_write() {
        let subscriptions = Subscriptions::default();
        let mut subscription =
            subscriptions.register(ChangeFilter::path(key("a"), keys(&["host"])), digest(1));

        subscriptions.publish(digest(1), digest(2), &wrote_path("a", keys(&["port"])));

        // Nothing pending, and nothing to wake it: dropping the publisher
        // is what ends the wait.
        drop(subscriptions);
        assert!(subscription.next().await.is_none());
    }

    /// A subscriber only ever hears about the head moving, so an empty
    /// change set still wakes it.
    #[tokio::test]
    async fn a_head_subscription_is_woken_by_any_movement() {
        let subscriptions = Subscriptions::default();
        let mut subscription = subscriptions.register(ChangeFilter::head(), digest(1));

        subscriptions.publish(digest(1), digest(2), &Movement::default());

        assert_eq!(subscription.next().await.unwrap().head, digest(2));
    }

    #[tokio::test]
    async fn a_filter_reports_which_of_its_selectors_fired() {
        let subscriptions = Subscriptions::default();
        let filter = ChangeFilter::namespace(key("a")).and_namespace(key("b"));
        let mut subscription = subscriptions.register(filter, digest(1));

        subscriptions.publish(digest(1), digest(2), &wrote_namespace("b"));

        let notification = subscription.next().await.unwrap();
        let matched: Vec<_> = subscription
            .filter()
            .matched(&notification.movement)
            .collect();
        assert_eq!(matched, [&ChangeSelector::Namespace(key("b"))]);
    }

    /// A subscriber that was not reading finds the movements merged into
    /// one notification spanning all of them, rather than a queue to catch
    /// up through.
    #[tokio::test]
    async fn movements_merge_while_a_subscriber_is_not_reading() {
        let subscriptions = Subscriptions::default();
        let mut subscription = subscriptions.register(ChangeFilter::head(), digest(1));

        subscriptions.publish(digest(1), digest(2), &wrote_namespace("a"));
        subscriptions.publish(digest(2), digest(3), &wrote_namespace("b"));
        subscriptions.publish(digest(3), digest(4), &wrote_namespace("c"));

        let notification = subscription.next().await.unwrap();
        // Spanning every movement, not just the last.
        assert_eq!(notification.from, digest(1));
        assert_eq!(notification.head, digest(4));
        assert!(notification.movement.changes.touches(&key("a"), None));
        assert!(notification.movement.changes.touches(&key("b"), None));
        assert!(notification.movement.changes.touches(&key("c"), None));

        // Drained: what came before is not delivered twice.
        drop(subscriptions);
        assert!(subscription.next().await.is_none());
    }

    #[tokio::test]
    async fn an_orphan_subscription_is_woken_when_its_envelope_leaves() {
        let subscriptions = Subscriptions::default();
        let mut subscription = subscriptions.register(ChangeFilter::orphaned(digest(7)), digest(1));

        subscriptions.publish(digest(1), digest(2), &orphaned(7));

        let notification = subscription.next().await.unwrap();
        assert!(notification.movement.orphaned.contains(&digest(7)));
    }

    /// Another envelope being orphaned is not this subscriber's business.
    #[tokio::test]
    async fn an_orphan_subscription_sleeps_through_another_envelope_leaving() {
        let subscriptions = Subscriptions::default();
        let mut subscription = subscriptions.register(ChangeFilter::orphaned(digest(7)), digest(1));

        subscriptions.publish(digest(1), digest(2), &orphaned(8));

        drop(subscriptions);
        assert!(subscription.next().await.is_none());
    }

    /// Nor is a change that orphans nothing, however much state it moved.
    #[tokio::test]
    async fn an_orphan_subscription_sleeps_through_an_ordinary_write() {
        let subscriptions = Subscriptions::default();
        let mut subscription = subscriptions.register(ChangeFilter::orphaned(digest(7)), digest(1));

        subscriptions.publish(digest(1), digest(2), &wrote_namespace("a"));

        drop(subscriptions);
        assert!(subscription.next().await.is_none());
    }

    /// Orphans accumulate across a window the subscriber slept through,
    /// alongside the changes.
    #[tokio::test]
    async fn orphans_merge_while_a_subscriber_is_not_reading() {
        let subscriptions = Subscriptions::default();
        let mut subscription = subscriptions.register(ChangeFilter::head(), digest(1));

        subscriptions.publish(digest(1), digest(2), &orphaned(7));
        subscriptions.publish(digest(2), digest(3), &wrote_namespace("a"));
        subscriptions.publish(digest(3), digest(4), &orphaned(8));

        let notification = subscription.next().await.unwrap();
        assert_eq!(
            notification.movement.orphaned,
            [digest(7), digest(8)].into()
        );
        assert!(notification.movement.changes.touches(&key("a"), None));
    }

    #[tokio::test]
    async fn dropping_a_subscription_deregisters_it() {
        let subscriptions = Subscriptions::default();
        let one = subscriptions.register(ChangeFilter::head(), digest(1));
        let two = subscriptions.register(ChangeFilter::namespace(key("a")), digest(1));
        assert_eq!(subscriptions.count(), 2);

        drop(one);
        assert_eq!(subscriptions.count(), 1);

        drop(two);
        assert_eq!(subscriptions.count(), 0);
    }

    /// Deregistering must not depend on the publisher still being there:
    /// the core can go away first.
    #[tokio::test]
    async fn a_subscription_outliving_the_publisher_drops_cleanly() {
        let subscriptions = Subscriptions::default();
        let subscription = subscriptions.register(ChangeFilter::head(), digest(1));

        drop(subscriptions);
        drop(subscription);
    }

    /// What was already pending when the publisher went away is still
    /// delivered; only then does the subscription end.
    #[tokio::test]
    async fn a_pending_notification_survives_the_publisher() {
        let subscriptions = Subscriptions::default();
        let mut subscription = subscriptions.register(ChangeFilter::head(), digest(1));

        subscriptions.publish(digest(1), digest(2), &wrote_namespace("a"));
        drop(subscriptions);

        assert_eq!(subscription.next().await.unwrap().head, digest(2));
        assert!(subscription.next().await.is_none());
    }
}
