use super::*;
use std::{sync::Barrier, thread};

#[test]
fn receiver_capacity_rejects_invalid_limits_and_holds_unique_owned_permits() {
    for active in [0, 5, usize::MAX] {
        assert!(matches!(
            ReceiverFactory::new(active),
            Err(ReceiverError::InvalidConfiguration)
        ));
    }
    let factory = ReceiverFactory::new(1).unwrap();
    let permit = factory.reserve().unwrap();
    assert_eq!(factory.active(), 1);
    assert!(matches!(factory.reserve(), Err(ReceiverError::Busy)));
    // Moving an owned permit keeps capacity reserved independently of the
    // source variable/factory handle, as the final view-owning lease requires.
    let moved = Some(permit);
    let other = factory.clone();
    drop(factory);
    assert!(matches!(other.reserve(), Err(ReceiverError::Busy)));
    drop(moved);
    assert_eq!(other.active(), 0);
    assert!(other.reserve().is_ok());
}

#[test]
fn receiver_capacity_is_bounded_under_simultaneous_reservations() {
    let factory = ReceiverFactory::new(4).unwrap();
    let arrived = Arc::new(Barrier::new(17));
    let release = Arc::new(Barrier::new(17));
    let mut threads = Vec::new();
    for _ in 0..16 {
        let factory = factory.clone();
        let arrived = arrived.clone();
        let release = release.clone();
        threads.push(thread::spawn(move || {
            let permit = factory.reserve().ok();
            let reserved = permit.is_some();
            arrived.wait();
            release.wait();
            drop(permit);
            reserved
        }));
    }
    arrived.wait();
    let active = factory.active();
    release.wait();
    let successes = threads
        .into_iter()
        .map(|thread| usize::from(thread.join().unwrap()))
        .sum::<usize>();
    assert_eq!(active, 4);
    assert_eq!(successes, 4);
    assert_eq!(factory.active(), 0);
}
