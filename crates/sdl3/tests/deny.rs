//! Its own test binary: denying display connections is process-wide, and
//! would make any other test that opens a window fail.

/// A denied process cannot bring the display up, and can once allowed
/// again; refusing while connected fails rather than leaving it connected.
#[test]
fn denied_display_connections_are_refused_until_allowed() {
    assert!(sdl3::video::deny_connections(true));
    assert!(!sdl3::video::init_video());
    assert!(!sdl3::video::video_up());
    assert!(sdl3::video::deny_connections(false));
    if !sdl3::video::init_video() {
        eprintln!("skipped the connected half: no SDL3 display here");
        return;
    }
    assert!(!sdl3::video::deny_connections(true), "a connection is open");
    assert!(sdl3::video::init_video());
    sdl3::video::quit_video();
    assert!(sdl3::video::deny_connections(true));
    assert!(sdl3::video::deny_connections(false));
}
