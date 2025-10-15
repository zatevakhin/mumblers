use mumblers::channels::{Channel, Channels};
use mumblers::state::ClientState;

#[test]
fn test_channel_creation() {
    let mut channels = Channels::new();
    assert!(channels.get(0).is_some());

    let channel = Channel::new(1);
    channels.insert(channel);
    assert!(channels.get(1).is_some());
}

#[test]
fn test_channel_update() {
    let mut channels = Channels::new();
    let message = mumblers::proto::mumble::ChannelState {
        channel_id: Some(1),
        name: Some("Test Channel".to_string()),
        parent: Some(0),
        ..Default::default()
    };
    channels.update(&message);
    let channel = channels.get(1).unwrap();
    assert_eq!(channel.name, Some("Test Channel".to_string()));
    assert_eq!(channel.parent, Some(0));
}

#[test]
fn test_get_childs() {
    let mut channels = Channels::new();
    let child1 = Channel {
        channel_id: 1,
        name: Some("Child1".to_string()),
        parent: Some(0),
        ..Default::default()
    };
    let child2 = Channel {
        channel_id: 2,
        name: Some("Child2".to_string()),
        parent: Some(0),
        ..Default::default()
    };
    channels.insert(child1);
    channels.insert(child2);

    let childs = channels.get_childs(0);
    assert_eq!(childs.len(), 2);
}

#[test]
fn test_get_descendants() {
    let mut channels = Channels::new();
    let child = Channel {
        channel_id: 1,
        name: Some("Child".to_string()),
        parent: Some(0),
        ..Default::default()
    };
    let grandchild = Channel {
        channel_id: 2,
        name: Some("Grandchild".to_string()),
        parent: Some(1),
        ..Default::default()
    };
    channels.insert(child);
    channels.insert(grandchild);

    let descendants = channels.get_descendants(0);
    assert_eq!(descendants.len(), 2);
}

#[test]
fn test_get_tree() {
    let mut channels = Channels::new();
    let child = Channel {
        channel_id: 1,
        name: Some("Child".to_string()),
        parent: Some(0),
        ..Default::default()
    };
    channels.insert(child);

    let tree = channels.get_tree(1);
    assert_eq!(tree.len(), 2); // Root and child
    assert_eq!(tree[0].channel_id, 0);
    assert_eq!(tree[1].channel_id, 1);
}

#[test]
fn test_find_by_name() {
    let mut channels = Channels::new();
    let channel = Channel {
        channel_id: 1,
        name: Some("Test Channel".to_string()),
        parent: Some(0),
        ..Default::default()
    };
    channels.insert(channel);

    let found = channels.find_by_name("Test Channel");
    assert!(found.is_some());
    assert_eq!(found.unwrap().channel_id, 1);
}

#[test]
fn test_find_by_tree() {
    let mut channels = Channels::new();
    let child = Channel {
        channel_id: 1,
        name: Some("Child".to_string()),
        parent: Some(0),
        ..Default::default()
    };
    channels.insert(child);

    let found = channels.find_by_tree(vec!["Child".to_string()]);
    assert!(found.is_some());
    assert_eq!(found.unwrap().channel_id, 1);
}

#[test]
fn test_move_user_to_channel() {
    let channels = Channels::new();
    let user_state = channels.move_user_to_channel(1, 2);
    assert_eq!(user_state.session, Some(1));
    assert_eq!(user_state.channel_id, Some(2));
}

#[test]
fn test_create_channel() {
    let channels = Channels::new();
    let channel_state = channels.create_channel(0, "New Channel".to_string());
    assert_eq!(channel_state.parent, Some(0));
    assert_eq!(channel_state.name, Some("New Channel".to_string()));
}

#[test]
fn test_remove_channel() {
    let channels = Channels::new();
    let channel_remove = channels.remove_channel(1);
    assert_eq!(channel_remove.channel_id, 1);
}

#[test]
fn test_rename_channel() {
    let channels = Channels::new();
    let channel_state = channels.rename_channel(1, "Renamed".to_string());
    assert_eq!(channel_state.channel_id, Some(1));
    assert_eq!(channel_state.name, Some("Renamed".to_string()));
}

#[test]
fn test_move_channel() {
    let channels = Channels::new();
    let channel_state = channels.move_channel(1, 2);
    assert_eq!(channel_state.channel_id, Some(1));
    assert_eq!(channel_state.parent, Some(2));
}

#[test]
fn test_send_channel_message() {
    let channels = Channels::new();
    let text_message = channels.send_channel_message(1, "Hello".to_string());
    assert_eq!(text_message.channel_id, vec![1]);
    assert_eq!(text_message.message, "Hello".to_string());
}

#[test]
fn test_get_users_in_channel() {
    let mut state = ClientState::default();
    state.user_channels.insert(1, 0);
    state.user_channels.insert(2, 1);
    state.user_channels.insert(3, 0);

    let users_in_0 = state.get_users_in_channel(0);
    assert_eq!(users_in_0.len(), 2);
    assert!(users_in_0.contains(&1));
    assert!(users_in_0.contains(&3));

    let users_in_1 = state.get_users_in_channel(1);
    assert_eq!(users_in_1.len(), 1);
    assert!(users_in_1.contains(&2));
}

#[test]
fn test_channel_error() {
    let err = mumblers::MumbleError::Channel("test error".to_string());
    assert_eq!(err.to_string(), "channel error: test error");
}

#[test]
fn test_channel_hierarchy_edge_cases() {
    let channels = Channels::new();

    // Test root channel
    assert!(channels.get(0).is_some());

    // Test non-existent channel
    assert!(channels.get(999).is_none());

    // Test find non-existent name
    assert!(channels.find_by_name("NonExistent").is_none());

    // Test find_by_tree with invalid path
    assert!(channels.find_by_tree(vec!["Invalid".to_string()]).is_none());
}

#[test]
fn test_channel_operations_edge_cases() {
    let channels = Channels::new();

    // Test create channel with empty name
    let channel_state = channels.create_channel(0, "".to_string());
    assert_eq!(channel_state.name, Some("".to_string()));

    // Test move user to non-existent channel
    let user_state = channels.move_user_to_channel(1, 999);
    assert_eq!(user_state.channel_id, Some(999));

    // Test send message to non-existent channel
    let text_message = channels.send_channel_message(999, "test".to_string());
    assert_eq!(text_message.channel_id, vec![999]);
}
