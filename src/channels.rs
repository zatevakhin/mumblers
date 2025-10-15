use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::proto::mumble::{ChannelState, TextMessage, UserState};

/// Represents a Mumble channel with its properties.
#[derive(Debug, Clone, PartialEq)]
pub struct Channel {
    pub channel_id: u32,
    pub name: Option<String>,
    pub parent: Option<u32>,
    pub description: Option<String>,
    pub position: Option<i32>,
    pub max_users: Option<u32>,
    pub links: Vec<u32>,
}

impl Channel {
    pub fn new(channel_id: u32) -> Self {
        Self {
            channel_id,
            name: None,
            parent: None,
            description: None,
            position: None,
            max_users: None,
            links: Vec::new(),
        }
    }

    pub fn update_from_message(&mut self, message: &ChannelState) {
        if let Some(name) = &message.name {
            self.name = Some(name.clone());
        }
        if let Some(parent) = message.parent {
            self.parent = Some(parent);
        }
        if let Some(description) = &message.description {
            self.description = Some(description.clone());
        }
        if let Some(position) = message.position {
            self.position = Some(position);
        }
        if let Some(max_users) = message.max_users {
            self.max_users = Some(max_users);
        }
        self.links = message.links.clone();
    }

    pub fn get_parent(&self) -> Option<u32> {
        self.parent
    }

    pub fn set_parent(&mut self, parent: u32) {
        self.parent = Some(parent);
    }
}

impl Default for Channel {
    fn default() -> Self {
        Self::new(0) // Root channel
    }
}

/// Manages all channels and their hierarchy.
#[derive(Debug)]
pub struct Channels {
    channels: HashMap<u32, Channel>,
}

impl Channels {
    pub fn new() -> Self {
        let mut channels = HashMap::new();
        channels.insert(0, Channel::new(0)); // Root channel
        Self { channels }
    }

    pub fn insert(&mut self, channel: Channel) {
        self.channels.insert(channel.channel_id, channel);
    }

    pub fn get(&self, channel_id: u32) -> Option<&Channel> {
        self.channels.get(&channel_id)
    }

    pub fn get_mut(&mut self, channel_id: u32) -> Option<&mut Channel> {
        self.channels.get_mut(&channel_id)
    }

    pub fn remove(&mut self, channel_id: u32) -> Option<Channel> {
        self.channels.remove(&channel_id)
    }

    pub fn update(&mut self, message: &ChannelState) {
        let channel_id = message.channel_id.unwrap_or(0);
        if let Some(channel) = self.channels.get_mut(&channel_id) {
            channel.update_from_message(message);
        } else {
            let mut channel = Channel::new(channel_id);
            channel.update_from_message(message);
            self.insert(channel);
        }
    }

    pub fn get_childs(&self, channel_id: u32) -> Vec<&Channel> {
        self.channels
            .values()
            .filter(|c| c.parent == Some(channel_id))
            .collect()
    }

    pub fn find_by_name(&self, name: &str) -> Option<&Channel> {
        self.channels
            .values()
            .find(|c| c.name.as_deref() == Some(name))
    }

    pub fn get_descendants(&self, channel_id: u32) -> Vec<&Channel> {
        let mut descendants = Vec::new();
        let mut to_visit = self.get_childs(channel_id);
        while let Some(channel) = to_visit.pop() {
            descendants.push(channel);
            to_visit.extend(self.get_childs(channel.channel_id));
        }
        descendants
    }

    pub fn get_tree(&self, channel_id: u32) -> Vec<&Channel> {
        let mut tree = Vec::new();
        let mut current_id = channel_id;
        while let Some(channel) = self.get(current_id) {
            tree.push(channel);
            if let Some(parent) = channel.parent {
                current_id = parent;
            } else {
                break;
            }
        }
        tree.reverse();
        tree
    }

    pub fn find_by_tree(&self, path: Vec<String>) -> Option<&Channel> {
        let mut current = self.get(0)?; // Start from root
        for name in path {
            let found = self
                .get_childs(current.channel_id)
                .into_iter()
                .find(|c| c.name.as_deref() == Some(&name));
            if let Some(child) = found {
                current = child;
            } else {
                return None;
            }
        }
        Some(current)
    }

    pub fn iter(&self) -> std::collections::hash_map::Iter<'_, u32, Channel> {
        self.channels.iter()
    }

    pub fn move_user_to_channel(&self, session_id: u32, channel_id: u32) -> UserState {
        UserState {
            session: Some(session_id),
            channel_id: Some(channel_id),
            ..Default::default()
        }
    }

    pub fn create_channel(&self, parent_id: u32, name: String) -> ChannelState {
        ChannelState {
            channel_id: None, // Server assigns
            parent: Some(parent_id),
            name: Some(name),
            ..Default::default()
        }
    }

    pub fn remove_channel(&self, channel_id: u32) -> crate::proto::mumble::ChannelRemove {
        crate::proto::mumble::ChannelRemove { channel_id }
    }

    pub fn rename_channel(&self, channel_id: u32, name: String) -> ChannelState {
        ChannelState {
            channel_id: Some(channel_id),
            name: Some(name),
            ..Default::default()
        }
    }

    pub fn move_channel(&self, channel_id: u32, new_parent: u32) -> ChannelState {
        ChannelState {
            channel_id: Some(channel_id),
            parent: Some(new_parent),
            ..Default::default()
        }
    }

    pub fn link_channel(&self, channel_id: u32, target_id: u32) -> ChannelState {
        ChannelState {
            channel_id: Some(channel_id),
            links: vec![target_id],
            ..Default::default()
        }
    }

    pub fn unlink_channel(&self, channel_id: u32, _target_id: u32) -> ChannelState {
        ChannelState {
            channel_id: Some(channel_id),
            links: vec![], // To remove, set empty or specific logic
            ..Default::default()
        }
    }

    pub fn send_channel_message(&self, channel_id: u32, message: String) -> TextMessage {
        TextMessage {
            channel_id: vec![channel_id],
            message,
            ..Default::default()
        }
    }
}

impl Default for Channels {
    fn default() -> Self {
        Self::new()
    }
}

pub type SharedChannels = Arc<Mutex<Channels>>;

pub fn new_shared_channels() -> SharedChannels {
    Arc::new(Mutex::new(Channels::new()))
}
