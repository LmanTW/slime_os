#![cfg_attr(not(test), no_std)]

#[cfg(feature = "component-runtime")]
pub mod block_io;
#[cfg(feature = "component-runtime")]
pub mod console_line;
pub mod data_volume;
#[cfg(feature = "component-runtime")]
pub mod fabric_boot;
#[cfg(feature = "component-runtime")]
pub mod fabric_matrix;
#[cfg(feature = "component-runtime")]
pub mod fabric_self_view;
#[cfg(feature = "component-runtime")]
pub mod fabric_visibility;
pub mod frame_store;
#[cfg(feature = "component-runtime")]
pub mod generation_composition;
pub mod hmac_drbg;
pub mod http;
pub mod link_frames;
#[cfg(feature = "component-runtime")]
pub mod network_io;
#[cfg(feature = "component-runtime")]
pub mod private_memory_adaptive;
#[cfg(feature = "component-runtime")]
pub mod private_memory_capacity;
#[cfg(feature = "component-runtime")]
pub mod private_memory_matrix;
pub mod ros_cdr;
pub mod servo_failsafe;
#[cfg(feature = "component-runtime")]
pub mod shared_buffer_probe;
pub mod tick_clock;
pub mod uart16550;
pub mod virtio_mmio;
pub mod zenoh_link;
pub mod zenoh_link_limits_v3;
#[cfg(test)]
mod zenoh_links;
pub mod zenoh_node;
pub mod zenoh_profile0;
#[cfg(test)]
mod zenoh_rmw;
#[cfg(test)]
mod zenoh_rmw_data;
#[cfg(test)]
mod zenoh_rmw_data_link;
pub mod zenoh_rmw_graph;
pub mod zenoh_rmw_link;
pub mod zenoh_service;
#[cfg(feature = "component-runtime")]
pub mod zenoh_service_client;
#[cfg(test)]
mod zenoh_service_link;
pub mod zenoh_service_server;
pub mod zenoh_service_server_roster;
#[cfg(test)]
mod zenoh_service_stack;
#[cfg(test)]
mod zenoh_stock;
#[cfg(test)]
mod zenoh_subscribers;
#[cfg(test)]
mod zenoh_undeclare;
