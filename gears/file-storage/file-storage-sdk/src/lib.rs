//! File Storage SDK
//!
//! Public API surface of the `file-storage` gear (control plane). Operations run
//! in-process through [`FileStorageClientV1`] and return models / signed URLs; the
//! SDK never transfers file bytes itself.
//!
//! - [`FileStorageClientV1`] — the inter-gear client trait (resolved from `ClientHub`)
//! - model types ([`models`])
//! - GTS resource-type constants ([`gts`])
//! - [`FileStorageError`] — the canonical error envelope
//!
//! ## Usage
//!
//! ```ignore
//! use file_storage_sdk::FileStorageClientV1;
//!
//! let client = hub.get::<dyn FileStorageClientV1>()?;
//! ```

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

pub mod api;
pub mod gts;
pub mod models;

pub use api::FileStorageClientV1;
pub use gts::FILE_TYPE_RESOURCE;
pub use models::{
    AgeRetention, BindState, ByteRange, CompletedMultipartUpload, CreateFileOutcome,
    CustomMetadataEntry, CustomMetadataPatch, DownloadTicket, EffectivePolicy, File, FileFetch,
    FileId, FileRecord, FileVersion, InactivityRetention, MetadataLimits, MetadataRetention,
    MimeSizeOverride, MissingPart, MultipartCompleteOutcome, MultipartIntent, MultipartPartPlan,
    MultipartPlan, MultipartStatus, MultipartUploadState, NewFile, OwnerFilter, OwnerKind, Policy,
    PolicyBody, PolicyScope, ReceivedPart, RetentionRule, RetentionRuleBody, RetentionScope,
    SizeLimits, Storage, StorageCapabilities, UploadTicket, VersionId, VersionRecord,
    VersionStatus,
};

// Cursor-pagination envelope for the `list_*` methods, re-exported so callers need
// no direct `toolkit-odata` dependency.
pub use toolkit_odata::Page;

pub use toolkit_canonical_errors::CanonicalError as FileStorageError;
pub use toolkit_canonical_errors::{self, CanonicalError, Problem};
