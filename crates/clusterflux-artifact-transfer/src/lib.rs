#![forbid(unsafe_code)]

mod endpoint;
mod identity;
mod metrics;
mod path_policy;
mod pool;
mod protocol;
mod provider;
mod receiver;

pub use endpoint::{ClusterfluxEndpoint, EndpointBindConfig};
pub use identity::{IrohIdentityScope, PersistentIrohIdentity};
pub use metrics::{ArtifactDataPlaneMetrics, ArtifactDataPlaneMetricsSnapshot};
pub use path_policy::{PathPolicy, PathPolicyError, PathPolicyMetrics};
pub use protocol::{
    read_request, read_response, write_request, write_response, GetArtifactRequest,
    GetArtifactResponse, ProtocolError,
};
pub use provider::{ArtifactProviderRegistry, ArtifactProviderServer, ProviderError};
pub use receiver::{
    ArtifactReceiver, CompletedTransfer, PartialStoreConfig, ReceiveError, TransferProgress,
};

pub use clusterflux_core::{
    ArtifactRelayPolicy, ArtifactTransferErrorCode, ArtifactTransferLease, AuthorizedPeerEndpoint,
    ClusterfluxPathKind, IrohEndpointAdvertisement, IrohRelayConfiguration,
};
