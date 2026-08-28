use clusterflux_core::{
    ArtifactId, ArtifactTransferErrorCode, Digest, ARTIFACT_TRANSFER_PROTOCOL_VERSION,
    MAX_TRANSFER_ERROR_MESSAGE_BYTES, MAX_TRANSFER_ID_BYTES,
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_PROTOCOL_HEADER_BYTES: usize = 8 * 1024;
const MAX_ARTIFACT_ID_BYTES: usize = 255;
const SHA256_DIGEST_BYTES: usize = 71;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetArtifactRequest {
    pub protocol_version: u16,
    pub transfer_id: String,
    pub transfer_secret: [u8; 32],
    pub artifact: ArtifactId,
    pub expected_digest: Digest,
    pub expected_size: u64,
    pub offset: u64,
}

impl GetArtifactRequest {
    pub fn new(
        transfer_id: String,
        transfer_secret: [u8; 32],
        artifact: ArtifactId,
        expected_digest: Digest,
        expected_size: u64,
        offset: u64,
    ) -> Self {
        Self {
            protocol_version: ARTIFACT_TRANSFER_PROTOCOL_VERSION,
            transfer_id,
            transfer_secret,
            artifact,
            expected_digest,
            expected_size,
            offset,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GetArtifactResponse {
    Accepted {
        artifact: ArtifactId,
        digest: Digest,
        total_size: u64,
        offset: u64,
        remaining_size: u64,
    },
    Rejected {
        code: ArtifactTransferErrorCode,
        message: String,
    },
}

pub async fn write_request<W>(
    writer: &mut W,
    request: &GetArtifactRequest,
) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    validate_request(request)?;
    let mut encoded = Vec::with_capacity(512);
    encoded.extend_from_slice(&request.protocol_version.to_be_bytes());
    encode_string(
        &mut encoded,
        &request.transfer_id,
        MAX_TRANSFER_ID_BYTES,
        "transfer ID",
    )?;
    encoded.extend_from_slice(&request.transfer_secret);
    encode_string(
        &mut encoded,
        request.artifact.as_str(),
        MAX_ARTIFACT_ID_BYTES,
        "artifact ID",
    )?;
    encode_string(
        &mut encoded,
        request.expected_digest.as_str(),
        SHA256_DIGEST_BYTES,
        "digest",
    )?;
    encoded.extend_from_slice(&request.expected_size.to_be_bytes());
    encoded.extend_from_slice(&request.offset.to_be_bytes());
    write_frame(writer, &encoded).await
}

pub async fn read_request<R>(reader: &mut R) -> Result<GetArtifactRequest, ProtocolError>
where
    R: AsyncRead + Unpin,
{
    let encoded = read_frame(reader).await?;
    let mut decoder = Decoder::new(&encoded);
    let protocol_version = decoder.u16()?;
    let transfer_id = decoder.string(MAX_TRANSFER_ID_BYTES, "transfer ID")?;
    let transfer_secret = decoder.array_32()?;
    let artifact = ArtifactId::try_new(decoder.string(MAX_ARTIFACT_ID_BYTES, "artifact ID")?)
        .map_err(|error| ProtocolError::InvalidField(error.to_string()))?;
    let expected_digest = decode_digest(decoder.string(SHA256_DIGEST_BYTES, "digest")?)?;
    let expected_size = decoder.u64()?;
    let offset = decoder.u64()?;
    decoder.finish()?;
    let request = GetArtifactRequest {
        protocol_version,
        transfer_id,
        transfer_secret,
        artifact,
        expected_digest,
        expected_size,
        offset,
    };
    validate_request(&request)?;
    Ok(request)
}

pub async fn write_response<W>(
    writer: &mut W,
    response: &GetArtifactResponse,
) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    let mut encoded = Vec::with_capacity(512);
    match response {
        GetArtifactResponse::Accepted {
            artifact,
            digest,
            total_size,
            offset,
            remaining_size,
        } => {
            if !digest.is_valid_sha256()
                || *offset > *total_size
                || *remaining_size != total_size.saturating_sub(*offset)
            {
                return Err(ProtocolError::InvalidField(
                    "accepted response has inconsistent size or digest fields".to_owned(),
                ));
            }
            encoded.push(0);
            encode_string(
                &mut encoded,
                artifact.as_str(),
                MAX_ARTIFACT_ID_BYTES,
                "artifact ID",
            )?;
            encode_string(&mut encoded, digest.as_str(), SHA256_DIGEST_BYTES, "digest")?;
            encoded.extend_from_slice(&total_size.to_be_bytes());
            encoded.extend_from_slice(&offset.to_be_bytes());
            encoded.extend_from_slice(&remaining_size.to_be_bytes());
        }
        GetArtifactResponse::Rejected { code, message } => {
            encoded.push(1);
            encoded.push(error_code_to_wire(*code));
            encode_string(
                &mut encoded,
                message,
                MAX_TRANSFER_ERROR_MESSAGE_BYTES,
                "rejection message",
            )?;
        }
    }
    write_frame(writer, &encoded).await
}

pub async fn read_response<R>(reader: &mut R) -> Result<GetArtifactResponse, ProtocolError>
where
    R: AsyncRead + Unpin,
{
    let encoded = read_frame(reader).await?;
    let mut decoder = Decoder::new(&encoded);
    let response = match decoder.u8()? {
        0 => {
            let artifact =
                ArtifactId::try_new(decoder.string(MAX_ARTIFACT_ID_BYTES, "artifact ID")?)
                    .map_err(|error| ProtocolError::InvalidField(error.to_string()))?;
            let digest = decode_digest(decoder.string(SHA256_DIGEST_BYTES, "digest")?)?;
            let total_size = decoder.u64()?;
            let offset = decoder.u64()?;
            let remaining_size = decoder.u64()?;
            if offset > total_size || remaining_size != total_size.saturating_sub(offset) {
                return Err(ProtocolError::InvalidField(
                    "accepted response has inconsistent sizes".to_owned(),
                ));
            }
            GetArtifactResponse::Accepted {
                artifact,
                digest,
                total_size,
                offset,
                remaining_size,
            }
        }
        1 => GetArtifactResponse::Rejected {
            code: error_code_from_wire(decoder.u8()?)?,
            message: decoder.string(MAX_TRANSFER_ERROR_MESSAGE_BYTES, "rejection message")?,
        },
        tag => return Err(ProtocolError::UnknownResponseTag(tag)),
    };
    decoder.finish()?;
    Ok(response)
}

fn validate_request(request: &GetArtifactRequest) -> Result<(), ProtocolError> {
    if request.protocol_version != ARTIFACT_TRANSFER_PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(request.protocol_version));
    }
    if request.transfer_id.is_empty() || request.transfer_id.len() > MAX_TRANSFER_ID_BYTES {
        return Err(ProtocolError::InvalidField(
            "transfer ID is empty or too large".to_owned(),
        ));
    }
    if !request.expected_digest.is_valid_sha256() {
        return Err(ProtocolError::InvalidField(
            "expected digest is not SHA-256".to_owned(),
        ));
    }
    if request.offset > request.expected_size {
        return Err(ProtocolError::InvalidField(
            "requested offset exceeds expected size".to_owned(),
        ));
    }
    Ok(())
}

async fn write_frame<W>(writer: &mut W, encoded: &[u8]) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    if encoded.is_empty() || encoded.len() > MAX_PROTOCOL_HEADER_BYTES {
        return Err(ProtocolError::HeaderTooLarge);
    }
    writer.write_u32(encoded.len() as u32).await?;
    writer.write_all(encoded).await?;
    Ok(())
}

async fn read_frame<R>(reader: &mut R) -> Result<Vec<u8>, ProtocolError>
where
    R: AsyncRead + Unpin,
{
    let length = reader.read_u32().await? as usize;
    if length == 0 || length > MAX_PROTOCOL_HEADER_BYTES {
        return Err(ProtocolError::HeaderTooLarge);
    }
    let mut encoded = vec![0; length];
    reader.read_exact(&mut encoded).await?;
    Ok(encoded)
}

fn encode_string(
    encoded: &mut Vec<u8>,
    value: &str,
    maximum: usize,
    field: &'static str,
) -> Result<(), ProtocolError> {
    if value.is_empty() || value.len() > maximum || value.len() > u16::MAX as usize {
        return Err(ProtocolError::InvalidField(format!(
            "{field} is empty or too large"
        )));
    }
    encoded.extend_from_slice(&(value.len() as u16).to_be_bytes());
    encoded.extend_from_slice(value.as_bytes());
    Ok(())
}

fn decode_digest(value: String) -> Result<Digest, ProtocolError> {
    let Some(value) = value.strip_prefix("sha256:") else {
        return Err(ProtocolError::InvalidField(
            "digest is not SHA-256".to_owned(),
        ));
    };
    Digest::from_sha256_hex(value).map_err(ProtocolError::InvalidField)
}

struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ProtocolError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ProtocolError::TruncatedHeader)?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or(ProtocolError::TruncatedHeader)?;
        self.offset = end;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ProtocolError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("two bytes"),
        ))
    }

    fn u64(&mut self) -> Result<u64, ProtocolError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("eight bytes"),
        ))
    }

    fn array_32(&mut self) -> Result<[u8; 32], ProtocolError> {
        Ok(self.take(32)?.try_into().expect("32 bytes"))
    }

    fn string(&mut self, maximum: usize, field: &'static str) -> Result<String, ProtocolError> {
        let length = self.u16()? as usize;
        if length == 0 || length > maximum {
            return Err(ProtocolError::InvalidField(format!(
                "{field} is empty or too large"
            )));
        }
        let value = std::str::from_utf8(self.take(length)?)
            .map_err(|_| ProtocolError::InvalidField(format!("{field} is not UTF-8")))?;
        Ok(value.to_owned())
    }

    fn finish(self) -> Result<(), ProtocolError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(ProtocolError::TrailingHeaderBytes)
        }
    }
}

fn error_code_to_wire(code: ArtifactTransferErrorCode) -> u8 {
    match code {
        ArtifactTransferErrorCode::NoArtifactLocation => 0,
        ArtifactTransferErrorCode::SourceNodeOffline => 1,
        ArtifactTransferErrorCode::DestinationNodeOffline => 2,
        ArtifactTransferErrorCode::EndpointAdvertisementMissing => 3,
        ArtifactTransferErrorCode::RelayAssistUnavailable => 4,
        ArtifactTransferErrorCode::DirectPathTimeout => 5,
        ArtifactTransferErrorCode::RelayPathForbidden => 6,
        ArtifactTransferErrorCode::ConnectionFailed => 7,
        ArtifactTransferErrorCode::PeerIdentityMismatch => 8,
        ArtifactTransferErrorCode::TransferLeaseRejected => 9,
        ArtifactTransferErrorCode::TransferLeaseExpired => 10,
        ArtifactTransferErrorCode::ArtifactMissingAtSource => 11,
        ArtifactTransferErrorCode::RangeInvalid => 12,
        ArtifactTransferErrorCode::DestinationDiskFull => 13,
        ArtifactTransferErrorCode::SizeMismatch => 14,
        ArtifactTransferErrorCode::DigestMismatch => 15,
        ArtifactTransferErrorCode::TransferCancelled => 16,
        ArtifactTransferErrorCode::CapacityUnavailable => 17,
    }
}

fn error_code_from_wire(value: u8) -> Result<ArtifactTransferErrorCode, ProtocolError> {
    Ok(match value {
        0 => ArtifactTransferErrorCode::NoArtifactLocation,
        1 => ArtifactTransferErrorCode::SourceNodeOffline,
        2 => ArtifactTransferErrorCode::DestinationNodeOffline,
        3 => ArtifactTransferErrorCode::EndpointAdvertisementMissing,
        4 => ArtifactTransferErrorCode::RelayAssistUnavailable,
        5 => ArtifactTransferErrorCode::DirectPathTimeout,
        6 => ArtifactTransferErrorCode::RelayPathForbidden,
        7 => ArtifactTransferErrorCode::ConnectionFailed,
        8 => ArtifactTransferErrorCode::PeerIdentityMismatch,
        9 => ArtifactTransferErrorCode::TransferLeaseRejected,
        10 => ArtifactTransferErrorCode::TransferLeaseExpired,
        11 => ArtifactTransferErrorCode::ArtifactMissingAtSource,
        12 => ArtifactTransferErrorCode::RangeInvalid,
        13 => ArtifactTransferErrorCode::DestinationDiskFull,
        14 => ArtifactTransferErrorCode::SizeMismatch,
        15 => ArtifactTransferErrorCode::DigestMismatch,
        16 => ArtifactTransferErrorCode::TransferCancelled,
        17 => ArtifactTransferErrorCode::CapacityUnavailable,
        value => return Err(ProtocolError::UnknownErrorCode(value)),
    })
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("artifact protocol header is empty or exceeds its bound")]
    HeaderTooLarge,
    #[error("artifact protocol header is truncated")]
    TruncatedHeader,
    #[error("artifact protocol header has trailing bytes")]
    TrailingHeaderBytes,
    #[error("artifact protocol version {0} is unsupported")]
    UnsupportedVersion(u16),
    #[error("artifact protocol field is invalid: {0}")]
    InvalidField(String),
    #[error("artifact protocol response tag {0} is unknown")]
    UnknownResponseTag(u8),
    #[error("artifact protocol error code {0} is unknown")]
    UnknownErrorCode(u8),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> GetArtifactRequest {
        GetArtifactRequest::new(
            "transfer-1".to_owned(),
            [7; 32],
            ArtifactId::from("artifact"),
            Digest::sha256(b"body"),
            4,
            2,
        )
    }

    #[tokio::test]
    async fn request_round_trip_is_bounded_binary_framing() {
        let (mut writer, mut reader) = tokio::io::duplex(1_024);
        let expected = request();
        let send = expected.clone();
        let write = tokio::spawn(async move { write_request(&mut writer, &send).await });
        let decoded = read_request(&mut reader).await.unwrap();
        write.await.unwrap().unwrap();
        assert_eq!(decoded, expected);
    }

    #[tokio::test]
    async fn accepted_response_round_trip_preserves_range() {
        let response = GetArtifactResponse::Accepted {
            artifact: ArtifactId::from("artifact"),
            digest: Digest::sha256(b"body"),
            total_size: 4,
            offset: 2,
            remaining_size: 2,
        };
        let (mut writer, mut reader) = tokio::io::duplex(1_024);
        let send = response.clone();
        let write = tokio::spawn(async move { write_response(&mut writer, &send).await });
        assert_eq!(read_response(&mut reader).await.unwrap(), response);
        write.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn oversized_header_is_rejected_before_allocation() {
        let (mut writer, mut reader) = tokio::io::duplex(16);
        writer
            .write_u32((MAX_PROTOCOL_HEADER_BYTES + 1) as u32)
            .await
            .unwrap();
        assert!(matches!(
            read_request(&mut reader).await,
            Err(ProtocolError::HeaderTooLarge)
        ));
    }
}
