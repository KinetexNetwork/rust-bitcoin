//! Utreexo implementation for rust-bitcoin
use std::io::ErrorKind;

use crate::consensus::{self, Decodable, Encodable};
use crate::hash_types::BlockHash;
use crate::internal_macros::impl_consensus_encoding;
use crate::{Block, VarInt};
/// Commitment of the leaf data, but in a compact way
///
/// The serialized format is:
/// [<header_code><amount><spk_type>]
///
/// The serialized header code format is:
///   bit 0 - containing transaction is a coinbase
///   bits 1-x - height of the block that contains the spent txout
///
/// It's calculated with:
///   header_code = <<= 1
///   if IsCoinBase {
///       header_code |= 1 // only set the bit 0 if it's a coinbase.
///   }
/// ScriptPubkeyType is the output's scriptPubkey, but serialized in a more efficient way
/// to save bandwidth. If the type is recoverable from the scriptSig, don't download the
/// scriptPubkey.
#[derive(PartialEq, Eq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct CompactLeafData {
    /// Header code tells the height of creating for this UTXO and whether it's a coinbase
    pub header_code: u32,
    /// The amount locked in this UTXO
    pub amount: u64,
    /// The type of the locking script for this UTXO
    pub spk_ty: ScriptPubkeyType,
}
/// A recoverable scriptPubkey type, this avoids copying over data that are already
/// present or can be computed from the transaction itself.
/// An example is a p2pkh, the public key is serialized in the scriptSig, so we can just
/// grab it and hash to obtain the actual scriptPubkey. Since this data is committed in
/// the Utreexo leaf hash, it is still authenticated
#[derive(PartialEq, Eq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub enum ScriptPubkeyType {
    /// An non-specified type, in this case the script is just copied over
    Other(Box<[u8]>),
    /// p2pkh
    PubKeyHash,
    /// p2wsh
    WitnessV0PubKeyHash,
    /// p2sh
    ScriptHash,
    /// p2wsh
    WitnessV0ScriptHash,
}
impl Decodable for ScriptPubkeyType {
    fn consensus_decode<R: std::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, consensus::encode::Error> {
        let ty = u8::consensus_decode(reader)?;
        match ty {
            0x00 => Ok(ScriptPubkeyType::Other(Box::consensus_decode(reader)?)),
            0x01 => Ok(ScriptPubkeyType::PubKeyHash),
            0x02 => Ok(ScriptPubkeyType::WitnessV0PubKeyHash),
            0x03 => Ok(ScriptPubkeyType::ScriptHash),
            0x04 => Ok(ScriptPubkeyType::WitnessV0ScriptHash),
            _ => Err(consensus::encode::Error::ParseFailed("Invalid script type")),
        }
    }
}
impl Encodable for ScriptPubkeyType {
    fn consensus_encode<W: std::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, std::io::Error> {
        let mut len = 1;

        match self {
            ScriptPubkeyType::Other(script) => {
                00_u8.consensus_encode(writer)?;
                len += script.consensus_encode(writer)?;
            }
            ScriptPubkeyType::PubKeyHash => {
                0x01_u8.consensus_encode(writer)?;
            }
            ScriptPubkeyType::WitnessV0PubKeyHash => {
                0x02_u8.consensus_encode(writer)?;
            }
            ScriptPubkeyType::ScriptHash => {
                0x03_u8.consensus_encode(writer)?;
            }
            ScriptPubkeyType::WitnessV0ScriptHash => {
                0x04_u8.consensus_encode(writer)?;
            }
        }
        Ok(len)
    }
}
/// BatchProof serialization defines how the utreexo accumulator proof will be
/// serialized both for i/o.
///
/// Note that this serialization format differs from the one from
/// github.com/mit-dci/utreexo/accumulator as this serialization method uses
/// varints and the one in that package does not.  They are not compatible and
/// should not be used together.  The serialization method here is more compact
/// and thus is better for wire and disk storage.
///
/// The serialized format is:
/// [<target count><targets><proof count><proofs>]
///
/// All together, the serialization looks like so:
/// Field          Type       Size
/// target count   varint     1-8 bytes
/// targets        []uint64   variable
/// hash count     varint     1-8 bytes
/// hashes         []32 byte  variable
#[derive(PartialEq, Eq, Clone, Debug, Default)]
pub struct BatchProof {
    /// All targets that'll be deleted
    pub targets: Vec<VarInt>,
    /// The inner hashes of a proof
    pub hashes: Vec<BlockHash>,
}
/// UData contains data needed to prove the existence and validity of all inputs
/// for a Bitcoin block.  With this data, a full node may only keep the utreexo
/// roots and still be able to fully validate a block.
#[derive(PartialEq, Eq, Clone, Debug, Default)]
pub struct UData {
    /// All the indexes of new utxos to remember.
    pub remember_idx: Vec<u64>,
    /// AccProof is the utreexo accumulator proof for all the inputs.
    pub proof: BatchProof,
    /// LeafData are the tx validation data for every input.
    pub leaves: Vec<CompactLeafData>,
}

/// A block plus some udata
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct UtreexoBlock {
    /// A actual block
    pub block: Block,
    /// The utreexo specific data
    pub udata: Option<UData>,
}

impl Encodable for UtreexoBlock {
    fn consensus_encode<W: std::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, std::io::Error> {
        let mut len = 0;
        len += self.block.consensus_encode(writer)?;
        if let Some(ref udata) = self.udata {
            len += udata.consensus_encode(writer)?;
        }

        Ok(len)
    }
}
impl Decodable for UtreexoBlock {
    fn consensus_decode<R: std::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, crate::consensus::encode::Error> {
        let block = Block::consensus_decode(reader)?;
        let udata = UData::consensus_decode(reader);
        let udata = match udata {
            Ok(udata) => Some(udata),
            Err(e) => {
                if let consensus::encode::Error::Io(e) = e {
                    if e.kind() == ErrorKind::UnexpectedEof {
                        None
                    } else {
                        return Err(consensus::encode::Error::Io(e));
                    }
                } else {
                    return Err(e);
                }
            }
        };
        Ok(Self { block, udata })
    }
}

impl_consensus_encoding!(CompactLeafData, header_code, amount, spk_ty);
impl_consensus_encoding!(BatchProof, targets, hashes);
impl_consensus_encoding!(UData, remember_idx, proof, leaves);

impl Into<Block> for UtreexoBlock {
    fn into(self) -> Block {
        self.block
    }
}
impl Into<UtreexoBlock> for Block {
    fn into(self) -> UtreexoBlock {
        UtreexoBlock { block: self, udata: None }
    }
}
