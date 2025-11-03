use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

fn main() {
    println!("Hello, world!");
}

#[derive(Serialize, Deserialize, Debug)]
struct TxInput {
    txid: String,
    vout: String,
    scriptsigsize: String,
    scriptsig: String,
    sequence: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct TxOutput {
    amount: String,
    scriptpubkeysize: String,
    scriptpubkey: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct BitcoinTransaction {
    version: String,
    marker: String,
    flag: String,
    inputcount: String,
    inputs: Vec<TxInput>,
    outputcount: String,
    outputs: Vec<TxOutput>,
    witness: Vec<Value>,
    locktime: String,
}

fn btc_tx_decoder(input: &str) -> Result<String, String> {
    // Remove any whitespace
    let hex_input = input.replace(" ", "");

    // Convert hex string to bytes
    let bytes = hex::decode(&hex_input).map_err(|e| format!("Invalid hex: {}", e))?;

    let mut pos = 0;

    // Parse version (4 bytes)
    if bytes.len() < 4 {
        return Err("Input too short for version".to_string());
    }
    let version = hex::encode(&bytes[pos..pos + 4]);
    pos += 4;

    // Check for segwit marker and flag
    let (marker, flag, is_segwit) =
        if pos + 2 <= bytes.len() && bytes[pos] == 0x00 && bytes[pos + 1] == 0x01 {
            let m = hex::encode(&bytes[pos..pos + 1]);
            let f = hex::encode(&bytes[pos + 1..pos + 2]);
            pos += 2;
            (m, f, true)
        } else {
            (String::new(), String::new(), false)
        };

    // Parse input count (compact size)
    let input_count_start = pos;
    let (input_count, count_size) = read_compact_size(&bytes, pos)?;
    let inputcount = hex::encode(&bytes[input_count_start..input_count_start + count_size]);
    pos += count_size;

    // Parse inputs
    let mut inputs = Vec::new();
    for _ in 0..input_count {
        let (tx_input, size) = parse_input(&bytes, pos)?;
        inputs.push(tx_input);
        pos += size;
    }

    // Parse output count
    let output_count_start = pos;
    let (output_count, count_size) = read_compact_size(&bytes, pos)?;
    let outputcount = hex::encode(&bytes[output_count_start..output_count_start + count_size]);
    pos += count_size;

    // Parse outputs
    let mut outputs = Vec::new();
    for _ in 0..output_count {
        let (tx_output, size) = parse_output(&bytes, pos)?;
        outputs.push(tx_output);
        pos += size;
    }

    // Parse witness data if segwit
    let witness = if is_segwit {
        let mut witness_data = Vec::new();
        for _ in 0..input_count {
            let stack_items_start = pos;
            let (stack_items, stack_size) = read_compact_size(&bytes, pos)?;
            let stackitems = hex::encode(&bytes[stack_items_start..stack_items_start + stack_size]);
            pos += stack_size;

            let mut witness_obj = json!({
                "stackitems": stackitems
            });

            for i in 0..stack_items {
                let item_size_start = pos;
                let (item_size, size) = read_compact_size(&bytes, pos)?;
                let size_hex = hex::encode(&bytes[item_size_start..item_size_start + size]);
                pos += size;

                if pos + item_size > bytes.len() {
                    return Err("Invalid witness data".to_string());
                }

                let item_hex = hex::encode(&bytes[pos..pos + item_size]);
                pos += item_size;

                witness_obj[i.to_string()] = json!({
                    "size": size_hex,
                    "item": item_hex
                });
            }
            witness_data.push(witness_obj);
        }
        witness_data
    } else {
        Vec::new()
    };

    // Parse locktime (4 bytes)
    if pos + 4 > bytes.len() {
        return Err("Input too short for locktime".to_string());
    }
    let locktime = hex::encode(&bytes[pos..pos + 4]);

    let tx = BitcoinTransaction {
        version,
        marker,
        flag,
        inputcount,
        inputs,
        outputcount,
        outputs,
        witness,
        locktime,
    };

    // Serialize to JSON
    serde_json::to_string_pretty(&tx).map_err(|e| format!("JSON serialization error: {}", e))
}

fn read_compact_size(bytes: &[u8], pos: usize) -> Result<(usize, usize), String> {
    if pos >= bytes.len() {
        return Err("Invalid compact size".to_string());
    }

    let first_byte = bytes[pos];
    match first_byte {
        0..=0xfc => Ok((first_byte as usize, 1)),
        0xfd => {
            if pos + 3 > bytes.len() {
                return Err("Invalid compact size".to_string());
            }
            Ok((
                u16::from_le_bytes([bytes[pos + 1], bytes[pos + 2]]) as usize,
                3,
            ))
        }
        0xfe => {
            if pos + 5 > bytes.len() {
                return Err("Invalid compact size".to_string());
            }
            Ok((
                u32::from_le_bytes([
                    bytes[pos + 1],
                    bytes[pos + 2],
                    bytes[pos + 3],
                    bytes[pos + 4],
                ]) as usize,
                5,
            ))
        }
        0xff => {
            if pos + 9 > bytes.len() {
                return Err("Invalid compact size".to_string());
            }
            Ok((
                u64::from_le_bytes([
                    bytes[pos + 1],
                    bytes[pos + 2],
                    bytes[pos + 3],
                    bytes[pos + 4],
                    bytes[pos + 5],
                    bytes[pos + 6],
                    bytes[pos + 7],
                    bytes[pos + 8],
                ]) as usize,
                9,
            ))
        }
    }
}

fn parse_input(bytes: &[u8], pos: usize) -> Result<(TxInput, usize), String> {
    let mut offset = pos;

    // Parse previous txid (32 bytes, no reversal)
    if offset + 32 > bytes.len() {
        return Err("Invalid input: txid too short".to_string());
    }
    let txid = hex::encode(&bytes[offset..offset + 32]);
    offset += 32;

    // Parse vout (4 bytes)
    if offset + 4 > bytes.len() {
        return Err("Invalid input: vout too short".to_string());
    }
    let vout = hex::encode(&bytes[offset..offset + 4]);
    offset += 4;

    // Parse script sig length and script sig
    let scriptsigsize_start = offset;
    let (script_sig_len, len_size) = read_compact_size(bytes, offset)?;
    let scriptsigsize = hex::encode(&bytes[scriptsigsize_start..scriptsigsize_start + len_size]);
    offset += len_size;

    if offset + script_sig_len > bytes.len() {
        return Err("Invalid input: script_sig too short".to_string());
    }
    let scriptsig = hex::encode(&bytes[offset..offset + script_sig_len]);
    offset += script_sig_len;

    // Parse sequence (4 bytes)
    if offset + 4 > bytes.len() {
        return Err("Invalid input: sequence too short".to_string());
    }
    let sequence = hex::encode(&bytes[offset..offset + 4]);
    offset += 4;

    Ok((
        TxInput {
            txid,
            vout,
            scriptsigsize,
            scriptsig,
            sequence,
        },
        offset - pos,
    ))
}

fn parse_output(bytes: &[u8], pos: usize) -> Result<(TxOutput, usize), String> {
    let mut offset = pos;

    // Parse amount (8 bytes)
    if offset + 8 > bytes.len() {
        return Err("Invalid output: amount too short".to_string());
    }
    let amount = hex::encode(&bytes[offset..offset + 8]);
    offset += 8;

    // Parse script pubkey length and script pubkey
    let scriptpubkeysize_start = offset;
    let (script_pubkey_len, len_size) = read_compact_size(bytes, offset)?;
    let scriptpubkeysize =
        hex::encode(&bytes[scriptpubkeysize_start..scriptpubkeysize_start + len_size]);
    offset += len_size;

    if offset + script_pubkey_len > bytes.len() {
        return Err("Invalid output: script_pubkey too short".to_string());
    }
    let scriptpubkey = hex::encode(&bytes[offset..offset + script_pubkey_len]);
    offset += script_pubkey_len;

    Ok((
        TxOutput {
            amount,
            scriptpubkeysize,
            scriptpubkey,
        },
        offset - pos,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_btc_tx_decoder() {
        let input = "0200000000010131811cd355c357e0e01437d9bcf690df824e9ff785012b6115dfae3d8e8b36c10100000000fdffffff0220a107000000000016001485d78eb795bd9c8a21afefc8b6fdaedf718368094c08100000000000160014840ab165c9c2555d4a31b9208ad806f89d2535e20247304402207bce86d430b58bb6b79e8c1bbecdf67a530eff3bc61581a1399e0b28a741c0ee0220303d5ce926c60bf15577f2e407f28a2ef8fe8453abd4048b716e97dbb1e3a85c01210260828bc77486a55e3bc6032ccbeda915d9494eda17b4a54dbe3b24506d40e4ff43030e00";
        let expected_output = json!({
            "version": "02000000",
            "marker": "00",
            "flag": "01",
            "inputcount": "01",
            "inputs": [
                {
                    "txid": "31811cd355c357e0e01437d9bcf690df824e9ff785012b6115dfae3d8e8b36c1",
                    "vout": "01000000",
                    "scriptsigsize": "00",
                    "scriptsig": "",
                    "sequence": "fdffffff"
                }
            ],
            "outputcount": "02",
            "outputs": [
                {
                    "amount": "20a1070000000000",
                    "scriptpubkeysize": "16",
                    "scriptpubkey": "001485d78eb795bd9c8a21afefc8b6fdaedf71836809"
                },
                {
                    "amount": "4c08100000000000",
                    "scriptpubkeysize": "16",
                    "scriptpubkey": "0014840ab165c9c2555d4a31b9208ad806f89d2535e2"
                }
            ],
            "witness": [
                {
                    "stackitems": "02",
                    "0": {
                        "size": "47",
                        "item": "304402207bce86d430b58bb6b79e8c1bbecdf67a530eff3bc61581a1399e0b28a741c0ee0220303d5ce926c60bf15577f2e407f28a2ef8fe8453abd4048b716e97dbb1e3a85c01"
                    },
                    "1": {
                        "size": "21",
                        "item": "0260828bc77486a55e3bc6032ccbeda915d9494eda17b4a54dbe3b24506d40e4ff"
                    }
                }
            ],
            "locktime": "43030e00"
        });
        let result = btc_tx_decoder(input).unwrap();
        let result_json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(result_json, expected_output);
    }
     #[test]
    fn test_btc_tx_decoder_invalid_hex() {
        let input = "invalidhex";
        let result = btc_tx_decoder(input);
        assert!(result.is_err());
    }
}
