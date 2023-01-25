/* Copyright (C) 2017 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

use crate::common::nom7::bits;
use crate::smb::error::SmbError;
use nom7::bits::streaming::take as take_bits;
use nom7::bytes::streaming::take;
use nom7::combinator::{cond, rest};
use nom7::multi::count;
use nom7::number::Endianness;
use nom7::number::streaming::{be_u16, le_u8, le_u16, le_u32, u16, u32};
use nom7::sequence::tuple;
use nom7::{Err, IResult};

#[derive(Debug,PartialEq, Eq)]
pub struct DceRpcResponseRecord<'a> {
    pub data: &'a[u8],
}

/// parse a packet type 'response' DCERPC record. Implemented
/// as function to be able to pass the fraglen in.
pub fn parse_dcerpc_response_record(i:&[u8], frag_len: u16 )
    -> IResult<&[u8], DceRpcResponseRecord, SmbError>
{
    if frag_len < 24 {
        return Err(Err::Error(SmbError::RecordTooSmall));
    }
    let (i, _) = take(8_usize)(i)?;
    let (i, data) = take(frag_len - 24)(i)?;
    let record = DceRpcResponseRecord { data };
    Ok((i, record))
}


#[derive(Debug,PartialEq, Eq)]
pub struct DceRpcRequestRecord<'a> {
    pub opnum: u16,
    pub context_id: u16,
    pub data: &'a[u8],
}

/// parse a packet type 'request' DCERPC record. Implemented
/// as function to be able to pass the fraglen in.
pub fn parse_dcerpc_request_record(i:&[u8], frag_len: u16, little: bool)
    -> IResult<&[u8], DceRpcRequestRecord, SmbError>
{
    if frag_len < 24 {
        return Err(Err::Error(SmbError::RecordTooSmall));
    }
    let (i, _) = take(4_usize)(i)?;
    let endian = if little { Endianness::Little } else { Endianness::Big };
    let (i, context_id) = u16(endian)(i)?;
    let (i, opnum) = u16(endian)(i)?;
    let (i, data) = take(frag_len - 24)(i)?;
    let record = DceRpcRequestRecord { opnum, context_id, data };
    Ok((i, record))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DceRpcBindIface<'a> {
    pub iface: &'a[u8],
    pub ver: u16,
    pub ver_min: u16,
}

pub fn parse_dcerpc_bind_iface(i: &[u8]) -> IResult<&[u8], DceRpcBindIface> {
    let (i, _ctx_id) = le_u16(i)?;
    let (i, _num_trans_items) = le_u8(i)?;
    let (i, _) = take(1_usize)(i)?; // reserved
    let (i, interface) = take(16_usize)(i)?;
    let (i, ver) = le_u16(i)?;
    let (i, ver_min) = le_u16(i)?;
    let (i, _) = take(20_usize)(i)?;
    let res = DceRpcBindIface {
        iface:interface,
        ver,
        ver_min,
    };
    Ok((i, res))
}

pub fn parse_dcerpc_bind_iface_big(i: &[u8]) -> IResult<&[u8], DceRpcBindIface> {
    let (i, _ctx_id) = le_u16(i)?;
    let (i, _num_trans_items) = le_u8(i)?;
    let (i, _) = take(1_usize)(i)?; // reserved
    let (i, interface) = take(16_usize)(i)?;
    let (i, ver_min) = be_u16(i)?;
    let (i, ver) = be_u16(i)?;
    let (i, _) = take(20_usize)(i)?;
    let res = DceRpcBindIface {
        iface:interface,
        ver,
        ver_min,
    };
    Ok((i, res))
}

#[derive(Debug,PartialEq, Eq)]
pub struct DceRpcBindRecord<'a> {
    pub num_ctx_items: u8,
    pub ifaces: Vec<DceRpcBindIface<'a>>,
}

pub fn parse_dcerpc_bind_record(i: &[u8]) -> IResult<&[u8], DceRpcBindRecord> {
    let (i, _max_xmit_frag) = le_u16(i)?;
    let (i, _max_recv_frag) = le_u16(i)?;
    let (i, _assoc_group) = take(4_usize)(i)?;
    let (i, num_ctx_items) = le_u8(i)?;
    let (i, _) = take(3_usize)(i)?; // reserved
    let (i, ifaces) = count(parse_dcerpc_bind_iface, num_ctx_items as usize)(i)?;
    let record = DceRpcBindRecord {
        num_ctx_items,
        ifaces,
    };
    Ok((i, record))
}

pub fn parse_dcerpc_bind_record_big(i: &[u8]) -> IResult<&[u8], DceRpcBindRecord> {
    let (i, _max_xmit_frag) = be_u16(i)?;
    let (i, _max_recv_frag) = be_u16(i)?;
    let (i, _assoc_group) = take(4_usize)(i)?;
    let (i, num_ctx_items) = le_u8(i)?;
    let (i, _) = take(3_usize)(i)?; // reserved
    let (i, ifaces) = count(parse_dcerpc_bind_iface_big, num_ctx_items as usize)(i)?;
    let record = DceRpcBindRecord {
        num_ctx_items,
        ifaces,
    };
    Ok((i, record))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DceRpcBindAckResult<'a> {
    pub ack_result: u16,
    pub ack_reason: u16,
    pub transfer_syntax: &'a[u8],
    pub syntax_version: u32,
}

pub fn parse_dcerpc_bindack_result(i: &[u8]) -> IResult<&[u8], DceRpcBindAckResult> {
    let (i, ack_result) = le_u16(i)?;
    let (i, ack_reason) = le_u16(i)?;
    let (i, transfer_syntax) = take(16_usize)(i)?;
    let (i, syntax_version) = le_u32(i)?;
    let res = DceRpcBindAckResult {
        ack_result,
        ack_reason,
        transfer_syntax,
        syntax_version,
    };
    Ok((i, res))
}

#[derive(Debug,PartialEq, Eq)]
pub struct DceRpcBindAckRecord<'a> {
    pub num_results: u8,
    pub results: Vec<DceRpcBindAckResult<'a>>,
}

pub fn parse_dcerpc_bindack_record(i: &[u8]) -> IResult<&[u8], DceRpcBindAckRecord> {
    let (i, _max_xmit_frag) = le_u16(i)?;
    let (i, _max_recv_frag) = le_u16(i)?;
    let (i, _assoc_group) = take(4_usize)(i)?;
    let (i, sec_addr_len) = le_u16(i)?;
    let (i, _) = take(sec_addr_len)(i)?;
    let (i, _) = cond((sec_addr_len+2) % 4 != 0, take(4 - (sec_addr_len+2) % 4))(i)?;
    let (i, num_results) = le_u8(i)?;
    let (i, _) = take(3_usize)(i)?; // padding
    let (i, results) = count(parse_dcerpc_bindack_result, num_results as usize)(i)?;
    let record = DceRpcBindAckRecord {
        num_results,
        results,
    };
    Ok((i, record))
}

#[derive(Debug,PartialEq, Eq)]
pub struct DceRpcRecord<'a> {
    pub version_major: u8,
    pub version_minor: u8,

    pub first_frag: bool,
    pub last_frag: bool,

    pub frag_len: u16,

    pub little_endian: bool,

    pub packet_type: u8,

    pub call_id: u32,
    pub data: &'a[u8],
}

fn parse_dcerpc_flags1(i:&[u8]) -> IResult<&[u8],(u8,u8,u8)> {
    bits(tuple((
        take_bits(6u8),
        take_bits(1u8),   // last (1)
        take_bits(1u8),
    )))(i)
}

fn parse_dcerpc_flags2(i:&[u8]) -> IResult<&[u8],(u32,u32,u32)> {
    bits(tuple((
       take_bits(3u32),
       take_bits(1u32),     // endianess
       take_bits(28u32),
    )))(i)
}

pub fn parse_dcerpc_record(i: &[u8]) -> IResult<&[u8], DceRpcRecord> {
    let (i, version_major) = le_u8(i)?;
    let (i, version_minor) = le_u8(i)?;
    let (i, packet_type) = le_u8(i)?;
    let (i, packet_flags) = parse_dcerpc_flags1(i)?;
    let (i, data_rep) = parse_dcerpc_flags2(i)?;
    let endian = if data_rep.1 == 0 { Endianness::Big } else { Endianness::Little };
    let (i, frag_len) = u16(endian)(i)?;
    let (i, _auth) = u16(endian)(i)?;
    let (i, call_id) = u32(endian)(i)?;
	// TODO: 还有两个field未解析，排查是否有问题
    let (i, data) = rest(i)?;
    let record = DceRpcRecord {
        version_major,
        version_minor,
        packet_type,
        first_frag: packet_flags.2 == 1,
        last_frag: packet_flags.1 == 1,
        frag_len,
        little_endian: data_rep.1 == 1,
        call_id,
        data,
    };
    Ok((i, record))
}

#[cfg(test)]
mod tests {
    use super::*;

	use crate::dcerpc::dcerpc::DCERPC_TYPE_BINDACK;
	#[test]
	fn test_parse_dcerpc_bindack_record() {
        let data = hex::decode("05000c03100000007400000002000000b810b810d80a00000c005c504950455c6174737663000055030000000200020000000000000000000000000000000000000000000000000033057171babe37498319b5dbef9ccc3601000000030003000000000000000000000000000000000000000000").unwrap();
        let result = parse_dcerpc_record(&data);
        assert_eq!(result.is_ok(), true);
        let record = result.unwrap().1;
		assert_eq!(record.packet_type, DCERPC_TYPE_BINDACK);
        let result = parse_dcerpc_bindack_record(&record.data);
		// dbg!(&result);
        assert_eq!(result.is_ok(), true);
        assert_eq!(result.unwrap().1, DceRpcBindAckRecord {
            num_results: 3,
            results: [
                DceRpcBindAckResult {
                    ack_result: 2,
                    ack_reason: 2,
                    transfer_syntax: &[
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                    ],
                    syntax_version: 0,
                },
                DceRpcBindAckResult {
                    ack_result: 0,
                    ack_reason: 0,
                    transfer_syntax: &[
                        51,
                        5,
                        113,
                        113,
                        186,
                        190,
                        55,
                        73,
                        131,
                        25,
                        181,
                        219,
                        239,
                        156,
                        204,
                        54,
                    ],
                    syntax_version: 1,
                },
                DceRpcBindAckResult {
                    ack_result: 3,
                    ack_reason: 3,
                    transfer_syntax: &[
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                    ],
                    syntax_version: 0,
                },
            ].to_vec(),
        });
	}

	#[test]
	fn test_parse_dcerpc_bind_record() {
		// krb5.pcap no: 283
		// 20171220_smb_at_schedule.pcap
		// https://redmine.openinfosecfoundation.org/issues/3109
        let data = hex::decode("05000b0310000000a000000002000000b810b8100000000003000000000001008206f71f510ae830076d740be8cee98b01000000045d888aeb1cc9119fe808002b10486002000000010001008206f71f510ae830076d740be8cee98b0100000033057171babe37498319b5dbef9ccc3601000000020001008206f71f510ae830076d740be8cee98b010000002c1cb76c12984045030000000000000001000000").unwrap();
        let result = parse_dcerpc_record(&data);
        assert_eq!(result.is_ok(), true);
        let record = result.unwrap().1;
		assert_eq!(record.frag_len, 160);
        let result = parse_dcerpc_bind_record(&record.data);
		// dbg!(&result);
        assert_eq!(result.is_ok(), true);
        assert_eq!(result.unwrap().1, DceRpcBindRecord {
            num_ctx_items: 3,
            ifaces: [
                DceRpcBindIface {
                    iface: &[
                        130,
                        6,
                        247,
                        31,
                        81,
                        10,
                        232,
                        48,
                        7,
                        109,
                        116,
                        11,
                        232,
                        206,
                        233,
                        139,
                    ],
                    ver: 1,
                    ver_min: 0,
                },
                DceRpcBindIface {
                    iface: &[
                        130,
                        6,
                        247,
                        31,
                        81,
                        10,
                        232,
                        48,
                        7,
                        109,
                        116,
                        11,
                        232,
                        206,
                        233,
                        139,
                    ],
                    ver: 1,
                    ver_min: 0,
                },
                DceRpcBindIface {
                    iface: &[
                        130,
                        6,
                        247,
                        31,
                        81,
                        10,
                        232,
                        48,
                        7,
                        109,
                        116,
                        11,
                        232,
                        206,
                        233,
                        139,
                    ],
                    ver: 1,
                    ver_min: 0,
                },
            ].to_vec(),
        });

	}

	#[test]
	fn test_parse_dcerpc_request_record() {
		use crate::dcerpc::dcerpc::DCERPC_TYPE_REQUEST;
		// krb5.pcap dcerpc & no: 262
		// https://www.cloudshark.org/captures/fa35bc16bbb0?filter=frame%20and%20raw%20and%20ip%20and%20tcp%20and%20nbss%20and%20smb%20and%20smb_pipe%20and%20dcerpc%20and%20samr
        let data = hex::decode("05000003100000004c00000007000000340000000000070000000000190fb5f979a4cc4384dbc1cbc4ecd8ab1102000004000000010400000000000515000000cf525a5834770dc31056d8ac").unwrap();
        let result = parse_dcerpc_record(&data);
        assert_eq!(result.is_ok(), true);
        let record = result.unwrap().1;
		assert_eq!(record.packet_type, DCERPC_TYPE_REQUEST);
        let result = parse_dcerpc_request_record(&record.data, record.frag_len, record.little_endian );
		// dbg!(&result);
        assert_eq!(result.is_ok(), true);
        assert_eq!(result.unwrap().1, DceRpcRequestRecord {
            opnum: 7,
            context_id: 0,
            data: &[
                0,
                0,
                0,
                0,
                25,
                15,
                181,
                249,
                121,
                164,
                204,
                67,
                132,
                219,
                193,
                203,
                196,
                236,
                216,
                171,
                17,
                2,
                0,
                0,
                4,
                0,
                0,
                0,
                1,
                4,
                0,
                0,
                0,
                0,
                0,
                5,
                21,
                0,
                0,
                0,
                207,
                82,
                90,
                88,
                52,
                119,
                13,
                195,
                16,
                86,
                216,
                172,
            ],
        });

	}

	#[test]
	fn test_parse_dcerpc_response_record() {
		// TOOD: 多了8个字节
		// krb5.pcap no: 283
		// https://www.cloudshark.org/captures/fa35bc16bbb0?filter=frame%20and%20raw%20and%20ip%20and%20tcp%20and%20nbss%20and%20smb%20and%20smb_pipe%20and%20dcerpc%20and%20samr
        let data = hex::decode("05000203100000003c0000000a0000002400000000000000010000000400020001000000510400000100000008000200010000000100000000000000").unwrap();
        let result = parse_dcerpc_record(&data);
        assert_eq!(result.is_ok(), true);
        let record = result.unwrap().1;
		assert_eq!(record.frag_len, 60);
        let result = parse_dcerpc_response_record(&record.data, record.frag_len);
		// dbg!(result);
        assert_eq!(result.is_ok(), true);
        assert_eq!(result.unwrap().1, DceRpcResponseRecord {
            data: &[
                1,
                0,
                0,
                0,
                4,
                0,
                2,
                0,
                1,
                0,
                0,
                0,
                81,
                4,
                0,
                0,
                1,
                0,
                0,
                0,
                8,
                0,
                2,
                0,
                1,
                0,
                0,
                0,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
        });


	}
    #[test]
    fn test_parse_dcerpc_record() {
        let data = hex::decode("05000003100000004c00000007000000340000000000070000000000190fb5f979a4cc4384dbc1cbc4ecd8ab1102000004000000010400000000000515000000cf525a5834770dc31056d8ac").unwrap();
        let result = parse_dcerpc_record(&data);
        assert_eq!(result.is_ok(), true);
        assert_eq!(
            result.unwrap().1,
            DceRpcRecord {
                // version_major,
                // version_minor,
                // packet_type,
                // first_frag: packet_flags.2 == 1,
                // last_frag: packet_flags.1 == 1,
                // frag_len,
                // little_endian: data_rep.1 == 1,
                // call_id,
				version_major: 5,
				version_minor: 0,
				first_frag: true,
				last_frag: true,
				frag_len: 76,
				little_endian: true,
				packet_type: 0,
				call_id: 7,
				data: &[
					52,
					0,
					0,
					0,
					0,
					0,
					7,
					0,
					0,
					0,
					0,
					0,
					25,
					15,
					181,
					249,
					121,
					164,
					204,
					67,
					132,
					219,
					193,
					203,
					196,
					236,
					216,
					171,
					17,
					2,
					0,
					0,
					4,
					0,
					0,
					0,
					1,
					4,
					0,
					0,
					0,
					0,
					0,
					5,
					21,
					0,
					0,
					0,
					207,
					82,
					90,
					88,
					52,
					119,
					13,
					195,
					16,
					86,
					216,
					172,
				],

            }
        );
    }
}
