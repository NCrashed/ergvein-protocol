use bitcoin::consensus::deserialize;
use bitcoin::hashes::hex::FromHex;
use bitcoin::Block;
use bitcoin::OutPoint;
use bitcoin::Script;
use bitcoin::Transaction;
use bitcoin::util::bip158::Error;

use mempool_filters::filtertree::FilterTree;
use mempool_filters::filtertree::make_filters;
use mempool_filters::filtertree::make_full_filter;
use chrono::Utc;

use std::collections::HashMap;
use std::fs;
use std::io;
use std::io::BufRead;

use std::io::Write;use mempool_filters::txtree::*;

use ergvein_protocol::message::*;
use ergvein_protocol::util::*;
use rand::Rng;
use consensus_encode::util::hex::ToHex;
use flate2::Compression;
use flate2::write::{GzDecoder, GzEncoder};

// FullFilterInv,
// GetFullFilter,
// FullFilter(MemFilter),
// GetMemFilters,
// MemFilters(Vec<FilterPrefixPair>),
// GetMempool(Vec<TxPrefix>),
// MempoolChunk(MempoolChunkResp)

fn main() {
    let k0 = u64::from_le_bytes(*b"ergvein0");
    let k1 = u64::from_le_bytes(*b"filters0");
    let block = load_block("./test/block1");
    let txmap = make_inputs_map(load_txs("./test/block1-txs"));
    let txs = block.txdata;
    let txtree = TxTree::new();
    insert_tx_batch(&txtree, txs.clone(), Utc::now());

    let ftree = FilterTree::new();
    make_filters(&ftree, &txtree, |o| {
        if let Some(s) = txmap.get(o) {
            Ok(s.clone())
        } else {
            Err(Error::UtxoMissing(o.clone()))
        }
    });

    let ffilt = make_full_filter(&txtree, |o| {
        if let Some(s) = txmap.get(o) {
            Ok(s.clone())
        } else {
            Err(Error::UtxoMissing(o.clone()))
        }
    }).unwrap();

    let mut rng = rand::thread_rng();
    let n = rng.gen_range(0..10);
    let mut prefs : Vec<ergvein_protocol::message::TxPrefix> = Vec::new();
    (0..n).for_each(|_| { prefs.push(ergvein_protocol::message::TxPrefix(rng.gen())); });
    let mut fpairs : Vec<FilterPrefixPair> = ftree.iter().map(|kv| {
        let (k,v) = kv.pair();
        FilterPrefixPair{prefix:TxPrefix(k.clone()), filter: MemFilter(v.content.clone())}
    }).collect();

    fpairs.sort_by_key(|fp| fp.prefix.clone());

    let mut data : Vec<Vec<u8>> = Vec::new();
    let tx = Vec::from_hex("02000000000101261560a27330e73b46351ac349ff35136f614d4dfdfb3a108fa85c140a1c61a901000000171600149fd77bca5b9369478c80dc5c5cc4101f7baf5a95feffffff0254c410000000000017a914ba906b3da20467de78552d0c089e3754f49f62688740420f000000000017a9140f912a6fc7ba91305934dba0ef566cbfc62fd2218702473044022045d75032c9f3806939ff10ffd79a040bdcbece2f90cb1dc95e3a3b7cf109da1e022012a37cc4fee1ff9ae19c6adf7d0bc84a122b5ce33d5c43bebff52a6796d512340121025609c093b93e3d4a003ebb0ec8e58700d12e6f05c0c1096f18ba3ef8ff931fca260d1b00").unwrap();
    data.push(bitcoin::consensus::encode::serialize(&tx));
    data.push(bitcoin::consensus::encode::serialize(&tx));
    data.push(bitcoin::consensus::encode::serialize(&tx));
    data.push(bitcoin::consensus::encode::serialize(&tx));
    data.push(bitcoin::consensus::encode::serialize(&tx));
    data.push(bitcoin::consensus::encode::serialize(&tx));

    let chunk = MempoolChunkResp {prefix: TxPrefix([9, 128]), amount: data.len() as u32, txs: data};
    let full_filter_inv = Message::FullFilterInv;
    let get_full_filter = Message::GetFullFilter;
    let get_mem_filters = Message::GetMemFilters;
    let full_filter     = Message::FullFilter(MemFilter(ffilt.content));
    let mem_filters     = Message::MemFilters(fpairs);
    let get_mempool     = Message::GetMempool(prefs);
    let mempool_chunk   = Message::MempoolChunk(chunk.clone());

    println!("full_filter_inv :{}: {}", serialize(&full_filter_inv).len(), serialize(&full_filter_inv).to_hex());
    println!("full_filter_inv      {}", full_filter_inv);
    println!("get_full_filter :{}: {}", serialize(&get_full_filter).len(), serialize(&get_full_filter).to_hex());
    println!("get_full_filter      {}", get_full_filter);
    println!("get_mem_filters :{}: {}", serialize(&get_mem_filters).len(), serialize(&get_mem_filters).to_hex());
    println!("get_mem_filters      {}", get_mem_filters);
    println!("full_filter     :{}: {}", serialize(&full_filter).len(), serialize(&full_filter).to_hex());
    println!("full_filter          {}", full_filter);
    println!("mem_filters     :{}: {}", serialize(&mem_filters).len(), serialize(&mem_filters).to_hex());
    println!("mem_filters          {}", mem_filters);
    println!("get_mempool     :{}: {}", serialize(&get_mempool).len(), serialize(&get_mempool).to_hex());
    println!("get_mempool          {}", get_mempool);
    println!("mempool_chunk   :{}: {}", serialize(&mempool_chunk).len(), serialize(&mempool_chunk).to_hex());
    println!("mempool_chunk        {}:{}:{}", chunk.prefix, chunk.amount, chunk.txs[0].to_hex());
    let a = consensus_encode::deserialize::<Message>(&serialize(&mempool_chunk)).map(|v| v == Message::MempoolChunk(chunk.clone()));
    println!("ISEQ {:?}",a);
    println!("\n\n\n\n{}", tx.to_hex());

    let mut e = GzEncoder::new(Vec::new(), Compression::default());
    e.write_all(&serialize(&tx)).unwrap();
    let enc = e.finish().unwrap();

    let mut gz = GzDecoder::new(Vec::new());
    gz.write_all(&enc).unwrap();
    let tx2 : Vec<u8> = consensus_encode::deserialize(&gz.finish().unwrap()).unwrap();
    println!("\n\n\n\n{}", tx == tx2);
    println!("\n\n\n\n{}", enc.to_hex());

    println!("{:?}", tx);

    println!("\n\n\n\n");

    let v = Vec::from_hex("123aef32f21a2e7d9c").unwrap();
    let mut e = GzEncoder::new(Vec::new(), Compression::default());
    e.write_all(&serialize(&v)).unwrap();
    let enc = e.finish().unwrap();
    println!("\n\n\n\n{}", enc.to_hex());


}


pub fn make_inputs_map(txs: Vec<Transaction>) -> HashMap<OutPoint, Script> {
    let mut map = HashMap::new();
    for tx in txs {
        let mut out_point = OutPoint {
            txid: tx.txid(),
            vout: 0,
        };
        for (i, out) in tx.output.iter().enumerate() {
            out_point.vout = i as u32;
            map.insert(out_point.clone(), out.script_pubkey.clone());
        }
    }
    map
}

pub fn load_block(path: &str) -> Block {
    let mut contents = fs::read_to_string(path).unwrap();
    contents.pop();
    deserialize(&Vec::from_hex(&contents).unwrap()).unwrap()
}

pub fn load_txs(path: &str) -> Vec<Transaction> {
    let mut res = vec![];
    let file = std::fs::File::open(path).unwrap();
    for line in io::BufReader::new(file).lines() {
        let tx = deserialize(&Vec::from_hex(&line.unwrap()).unwrap()).unwrap();
        res.push(tx);
    }
    res
}
