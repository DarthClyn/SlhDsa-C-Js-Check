/* global BigInt */
// import React, { useState } from "react";
// import { mnemonicToEntropy } from "bip39";
// import { shake256 } from "@noble/hashes/sha3";
// import { keccak256 } from "ethereum-cryptography/keccak";
// import * as slh from "@noble/post-quantum/slh-dsa";
// import { Buffer } from "buffer";
// import axios from "axios";
// import rlp from "rlp";


const fs = require("fs");
const path = require("path");
const readline = require("readline");
const { keccak256 } = require("ethereum-cryptography/keccak");
const slh = require("@noble/post-quantum/slh-dsa");
const { Buffer } = require("buffer");
const axios = require("axios");
const rlp = require("rlp");

if (!global.Buffer) global.Buffer = Buffer;

const NODE_URL = "https://tqrn-node1.quranium.org/node";
const CHAIN_ID = "0x3dfb48";

// =====================
// Helpers (MATCH WORKING SCRIPTS)
// =====================
function canonicalIntHex(val) {
  if (typeof val === "bigint") {
    return val === 0n ? "" : "0x" + val.toString(16);
  }
  if (typeof val === "number") {
    return val === 0 ? "" : "0x" + val.toString(16);
  }
  if (typeof val === "string") {
    if (val === "" || val === "0x0" || val === "0x00") return "";
    if (val.startsWith("0x")) return val.replace(/^0x0+/, "0x");
  }
  return "";
}

const toHex = (val, allowEmpty = false) => {
  if (typeof val === "bigint") return "0x" + val.toString(16);

  if (typeof val === "number") {
    if (val === 0 && allowEmpty) return "";
    if (val === 0) return "0x0";
    return "0x" + val.toString(16).replace(/^0+/, "");
  }

  if (typeof val === "string") {
    if (val.startsWith("0x")) {
      let hex = val.slice(2).replace(/^0+/, "");
      if (hex === "" && allowEmpty) return "";
      if (hex === "") return "0x0";
      return "0x" + hex;
    }
    const b = BigInt(val);
    if (b === 0n && allowEmpty) return "";
    if (b === 0n) return "0x0";
    return "0x" + b.toString(16);
  }

  return allowEmpty ? "" : "0x0";
};

const decimalToWei = (amount, decimals = 18) => {
  const [whole, fractional] = amount.split(".");
  let wei = whole ? BigInt(whole) * 10n ** BigInt(decimals) : 0n;

  if (fractional) {
    const padded = fractional.padEnd(decimals, "0").slice(0, decimals);
    wei += BigInt(padded);
  }

  return wei;
};

const hexToBuffer = (hex) =>
  Buffer.from(hex.replace(/^0x/, ""), "hex");

const bufferToHex = (buf) =>
  "0x" + Buffer.from(buf).toString("hex");

// =====================
// Key handling
// =====================

async function deriveFromPrivateKey(privKeyHex) {
  const priv = hexToBuffer(privKeyHex);
  if (priv.length !== 128) throw new Error("Invalid private key length");

  const seed96 = priv.slice(0, 96);
  const keys = slh.slh_dsa_shake_256f.keygen(seed96);

  const pub = Buffer.from(keys.publicKey);
  const stripped = pub.subarray(1);
  const hash = keccak256(stripped);
  const address = bufferToHex(hash.slice(-20)).toLowerCase();

  return {
    address,
    privateKeyRaw: priv,
    publicKeyRaw: keys.publicKey,
    publicKeyHex: pub.toString("hex"),
  };
}

// =====================
// RPC
// =====================

async function rpc(method, params = []) {
  const res = await axios.post(NODE_URL, {
    jsonrpc: "2.0",
    method,
    params,
    id: 1,
  });
  if (res.data.error) throw new Error(res.data.error.message);
  return res.data.result;
}

// =====================
// Step 1: Create tx
// =====================

async function createTransaction() {
  const keypair = await deriveFromPrivateKey(FIXED_PRIVKEY);

  const nonce = parseInt(
    await rpc("eth_getTransactionCount", [keypair.address, "latest"]),
    16
  );

  const gasPrice = parseInt(await rpc("eth_gasPrice"), 16);
  const valueWei = decimalToWei(VALUE_QL1);

  const gasLimit = parseInt(
    await rpc("eth_estimateGas", [{
      from: keypair.address,
      to: TO_ADDRESS,
      value: valueWei === 0n ? "" : toHex(valueWei, true),
      data: "0x",
    }]),
    16
  ) + 2000;

  const txData = {
    nonce: canonicalIntHex(nonce),
    gasPrice: canonicalIntHex(gasPrice),
    gasLimit: canonicalIntHex(gasLimit),
    to: TO_ADDRESS,
    value: valueWei === 0n ? "" : toHex(valueWei, true),
    data: "0x",
    chainId: CHAIN_ID,
  };

  // ✅ Build unsigned tx ONCE
  const unsignedFields = [
    txData.nonce,
    txData.gasPrice,
    txData.gasLimit,
    txData.to,
    txData.value,
    txData.data,
    txData.chainId,
    "0x",
    "0x",
  ];

  const rlpEncoded = rlp.encode(unsignedFields);
  const msgHash = keccak256(rlpEncoded);


  // Write only privateKey for C signer
  fs.writeFileSync(
    "trxn.json",
    JSON.stringify(
      {
        txData,
        unsignedRlpHex: Buffer.from(rlpEncoded).toString("hex"),
        msgHash: Buffer.from(msgHash).toString("hex"),
        privateKey: keypair.privateKeyRaw.toString("hex"),
      },
      null,
      2
    )
  );

  console.log("Value field:", txData.value);
  console.log("Message hash:", Buffer.from(msgHash).toString("hex"));
  console.log("Transaction saved (nonce =", nonce, ")");
}


// =====================
// Step 2: Sign tx
// =====================
async function signTransaction() {
  const trxn = JSON.parse(fs.readFileSync("trxn.json"));
  // Use privateKey from trxn.json if present, else fallback
  const privHex = trxn.privateKey ? (trxn.privateKey.startsWith("0x") ? trxn.privateKey : "0x" + trxn.privateKey) : FIXED_PRIVKEY;
  const keypair = await deriveFromPrivateKey(privHex);

  // ✅ Load precomputed hash
  const msgHash = Buffer.from(trxn.msgHash, "hex");

  const sigBytes = slh.slh_dsa_shake_256f.sign(
    msgHash,
    keypair.privateKeyRaw
  );

  const sigHex =
    "0x" +
    Buffer.from(sigBytes).toString("hex");

  fs.writeFileSync("sign.json", JSON.stringify({ sig: sigHex }, null, 2));
  console.log("Transaction signed using stored msgHash and privateKey from trxn.json");
}


// =====================
// Step 3: Broadcast
// =====================

async function broadcastSignedTransaction() {
  const { txData } = JSON.parse(fs.readFileSync("trxn.json"));
  const { sig } = JSON.parse(fs.readFileSync("sign.json"));

  const finalFields = [
    txData.nonce,
    txData.gasPrice,
    txData.gasLimit,
    txData.to,
    txData.value,
    txData.data,
    sig,
    txData.chainId,
  ];

  const rawTx = "0x" + Buffer.from(rlp.encode(finalFields)).toString("hex");
  const txHash = await rpc("eth_sendRawTransaction", [rawTx]);

  console.log("Broadcasted Tx Hash:", txHash);
}

// =====================
// CLI
// =====================

const FIXED_PRIVKEY =
  "1ec733d6e67885e5ca0cb1c535239736011835e94c8112b0e76b70054e08792596291888948f31a3881fa2c9908acc96ba3ae3e09359b0dc4ebe2447daa9305badec84eda4a6f1543f75c3220bc86c3ecefc14c7d6ff52e2a8e1adcd8300eb20de1e3b742cbc79664d910fbe99b95cb1c6d8a91e8c87c9273abda081d220f0de";
const TO_ADDRESS = "0x64A0A7BA0d205b40091C91CB415e11bEc95BDE90";
const VALUE_QL1 = "2";


async function main() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  const menu = () => {
    console.log("\n1. Create transaction");
    console.log("2. Sign transaction");
    console.log("3. Broadcast transaction");
    console.log("exit");

    rl.question("> ", async (a) => {
      try {
        if (a === "1") await createTransaction();
        else if (a === "2") await signTransaction();
        else if (a === "3") await broadcastSignedTransaction();
        else if (a === "exit") return rl.close();
      } catch (e) {
        console.error("Error:", e.message);
      }
      menu();
    });
  };

  menu();
}

main();
